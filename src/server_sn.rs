//! OASIS MQTT-SN v1.2 gateway over UDP, sharing sessions and routing with the MQTT listeners.
//!
//! MQTT-SN v1.2 carries no credentials, so every SN client acts as one configured ACL identity
//! (`listeners.mqtt_sn.acl_user`) or, when that is empty, as the anonymous identity.

use crate::auth::UserAccount;
use crate::broker::{BrokerContext, OpenError};
use crate::config::MqttSnListenerConfig;
use crate::protocol::sn::{return_code, SnPacket, TopicIdType, MAX_SN_CLIENT_ID_LEN};
use crate::protocol::{PublishPacket, QoS, SubscriptionOptions};
use crate::queue::{Delivery, Outbound};
use crate::routing::topic::has_wildcards;
use crate::routing::{is_valid_topic_name, Subscription};
use crate::session::{Session, Transport};
use bytes::{Bytes, BytesMut};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{oneshot, Notify};
use tracing::{debug, info, warn};

/// Upper bound of topics a single client may register.
const MAX_REGISTERED_TOPICS: usize = 1024;
/// Time allowed to finish the Will handshake after CONNECT.
const WILL_SETUP_TIMEOUT: Duration = Duration::from_secs(30);

/// Identifies a client: its UDP address plus, behind a forwarder, its wireless node id (§5.5).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LinkKey {
    pub addr: SocketAddr,
    pub node: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// CONNECT received with the Will flag; waiting for WILLTOPIC / WILLMSG.
    WillSetup,
    Active,
    /// Sleeping client (§6.14); messages are buffered in the session queue.
    Asleep {
        duration: u16,
    },
    /// Sleeping client that sent PINGREQ; buffered messages are flushed, then PINGRESP.
    Awake {
        duration: u16,
    },
}

#[derive(Debug)]
enum InflightKind {
    /// REGISTER sent; the delivery is published once REGACK arrives.
    Register {
        topic_id: u16,
        then: Box<Delivery>,
    },
    Publish {
        qos: i8,
    },
    PubRel,
}

#[derive(Debug)]
struct Inflight {
    msg_id: u16,
    packet: SnPacket,
    kind: InflightKind,
    sent_at: Instant,
    retries: u8,
}

#[derive(Debug)]
struct LinkState {
    keep_alive: u16,
    last_seen: Instant,
    mode: Mode,
    will_topic: Option<(String, QoS, bool)>,
    will: Option<PublishPacket>,
    topics_by_id: HashMap<u16, String>,
    topics_by_name: HashMap<String, u16>,
    next_topic_id: u16,
    next_msg_id: u16,
    /// MQTT-SN clients are constrained: one outstanding QoS 1/2 or REGISTER at a time.
    inflight: Option<Inflight>,
    release: Option<oneshot::Sender<()>>,
}

impl LinkState {
    fn next_msg_id(&mut self) -> u16 {
        let id = self.next_msg_id;
        self.next_msg_id = self.next_msg_id.checked_add(1).unwrap_or(1);
        id
    }

    /// Returns the topic id for `name`, registering it when `allocate` is set.
    fn topic_id(&mut self, name: &str, allocate: bool) -> Option<u16> {
        if let Some(id) = self.topics_by_name.get(name) {
            return Some(*id);
        }
        if !allocate || self.topics_by_id.len() >= MAX_REGISTERED_TOPICS {
            return None;
        }
        // 0x0000 and 0xFFFF are reserved (§5.3.11).
        let mut id = self.next_topic_id;
        while id == 0 || id == 0xFFFF || self.topics_by_id.contains_key(&id) {
            id = id.wrapping_add(1);
        }
        self.next_topic_id = id.wrapping_add(1);
        self.topics_by_id.insert(id, name.to_owned());
        self.topics_by_name.insert(name.to_owned(), id);
        Some(id)
    }
}

#[derive(Debug)]
struct SnLink {
    key: LinkKey,
    session: Arc<Session>,
    epoch: u64,
    closed: AtomicBool,
    wake: Notify,
    st: Mutex<LinkState>,
}

impl SnLink {
    fn st(&self) -> MutexGuard<'_, LinkState> {
        self.st.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn can_send(&self) -> bool {
        let st = self.st();
        matches!(st.mode, Mode::Active | Mode::Awake { .. }) && st.inflight.is_none()
    }
}

struct Gateway {
    config: MqttSnListenerConfig,
    ctx: BrokerContext,
    socket: Arc<UdpSocket>,
    predef_by_id: HashMap<u16, String>,
    predef_by_name: HashMap<String, u16>,
    links: Mutex<HashMap<LinkKey, Arc<SnLink>>>,
}

pub struct MqttSnServer {
    gw: Arc<Gateway>,
}

fn qos_from_sn(q: u8) -> QoS {
    match q {
        1 => QoS::AtLeastOnce,
        2 => QoS::ExactlyOnce,
        _ => QoS::AtMostOnce,
    }
}

impl MqttSnServer {
    pub async fn bind(
        config: MqttSnListenerConfig,
        context: BrokerContext,
    ) -> Result<Self, std::io::Error> {
        let socket = UdpSocket::bind((config.bind_address.as_str(), config.port)).await?;
        if config.advertise_interval_sec > 0 {
            socket.set_broadcast(true)?;
        }
        let mut predef_by_id = HashMap::new();
        let mut predef_by_name = HashMap::new();
        for (id, topic) in &config.predefined_topics {
            match id.parse::<u16>() {
                Ok(n) if n != 0 && n != 0xFFFF => {
                    predef_by_id.insert(n, topic.clone());
                    predef_by_name.insert(topic.clone(), n);
                }
                _ => warn!("Ignoring invalid MQTT-SN predefined topic id '{}'", id),
            }
        }
        Ok(Self {
            gw: Arc::new(Gateway {
                config,
                ctx: context,
                socket: Arc::new(socket),
                predef_by_id,
                predef_by_name,
                links: Mutex::new(HashMap::new()),
            }),
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.gw.socket.local_addr()
    }

    /// Number of connected MQTT-SN clients.
    pub fn client_count(&self) -> usize {
        self.gw.links().len()
    }

    pub async fn run(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let gw = self.gw;
        let local = gw.socket.local_addr()?;
        info!(
            "MQTT-SN gateway listening on {} (gateway id {})",
            local, gw.config.gateway_id
        );

        if gw.config.advertise_interval_sec > 0 {
            let adv = Arc::clone(&gw);
            tokio::spawn(async move { adv.advertise_loop().await });
        }
        let reaper = Arc::clone(&gw);
        tokio::spawn(async move { reaper.reaper_loop().await });

        let mut shutdown = gw.ctx.shutdown_signal();
        let mut buf = vec![0u8; 65_535];
        loop {
            let (len, addr) = tokio::select! {
                r = gw.socket.recv_from(&mut buf) => match r {
                    Ok(v) => v,
                    Err(e) => {
                        // ICMP errors from previous sends surface here on some platforms.
                        debug!("MQTT-SN recv error: {}", e);
                        continue;
                    }
                },
                _ = shutdown.changed() => {
                    info!("MQTT-SN gateway stopped");
                    return Ok(());
                }
            };
            let mut slice = &buf[..len];
            match SnPacket::decode(&mut slice) {
                Ok(SnPacket::EncapMsg {
                    wireless_node_id,
                    payload,
                    ..
                }) => {
                    let key = LinkKey {
                        addr,
                        node: Some(wireless_node_id),
                    };
                    let mut inner = &payload[..];
                    match SnPacket::decode(&mut inner) {
                        Ok(SnPacket::EncapMsg { .. }) => {
                            debug!("Nested MQTT-SN encapsulation from {} ignored", addr)
                        }
                        Ok(pkt) => gw.handle(pkt, key).await,
                        Err(e) => debug!("Bad encapsulated MQTT-SN frame from {}: {}", addr, e),
                    }
                }
                Ok(pkt) => gw.handle(pkt, LinkKey { addr, node: None }).await,
                Err(e) => debug!("Bad MQTT-SN frame from {}: {}", addr, e),
            }
        }
    }
}

impl Gateway {
    fn links(&self) -> MutexGuard<'_, HashMap<LinkKey, Arc<SnLink>>> {
        self.links.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn link(&self, key: &LinkKey) -> Option<Arc<SnLink>> {
        self.links().get(key).cloned()
    }

    async fn send(&self, key: &LinkKey, pkt: &SnPacket) {
        let mut buf = BytesMut::new();
        if let Err(e) = pkt.encode(&mut buf) {
            warn!("Cannot encode MQTT-SN packet for {:?}: {}", key.addr, e);
            return;
        }
        if let Some(node) = &key.node {
            let encap = SnPacket::EncapMsg {
                ctrl: 0,
                wireless_node_id: node.clone(),
                payload: buf.freeze(),
            };
            buf = BytesMut::new();
            if encap.encode(&mut buf).is_err() {
                return;
            }
        }
        if let Err(e) = self.socket.send_to(&buf, key.addr).await {
            debug!("MQTT-SN send to {} failed: {}", key.addr, e);
        }
    }

    /// The ACL identity of MQTT-SN clients.
    async fn identity(&self) -> Option<Arc<UserAccount>> {
        if self.config.acl_user.is_empty() {
            self.ctx.acl.anonymous_identity()
        } else {
            self.ctx.acl.get_user(&self.config.acl_user).await
        }
    }

    async fn advertise_loop(&self) {
        let interval = Duration::from_secs(self.config.advertise_interval_sec as u64);
        let target = format!("{}:{}", self.config.advertise_address, self.config.port);
        let pkt = SnPacket::Advertise {
            gw_id: self.config.gateway_id,
            duration: self.config.advertise_interval_sec,
        };
        let Ok(frame) = pkt.to_bytes() else {
            return;
        };
        let mut tick = tokio::time::interval(interval);
        let mut shutdown = self.ctx.shutdown_signal();
        loop {
            tokio::select! {
                _ = tick.tick() => {}
                _ = shutdown.changed() => return,
            }
            if let Err(e) = self.socket.send_to(&frame, &target).await {
                debug!("ADVERTISE to {} failed: {}", target, e);
            }
        }
    }

    /// Keep-alive / sleep timers (§6.14) and retransmissions (Tretry / Nretry, §6.13).
    async fn reaper_loop(self: Arc<Self>) {
        let mut tick = tokio::time::interval(Duration::from_millis(500));
        let mut shutdown = self.ctx.shutdown_signal();
        let retry_after = Duration::from_secs(self.config.retry_interval_sec.max(1));
        loop {
            tokio::select! {
                _ = tick.tick() => {}
                _ = shutdown.changed() => return,
            }
            let now = Instant::now();
            let links: Vec<Arc<SnLink>> = self.links().values().cloned().collect();
            for link in links {
                enum Action {
                    None,
                    Lost,
                    Resend(SnPacket),
                }
                let action = {
                    let mut st = link.st();
                    let idle = now.duration_since(st.last_seen);
                    let limit = match st.mode {
                        Mode::WillSetup => Some(WILL_SETUP_TIMEOUT),
                        Mode::Active if st.keep_alive > 0 => {
                            Some(Duration::from_millis(st.keep_alive as u64 * 1500))
                        }
                        Mode::Asleep { duration } | Mode::Awake { duration } if duration > 0 => {
                            Some(Duration::from_millis(duration as u64 * 1500))
                        }
                        _ => None,
                    };
                    if limit.is_some_and(|l| idle > l) {
                        Action::Lost
                    } else if let Some(inf) = st
                        .inflight
                        .as_mut()
                        .filter(|i| now.duration_since(i.sent_at) >= retry_after)
                    {
                        if inf.retries >= self.config.max_retries {
                            Action::Lost
                        } else {
                            inf.retries += 1;
                            inf.sent_at = now;
                            if let SnPacket::Publish { dup, .. } = &mut inf.packet {
                                *dup = true;
                            }
                            Action::Resend(inf.packet.clone())
                        }
                    } else {
                        Action::None
                    }
                };
                match action {
                    Action::None => {}
                    Action::Resend(p) => self.send(&link.key, &p).await,
                    Action::Lost => {
                        info!(
                            "MQTT-SN client '{}' at {} timed out",
                            link.session.client_id, link.key.addr
                        );
                        self.close_link(&link, true);
                    }
                }
            }
        }
    }

    /// Detaches a link from its session; `abnormal` publishes the Will.
    fn close_link(&self, link: &Arc<SnLink>, abnormal: bool) {
        if link.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        {
            let mut links = self.links();
            if links.get(&link.key).is_some_and(|l| Arc::ptr_eq(l, link)) {
                links.remove(&link.key);
            }
        }
        let (will, release) = {
            let mut st = link.st();
            (st.will.take(), st.release.take())
        };
        self.ctx.connection_closed(
            &link.session,
            link.epoch,
            if abnormal { will } else { None },
        );
        drop(release);
        link.wake.notify_one();
        link.session.queue.wake();
    }

    fn resolve_topic(
        &self,
        link: Option<&SnLink>,
        id_type: TopicIdType,
        topic_id: u16,
    ) -> Option<String> {
        match id_type {
            TopicIdType::Predefined => self.predef_by_id.get(&topic_id).cloned(),
            TopicIdType::Short => {
                let bytes = topic_id.to_be_bytes();
                String::from_utf8(bytes.to_vec())
                    .ok()
                    .filter(|t| is_valid_topic_name(t))
            }
            TopicIdType::Normal => link.and_then(|l| l.st().topics_by_id.get(&topic_id).cloned()),
            TopicIdType::Reserved => None,
        }
    }

    async fn handle(self: &Arc<Self>, pkt: SnPacket, key: LinkKey) {
        let link = self.link(&key);
        if let Some(l) = &link {
            l.st().last_seen = Instant::now();
        }
        match pkt {
            SnPacket::SearchGw { .. } => {
                let resp = SnPacket::GwInfo {
                    gw_id: self.config.gateway_id,
                    gw_add: None,
                };
                self.send(&key, &resp).await;
            }
            SnPacket::Connect {
                will,
                clean_session,
                duration,
                client_id,
            } => {
                self.on_connect(key, link, will, clean_session, duration, client_id)
                    .await
            }
            SnPacket::WillTopic {
                qos,
                retain,
                will_topic,
            } => {
                let Some(link) = link else { return };
                if will_topic.is_empty() {
                    link.st().will_topic = None;
                    self.finish_connect(&link, true).await;
                } else {
                    link.st().will_topic = Some((will_topic, qos_from_sn(qos), retain));
                    self.send(&key, &SnPacket::WillMsgReq).await;
                }
            }
            SnPacket::WillMsg { will_msg } => {
                let Some(link) = link else { return };
                let topic = link.st().will_topic.take();
                let ok = match topic {
                    Some((topic, qos, retain)) => {
                        self.set_will(&link, topic, qos, retain, will_msg)
                    }
                    None => true,
                };
                self.finish_connect(&link, ok).await;
            }
            SnPacket::WillTopicUpd {
                qos,
                retain,
                will_topic,
            } => {
                let Some(link) = link else { return };
                let rc = if will_topic.is_empty() {
                    link.st().will = None;
                    return_code::ACCEPTED
                } else {
                    let payload = link
                        .st()
                        .will
                        .as_ref()
                        .map(|w| w.payload.clone())
                        .unwrap_or_default();
                    if self.set_will(&link, will_topic, qos_from_sn(qos), retain, payload) {
                        return_code::ACCEPTED
                    } else {
                        return_code::REJECTED_NOT_SUPPORTED
                    }
                };
                self.send(&key, &SnPacket::WillTopicResp { return_code: rc })
                    .await;
            }
            SnPacket::WillMsgUpd { will_msg } => {
                let Some(link) = link else { return };
                if let Some(w) = link.st().will.as_mut() {
                    w.payload = will_msg;
                }
                self.send(
                    &key,
                    &SnPacket::WillMsgResp {
                        return_code: return_code::ACCEPTED,
                    },
                )
                .await;
            }
            SnPacket::Register {
                msg_id, topic_name, ..
            } => {
                let Some(link) = link else { return };
                let (topic_id, rc) = if !is_valid_topic_name(&topic_name) {
                    (0, return_code::REJECTED_INVALID_TOPIC_ID)
                } else {
                    match link.st().topic_id(&topic_name, true) {
                        Some(id) => (id, return_code::ACCEPTED),
                        None => (0, return_code::REJECTED_CONGESTION),
                    }
                };
                self.send(
                    &key,
                    &SnPacket::RegAck {
                        topic_id,
                        msg_id,
                        return_code: rc,
                    },
                )
                .await;
            }
            SnPacket::RegAck {
                topic_id,
                msg_id,
                return_code: rc,
            } => {
                let Some(link) = link else { return };
                let pending = {
                    let mut st = link.st();
                    match st.inflight.take() {
                        Some(Inflight {
                            msg_id: m,
                            kind: InflightKind::Register { topic_id: t, then },
                            ..
                        }) if m == msg_id && t == topic_id => Some(then),
                        other => {
                            st.inflight = other;
                            None
                        }
                    }
                };
                if let Some(delivery) = pending {
                    if rc == return_code::ACCEPTED {
                        self.publish_to_client(&link, *delivery, TopicIdType::Normal, topic_id)
                            .await;
                    } else {
                        let mut st = link.st();
                        if let Some(name) = st.topics_by_id.remove(&topic_id) {
                            st.topics_by_name.remove(&name);
                        }
                    }
                    self.after_progress(&link).await;
                }
            }
            SnPacket::Publish {
                dup: _,
                qos,
                retain,
                topic_id_type,
                topic_id,
                msg_id,
                data,
            } => {
                self.on_publish(
                    key,
                    link,
                    qos,
                    retain,
                    topic_id_type,
                    topic_id,
                    msg_id,
                    data,
                )
                .await
            }
            SnPacket::PubAck { msg_id, .. } => {
                let Some(link) = link else { return };
                let done = {
                    let mut st = link.st();
                    let hit = matches!(&st.inflight, Some(i) if i.msg_id == msg_id
                        && matches!(i.kind, InflightKind::Publish { .. }));
                    if hit {
                        st.inflight = None;
                    }
                    hit
                };
                if done {
                    self.after_progress(&link).await;
                }
            }
            SnPacket::PubRec { msg_id } => {
                let Some(link) = link else {
                    return;
                };
                let rel = {
                    let mut st = link.st();
                    match st.inflight.as_mut() {
                        Some(i)
                            if i.msg_id == msg_id
                                && matches!(
                                    i.kind,
                                    InflightKind::Publish { qos: 2 } | InflightKind::PubRel
                                ) =>
                        {
                            i.kind = InflightKind::PubRel;
                            i.packet = SnPacket::PubRel { msg_id };
                            i.sent_at = Instant::now();
                            i.retries = 0;
                            true
                        }
                        _ => false,
                    }
                };
                if rel {
                    self.send(&key, &SnPacket::PubRel { msg_id }).await;
                }
            }
            SnPacket::PubComp { msg_id } => {
                let Some(link) = link else { return };
                let done = {
                    let mut st = link.st();
                    let hit = matches!(&st.inflight, Some(i) if i.msg_id == msg_id && matches!(i.kind, InflightKind::PubRel));
                    if hit {
                        st.inflight = None;
                    }
                    hit
                };
                if done {
                    self.after_progress(&link).await;
                }
            }
            SnPacket::PubRel { msg_id } => {
                if let Some(link) = &link {
                    link.session.state().inbound_qos2.remove(&msg_id);
                }
                self.send(&key, &SnPacket::PubComp { msg_id }).await;
            }
            SnPacket::Subscribe {
                qos,
                topic_id_type,
                msg_id,
                topic_id,
                topic_name,
                ..
            } => {
                self.on_subscribe(key, link, qos, topic_id_type, msg_id, topic_id, topic_name)
                    .await
            }
            SnPacket::Unsubscribe {
                topic_id_type,
                msg_id,
                topic_id,
                topic_name,
            } => {
                if let Some(link) = &link {
                    let filter = match topic_id_type {
                        TopicIdType::Normal => topic_name,
                        other => self.resolve_topic(Some(link), other, topic_id),
                    };
                    if let Some(f) = filter {
                        self.ctx.unsubscribe(link.session.id, &f);
                    }
                }
                self.send(&key, &SnPacket::UnsubAck { msg_id }).await;
            }
            SnPacket::PingReq { client_id } => {
                let Some(link) = link else {
                    // Unknown client: reply anyway so it can detect the gateway (§6.11).
                    self.send(&key, &SnPacket::PingResp).await;
                    return;
                };
                let woke = {
                    let mut st = link.st();
                    match st.mode {
                        Mode::Asleep { duration } if client_id.is_some() => {
                            st.mode = Mode::Awake { duration };
                            true
                        }
                        _ => false,
                    }
                };
                if woke {
                    link.session.queue.wake();
                    self.after_progress(&link).await;
                } else {
                    self.send(&key, &SnPacket::PingResp).await;
                }
            }
            SnPacket::Disconnect { duration } => {
                let Some(link) = link else {
                    self.send(&key, &SnPacket::Disconnect { duration: None })
                        .await;
                    return;
                };
                match duration {
                    Some(d) if d > 0 => {
                        let mut st = link.st();
                        st.mode = Mode::Asleep { duration: d };
                        st.last_seen = Instant::now();
                    }
                    _ => self.close_link(&link, false),
                }
                self.send(&key, &SnPacket::Disconnect { duration: None })
                    .await;
            }
            SnPacket::PingResp
            | SnPacket::Advertise { .. }
            | SnPacket::GwInfo { .. }
            | SnPacket::ConnAck { .. }
            | SnPacket::WillTopicReq
            | SnPacket::WillMsgReq
            | SnPacket::SubAck { .. }
            | SnPacket::UnsubAck { .. }
            | SnPacket::WillTopicResp { .. }
            | SnPacket::WillMsgResp { .. }
            | SnPacket::EncapMsg { .. } => {}
        }
    }

    fn set_will(
        &self,
        link: &SnLink,
        topic: String,
        qos: QoS,
        retain: bool,
        payload: Bytes,
    ) -> bool {
        let user = link.session.user();
        if !is_valid_topic_name(&topic)
            || !self
                .ctx
                .acl
                .check_publish(&user, &link.session.client_id, &topic)
        {
            warn!(
                "MQTT-SN client '{}' Will topic '{}' rejected",
                link.session.client_id, topic
            );
            return false;
        }
        let will = PublishPacket::new(topic, payload)
            .with_qos(self.ctx.granted_qos(qos), None)
            .with_retain(retain && self.ctx.options.allow_retained_messages);
        link.st().will = Some(will);
        true
    }

    async fn on_connect(
        self: &Arc<Self>,
        key: LinkKey,
        existing: Option<Arc<SnLink>>,
        will: bool,
        clean_session: bool,
        duration: u16,
        client_id: String,
    ) {
        let reject = |rc: u8| SnPacket::ConnAck { return_code: rc };
        if client_id.is_empty() || client_id.len() > MAX_SN_CLIENT_ID_LEN * 4 {
            self.send(&key, &reject(return_code::REJECTED_NOT_SUPPORTED))
                .await;
            return;
        }
        if let Some(old) = existing {
            // A client that reconnects from the same address replaces its previous link.
            self.close_link(&old, false);
        }
        if self.links().len() >= self.config.max_sessions {
            warn!("MQTT-SN session limit reached; rejecting '{}'", client_id);
            self.send(&key, &reject(return_code::REJECTED_CONGESTION))
                .await;
            return;
        }
        let Some(user) = self.identity().await else {
            warn!(
                "MQTT-SN CONNECT from '{}' rejected: no acl_user configured and anonymous access disabled",
                client_id
            );
            self.send(&key, &reject(return_code::REJECTED_NOT_SUPPORTED))
                .await;
            return;
        };
        let expiry = self.ctx.session_expiry_for(None, clean_session, false);
        let opened = match self
            .ctx
            .open_session(&client_id, user, clean_session, expiry, Transport::MqttSn)
            .await
        {
            Ok(o) => o,
            Err(OpenError::ClientIdInUse) | Err(OpenError::Busy) => {
                self.send(&key, &reject(return_code::REJECTED_CONGESTION))
                    .await;
                return;
            }
        };
        let link = Arc::new(SnLink {
            key: key.clone(),
            session: Arc::clone(&opened.session),
            epoch: opened.epoch,
            closed: AtomicBool::new(false),
            wake: Notify::new(),
            st: Mutex::new(LinkState {
                keep_alive: duration,
                last_seen: Instant::now(),
                mode: if will { Mode::WillSetup } else { Mode::Active },
                will_topic: None,
                will: None,
                topics_by_id: HashMap::new(),
                topics_by_name: HashMap::new(),
                next_topic_id: 1,
                next_msg_id: 1,
                inflight: None,
                release: Some(opened.release),
            }),
        });
        self.links().insert(key.clone(), Arc::clone(&link));
        let fw = Arc::clone(self);
        let fw_link = Arc::clone(&link);
        tokio::spawn(async move { fw.forwarder(fw_link, opened.kick).await });

        debug!(
            "MQTT-SN client '{}' connected from {} (will: {}, keep alive: {}s)",
            client_id, key.addr, will, duration
        );
        if will {
            self.send(&key, &SnPacket::WillTopicReq).await;
        } else {
            self.send(
                &key,
                &SnPacket::ConnAck {
                    return_code: return_code::ACCEPTED,
                },
            )
            .await;
        }
    }

    async fn finish_connect(&self, link: &Arc<SnLink>, ok: bool) {
        if !ok {
            self.send(
                &link.key,
                &SnPacket::ConnAck {
                    return_code: return_code::REJECTED_NOT_SUPPORTED,
                },
            )
            .await;
            self.close_link(link, false);
            return;
        }
        link.st().mode = Mode::Active;
        link.session.queue.wake();
        self.send(
            &link.key,
            &SnPacket::ConnAck {
                return_code: return_code::ACCEPTED,
            },
        )
        .await;
    }

    #[allow(clippy::too_many_arguments)]
    async fn on_publish(
        &self,
        key: LinkKey,
        link: Option<Arc<SnLink>>,
        qos: i8,
        retain: bool,
        topic_id_type: TopicIdType,
        topic_id: u16,
        msg_id: u16,
        data: Bytes,
    ) {
        let puback = |rc: u8| SnPacket::PubAck {
            topic_id,
            msg_id,
            return_code: rc,
        };

        // QoS -1: connectionless publish with a predefined or short topic id (§6.8).
        if qos < 0 {
            if !self.config.allow_qos_minus1 || topic_id_type == TopicIdType::Normal {
                return;
            }
            let (Some(topic), Some(user)) = (
                self.resolve_topic(None, topic_id_type, topic_id),
                self.identity().await,
            ) else {
                return;
            };
            if !self
                .ctx
                .acl
                .check_publish(&user, &format!("sn-{}", key.addr.ip()), &topic)
            {
                debug!("QoS -1 publish to '{}' from {} denied", topic, key.addr);
                return;
            }
            let retain = retain && self.ctx.options.allow_retained_messages;
            self.ctx
                .publish(None, PublishPacket::new(topic, data).with_retain(retain));
            return;
        }

        let Some(link) = link.filter(|l| matches!(l.st().mode, Mode::Active | Mode::Awake { .. }))
        else {
            debug!("MQTT-SN PUBLISH from unconnected client {}", key.addr);
            if qos > 0 {
                self.send(&key, &puback(return_code::REJECTED_NOT_SUPPORTED))
                    .await;
            }
            return;
        };
        let Some(topic) = self.resolve_topic(Some(&link), topic_id_type, topic_id) else {
            if qos > 0 {
                self.send(&key, &puback(return_code::REJECTED_INVALID_TOPIC_ID))
                    .await;
            }
            return;
        };
        let user = link.session.user();
        let qos = qos_from_sn(qos as u8);
        if qos > self.ctx.options.maximum_qos
            || !self
                .ctx
                .acl
                .check_publish(&user, &link.session.client_id, &topic)
        {
            warn!(
                "MQTT-SN publish by '{}' to '{}' denied",
                link.session.client_id, topic
            );
            if qos != QoS::AtMostOnce {
                self.send(&key, &puback(return_code::REJECTED_NOT_SUPPORTED))
                    .await;
            }
            return;
        }

        if qos == QoS::ExactlyOnce {
            // Duplicate of a message already accepted: acknowledge without redelivery (§6.7).
            if !link.session.state().inbound_qos2.insert(msg_id) {
                self.send(&key, &SnPacket::PubRec { msg_id }).await;
                return;
            }
        }
        let retain = retain && self.ctx.options.allow_retained_messages;
        let msg = PublishPacket::new(topic, data)
            .with_retain(retain)
            .with_qos(qos, None);
        self.ctx.publish(Some(link.session.id), msg);
        match qos {
            QoS::AtLeastOnce => self.send(&key, &puback(return_code::ACCEPTED)).await,
            QoS::ExactlyOnce => self.send(&key, &SnPacket::PubRec { msg_id }).await,
            QoS::AtMostOnce => {}
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn on_subscribe(
        &self,
        key: LinkKey,
        link: Option<Arc<SnLink>>,
        qos: u8,
        topic_id_type: TopicIdType,
        msg_id: u16,
        topic_id: u16,
        topic_name: Option<String>,
    ) {
        let suback = |rc: u8, tid: u16, q: u8| SnPacket::SubAck {
            qos: q,
            topic_id: tid,
            msg_id,
            return_code: rc,
        };
        let Some(link) = link.filter(|l| matches!(l.st().mode, Mode::Active | Mode::Awake { .. }))
        else {
            self.send(&key, &suback(return_code::REJECTED_NOT_SUPPORTED, 0, 0))
                .await;
            return;
        };
        let filter = match topic_id_type {
            TopicIdType::Normal => topic_name,
            other => self.resolve_topic(Some(&link), other, topic_id),
        };
        let Some(filter) = filter.filter(|f| crate::routing::validate_topic_filter(f).is_ok())
        else {
            self.send(&key, &suback(return_code::REJECTED_INVALID_TOPIC_ID, 0, 0))
                .await;
            return;
        };
        let wildcard = has_wildcards(&filter);
        let user = link.session.user();
        if (wildcard && !self.ctx.options.allow_wildcard_subscriptions)
            || !self
                .ctx
                .acl
                .check_subscribe(&user, &link.session.client_id, &filter)
        {
            warn!(
                "MQTT-SN subscription of '{}' to '{}' denied",
                link.session.client_id, filter
            );
            self.send(&key, &suback(return_code::REJECTED_NOT_SUPPORTED, 0, 0))
                .await;
            return;
        }
        let sub = Subscription::new(SubscriptionOptions::new(
            self.ctx.granted_qos(qos_from_sn(qos)),
        ));
        if self.ctx.subscribe(link.session.id, &filter, sub).is_err() {
            self.send(&key, &suback(return_code::REJECTED_INVALID_TOPIC_ID, 0, 0))
                .await;
            return;
        }
        // Topic id returned in SUBACK (§5.4.16): assigned id for a plain topic name, 0 for a
        // wildcard filter, the request's id for predefined topics.
        let returned_id = match topic_id_type {
            TopicIdType::Normal if !wildcard => link.st().topic_id(&filter, true).unwrap_or(0),
            TopicIdType::Predefined => topic_id,
            _ => 0,
        };
        self.send(
            &key,
            &suback(return_code::ACCEPTED, returned_id, sub.options.qos as u8),
        )
        .await;
        self.ctx.deliver_retained(&link.session, &filter, &sub);
    }

    /// Called whenever inflight state frees up: lets the forwarder continue and completes the
    /// awake cycle of a sleeping client once its buffer is drained.
    async fn after_progress(&self, link: &Arc<SnLink>) {
        let finish_awake = {
            let mut st = link.st();
            match st.mode {
                Mode::Awake { duration }
                    if st.inflight.is_none() && link.session.queue.queued_messages() == 0 =>
                {
                    st.mode = Mode::Asleep { duration };
                    true
                }
                _ => false,
            }
        };
        if finish_awake {
            self.send(&link.key, &SnPacket::PingResp).await;
        }
        link.session.queue.wake();
        link.wake.notify_one();
    }

    /// Drains the session queue to one MQTT-SN client.
    async fn forwarder(self: Arc<Self>, link: Arc<SnLink>, mut kick: oneshot::Receiver<u8>) {
        loop {
            if link.closed.load(Ordering::Acquire) {
                return;
            }
            let item = tokio::select! {
                biased;
                _ = &mut kick => {
                    self.close_link(&link, true);
                    return;
                }
                _ = link.wake.notified() => continue,
                item = link.session.queue.pop(|| link.can_send()) => item,
            };
            match item {
                None => {
                    // The session was discarded (e.g. taken over with clean start).
                    self.close_link(&link, false);
                    return;
                }
                Some(Outbound::Control(_)) => {}
                Some(Outbound::Publish(d)) => {
                    self.deliver(&link, d).await;
                    self.after_progress(&link).await;
                }
            }
        }
    }

    async fn deliver(&self, link: &Arc<SnLink>, d: Delivery) {
        if d.is_expired(Instant::now()) {
            return;
        }
        let topic = d.publish.topic.clone();
        if let Some(&id) = self.predef_by_name.get(&topic) {
            return self
                .publish_to_client(link, d, TopicIdType::Predefined, id)
                .await;
        }
        if topic.len() == 2 {
            let b = topic.as_bytes();
            return self
                .publish_to_client(
                    link,
                    d,
                    TopicIdType::Short,
                    u16::from_be_bytes([b[0], b[1]]),
                )
                .await;
        }
        let register = {
            let mut st = link.st();
            if let Some(id) = st.topics_by_name.get(&topic).copied() {
                Err(id)
            } else {
                match st.topic_id(&topic, true) {
                    Some(topic_id) => {
                        let msg_id = st.next_msg_id();
                        let packet = SnPacket::Register {
                            topic_id,
                            msg_id,
                            topic_name: topic.clone(),
                        };
                        st.inflight = Some(Inflight {
                            msg_id,
                            packet: packet.clone(),
                            kind: InflightKind::Register {
                                topic_id,
                                then: Box::new(d.clone()),
                            },
                            sent_at: Instant::now(),
                            retries: 0,
                        });
                        Ok(Some(packet))
                    }
                    None => Ok(None),
                }
            }
        };
        match register {
            Err(id) => {
                self.publish_to_client(link, d, TopicIdType::Normal, id)
                    .await
            }
            Ok(Some(packet)) => self.send(&link.key, &packet).await,
            Ok(None) => warn!(
                "MQTT-SN client '{}' has too many topics; message dropped",
                link.session.client_id
            ),
        }
    }

    async fn publish_to_client(
        &self,
        link: &Arc<SnLink>,
        d: Delivery,
        id_type: TopicIdType,
        topic_id: u16,
    ) {
        let qos = d.publish.qos as i8;
        let packet = {
            let mut st = link.st();
            let msg_id = if qos > 0 { st.next_msg_id() } else { 0 };
            let packet = SnPacket::Publish {
                dup: false,
                qos,
                retain: d.publish.retain,
                topic_id_type: id_type,
                topic_id,
                msg_id,
                data: d.publish.payload.clone(),
            };
            if qos > 0 {
                st.inflight = Some(Inflight {
                    msg_id,
                    packet: packet.clone(),
                    kind: InflightKind::Publish { qos },
                    sent_at: Instant::now(),
                    retries: 0,
                });
            }
            packet
        };
        let mut probe = BytesMut::new();
        if packet.encode(&mut probe).is_err() {
            warn!(
                "Message on '{}' too large for MQTT-SN; dropped",
                d.publish.topic
            );
            link.st().inflight = None;
            return;
        }
        self.ctx
            .metrics
            .messages_sent
            .fetch_add(1, Ordering::Relaxed);
        self.send(&link.key, &packet).await;
    }
}

impl std::fmt::Debug for Gateway {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Gateway")
            .field("config", &self.config)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> LinkState {
        LinkState {
            keep_alive: 0,
            last_seen: Instant::now(),
            mode: Mode::Active,
            will_topic: None,
            will: None,
            topics_by_id: HashMap::new(),
            topics_by_name: HashMap::new(),
            next_topic_id: 0xFFFE,
            next_msg_id: u16::MAX,
            inflight: None,
            release: None,
        }
    }

    #[test]
    fn topic_ids_skip_reserved_values() {
        let mut st = state();
        assert_eq!(st.topic_id("a", true), Some(0xFFFE));
        // 0xFFFF and 0x0000 are reserved.
        assert_eq!(st.topic_id("b", true), Some(1));
        assert_eq!(st.topic_id("a", false), Some(0xFFFE));
        assert_eq!(st.topic_id("c", false), None);
    }

    #[test]
    fn msg_ids_never_wrap_to_zero() {
        let mut st = state();
        assert_eq!(st.next_msg_id(), u16::MAX);
        assert_eq!(st.next_msg_id(), 1);
    }
}
