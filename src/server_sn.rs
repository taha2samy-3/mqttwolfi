//! OASIS MQTT-SN v1.2 gateway over UDP, sharing sessions and routing with the MQTT listeners.
//!
//! MQTT-SN v1.2 carries no credentials, so every SN client acts as one configured ACL identity
//! (`listeners.mqtt_sn.acl_user`) or, when that is empty, as the anonymous identity. UDP source
//! addresses can be spoofed: the gateway bounds every per-client resource, but it should only be
//! exposed on trusted networks.

use crate::auth::UserAccount;
use crate::broker::{BrokerContext, OpenError, SubscribeError};
use crate::config::MqttSnListenerConfig;
use crate::protocol::sn::{return_code, SnPacket, TopicIdType, MAX_SN_CLIENT_ID_LEN};
use crate::protocol::{PublishPacket, QoS, SubscriptionOptions};
use crate::queue::{Delivery, Outbound};
use crate::routing::topic::has_wildcards;
use crate::routing::{is_valid_topic_name, SessionId, Subscription};
use crate::session::{Session, Transport};
use bytes::{Bytes, BytesMut};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{oneshot, Notify};
use tracing::{debug, info, warn};

/// Topics a single client may register (REGISTER from either side, SUBACK ids).
const MAX_REGISTERED_TOPICS: usize = 256;
/// Longest topic name or filter accepted from an MQTT-SN client.
const MAX_TOPIC_LEN: usize = 512;
/// Subscriptions a single MQTT-SN session may hold.
const MAX_SUBSCRIPTIONS: usize = 256;
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
    /// PUBLISH sent; the delivery is kept so it can be re-queued if the link is lost.
    Publish {
        qos: i8,
        delivery: Box<Delivery>,
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

/// Topic registrations of one client (both directions share the id space, §6.5).
#[derive(Debug, Clone)]
struct TopicRegistry {
    by_id: HashMap<u16, String>,
    by_name: HashMap<String, u16>,
    next_id: u16,
}

impl Default for TopicRegistry {
    fn default() -> Self {
        Self {
            by_id: HashMap::new(),
            by_name: HashMap::new(),
            next_id: 1,
        }
    }
}

impl TopicRegistry {
    /// Returns the topic id for `name`, registering it when `allocate` is set.
    fn id(&mut self, name: &str, allocate: bool) -> Option<u16> {
        if let Some(id) = self.by_name.get(name) {
            return Some(*id);
        }
        if !allocate || self.by_id.len() >= MAX_REGISTERED_TOPICS {
            return None;
        }
        // 0x0000 and 0xFFFF are reserved (§5.3.11).
        let mut id = self.next_id;
        while id == 0 || id == 0xFFFF || self.by_id.contains_key(&id) {
            id = id.wrapping_add(1);
        }
        self.next_id = id.wrapping_add(1);
        self.by_id.insert(id, name.to_owned());
        self.by_name.insert(name.to_owned(), id);
        Some(id)
    }

    fn remove_id(&mut self, id: u16) {
        if let Some(name) = self.by_id.remove(&id) {
            self.by_name.remove(&name);
        }
    }
}

/// Client data kept with a persistent session (CleanSession = 0) between connections (§6.3).
#[derive(Debug, Default)]
struct SnPersisted {
    will: Option<PublishPacket>,
    topics: TopicRegistry,
    next_msg_id: u16,
    /// Outbound QoS 2 message waiting for PUBCOMP.
    pubrel: Option<u16>,
}

#[derive(Debug)]
struct LinkState {
    keep_alive: u16,
    last_seen: Instant,
    mode: Mode,
    will_topic: Option<(String, QoS, bool)>,
    will: Option<PublishPacket>,
    topics: TopicRegistry,
    next_msg_id: u16,
    /// MQTT-SN clients are constrained: one outstanding QoS 1/2 or REGISTER at a time.
    inflight: Option<Inflight>,
    /// The client reported congestion; deliveries pause until then.
    backoff_until: Option<Instant>,
    /// Deliveries wait while a SUBACK is outstanding: its topic id must reach the client before
    /// any PUBLISH that uses it.
    paused: bool,
    release: Option<oneshot::Sender<()>>,
}

impl LinkState {
    fn next_msg_id(&mut self) -> u16 {
        let id = self.next_msg_id.max(1);
        self.next_msg_id = id.checked_add(1).unwrap_or(1);
        id
    }
}

#[derive(Debug)]
struct SnLink {
    key: LinkKey,
    client_id: String,
    session: Arc<Session>,
    epoch: u64,
    /// ACL identity the client connected with (owner of its Will).
    owner: Arc<UserAccount>,
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
        matches!(st.mode, Mode::Active | Mode::Awake { .. })
            && !st.paused
            && st.inflight.is_none()
            && st.backoff_until.is_none_or(|t| Instant::now() >= t)
    }
}

struct Gateway {
    config: MqttSnListenerConfig,
    ctx: BrokerContext,
    socket: Arc<UdpSocket>,
    predef_by_id: HashMap<u16, String>,
    predef_by_name: HashMap<String, u16>,
    links: Mutex<HashMap<LinkKey, Arc<SnLink>>>,
    /// Clients whose CONNECT is being processed (it may wait for a session takeover).
    connecting: Mutex<HashSet<LinkKey>>,
    /// Client data of persistent SN sessions that are currently not connected.
    persisted: Mutex<HashMap<SessionId, SnPersisted>>,
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
                connecting: Mutex::new(HashSet::new()),
                persisted: Mutex::new(HashMap::new()),
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

    fn persisted(&self) -> MutexGuard<'_, HashMap<SessionId, SnPersisted>> {
        self.persisted.lock().unwrap_or_else(|e| e.into_inner())
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

    /// Keep-alive / sleep timers (§6.14), retransmissions (Tretry / Nretry, §6.13) and cleanup
    /// of persisted client data whose session has ended.
    async fn reaper_loop(self: Arc<Self>) {
        let mut tick = tokio::time::interval(Duration::from_millis(500));
        let mut shutdown = self.ctx.shutdown_signal();
        let retry_after = Duration::from_secs(self.config.retry_interval_sec.max(1));
        let max_idle = Duration::from_secs(self.config.max_idle_sec.max(1));
        let mut ticks: u64 = 0;
        loop {
            tokio::select! {
                _ = tick.tick() => {}
                _ = shutdown.changed() => return,
            }
            ticks += 1;
            let now = Instant::now();
            let links: Vec<Arc<SnLink>> = self.links().values().cloned().collect();
            for link in links {
                enum Action {
                    None,
                    Lost,
                    Resend(SnPacket),
                    Resume,
                }
                let action = {
                    let mut st = link.st();
                    let idle = now.duration_since(st.last_seen);
                    let limit = match st.mode {
                        Mode::WillSetup => Some(WILL_SETUP_TIMEOUT),
                        Mode::Active if st.keep_alive > 0 => {
                            Some(Duration::from_millis(st.keep_alive as u64 * 1500))
                        }
                        // Keep-alive 0 would let dead UDP clients hold a session forever.
                        Mode::Active => Some(max_idle),
                        Mode::Asleep { duration } | Mode::Awake { duration } if duration > 0 => {
                            Some(Duration::from_millis(duration as u64 * 1500))
                        }
                        _ => None,
                    };
                    let asleep = matches!(st.mode, Mode::Asleep { .. });
                    if limit.is_some_and(|l| idle > l) {
                        Action::Lost
                    } else if st.backoff_until.is_some_and(|t| now >= t) {
                        st.backoff_until = None;
                        Action::Resume
                    } else if let Some(inf) = st
                        .inflight
                        .as_mut()
                        // A sleeping client cannot answer; the message is resent when it wakes.
                        .filter(|i| !asleep && now.duration_since(i.sent_at) >= retry_after)
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
                    Action::Resume => link.session.queue.wake(),
                    Action::Lost => {
                        info!(
                            "MQTT-SN client '{}' at {} timed out",
                            link.client_id, link.key.addr
                        );
                        self.close_link(&link, true);
                    }
                }
            }
            // Every ~30 s: forget client data of sessions that expired meanwhile.
            if ticks % 60 == 0 {
                let ctx = self.ctx.clone();
                self.persisted().retain(|id, _| ctx.session(*id).is_some());
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
        let (will, release, unacked, persisted) = {
            let mut st = link.st();
            let mut pubrel = None;
            let unacked = match st.inflight.take() {
                Some(Inflight {
                    kind: InflightKind::Publish { delivery, .. },
                    ..
                }) => Some(delivery),
                Some(Inflight {
                    kind: InflightKind::Register { then, .. },
                    ..
                }) => Some(then),
                Some(Inflight {
                    kind: InflightKind::PubRel,
                    msg_id,
                    ..
                }) => {
                    pubrel = Some(msg_id);
                    None
                }
                None => None,
            };
            let persisted = SnPersisted {
                will: st.will.clone(),
                topics: std::mem::take(&mut st.topics),
                next_msg_id: st.next_msg_id,
                pubrel,
            };
            (st.will.take(), st.release.take(), unacked, persisted)
        };
        // The unacknowledged message stays with the session for its next connection (QoS 1/2
        // guarantee); it disappears with the session if the session does not persist.
        if let Some(d) = unacked {
            link.session.queue.push_front_publish(*d);
        }
        let will = if abnormal {
            will.map(|w| (w, Arc::clone(&link.owner)))
        } else {
            None
        };
        self.ctx.connection_closed(&link.session, link.epoch, will);
        // A persistent session keeps the client's data for its next CONNECT (§6.3).
        if self.ctx.session(link.session.id).is_some() {
            self.persisted().insert(link.session.id, persisted);
        }
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
            TopicIdType::Normal => link.and_then(|l| l.st().topics.by_id.get(&topic_id).cloned()),
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
                // Answered by unicast: UDP clients cannot rely on broadcast reaching them.
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
                // Opening a session can wait for another connection to release it, so CONNECT
                // runs in its own task instead of stalling every other client of the gateway.
                let first = self
                    .connecting
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(key.clone());
                if !first {
                    debug!("Duplicate MQTT-SN CONNECT from {} ignored", key.addr);
                    return;
                }
                let gw = Arc::clone(self);
                tokio::spawn(async move {
                    gw.on_connect(key.clone(), link, will, clean_session, duration, client_id)
                        .await;
                    gw.connecting
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .remove(&key);
                });
            }
            SnPacket::WillTopic {
                qos,
                retain,
                will_topic,
            } => {
                let Some(link) = link.filter(|l| l.st().mode == Mode::WillSetup) else {
                    return;
                };
                if will_topic.is_empty() {
                    link.st().will = None;
                    self.finish_connect(&link, true).await;
                } else {
                    link.st().will_topic = Some((will_topic, qos_from_sn(qos), retain));
                    self.send(&key, &SnPacket::WillMsgReq).await;
                }
            }
            SnPacket::WillMsg { will_msg } => {
                let Some(link) = link.filter(|l| l.st().mode == Mode::WillSetup) else {
                    return;
                };
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
                let (topic_id, rc) =
                    if topic_name.len() > MAX_TOPIC_LEN || !is_valid_topic_name(&topic_name) {
                        (0, return_code::REJECTED_INVALID_TOPIC_ID)
                    } else {
                        match link.st().topics.id(&topic_name, true) {
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
                    match rc {
                        return_code::ACCEPTED => {
                            self.publish_to_client(&link, *delivery, TopicIdType::Normal, topic_id)
                                .await;
                        }
                        // Congestion: retry the registration later (§6.5).
                        return_code::REJECTED_CONGESTION => {
                            self.retry_later(&link, *delivery, Some(topic_id));
                        }
                        _ => {
                            link.st().topics.remove_id(topic_id);
                            debug!(
                                "MQTT-SN client '{}' refused topic registration; message dropped",
                                link.client_id
                            );
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
            SnPacket::PubAck {
                msg_id,
                topic_id,
                return_code: rc,
            } => {
                let Some(link) = link else { return };
                if self.on_puback(&link, msg_id, topic_id, rc) {
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
                                    InflightKind::Publish { qos: 2, .. } | InflightKind::PubRel
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
                    // Not connected (gateway restart, expired sleep, new address after NAT
                    // rebinding): DISCONNECT tells the client to connect again (§5.4.21).
                    self.send(&key, &SnPacket::Disconnect { duration: None })
                        .await;
                    return;
                };
                enum Ping {
                    Respond,
                    Woke(Option<SnPacket>),
                    StillFlushing,
                }
                let ping = {
                    let mut st = link.st();
                    match st.mode {
                        Mode::Asleep { duration } if client_id.is_some() => {
                            st.mode = Mode::Awake { duration };
                            // Anything left unacknowledged when the client fell asleep is
                            // resent now that it can answer.
                            let resend = st.inflight.as_mut().map(|i| {
                                i.sent_at = Instant::now();
                                if let SnPacket::Publish { dup, .. } = &mut i.packet {
                                    *dup = true;
                                }
                                i.packet.clone()
                            });
                            Ping::Woke(resend)
                        }
                        // A repeated PINGREQ while buffered messages are still being sent.
                        Mode::Awake { .. } => Ping::StillFlushing,
                        _ => Ping::Respond,
                    }
                };
                match ping {
                    Ping::Respond => self.send(&key, &SnPacket::PingResp).await,
                    Ping::Woke(resend) => {
                        if let Some(p) = resend {
                            self.send(&key, &p).await;
                        }
                        link.session.queue.wake();
                        self.after_progress(&link).await;
                    }
                    Ping::StillFlushing => self.after_progress(&link).await,
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

    /// Handles PUBACK from the client; returns true when inflight state changed.
    fn on_puback(&self, link: &Arc<SnLink>, msg_id: u16, topic_id: u16, rc: u8) -> bool {
        let taken = {
            let mut st = link.st();
            let matches = match &st.inflight {
                Some(Inflight {
                    msg_id: m,
                    kind: InflightKind::Publish { qos, .. },
                    ..
                }) if *m == msg_id => rc != return_code::ACCEPTED || *qos == 1,
                _ => false,
            };
            if matches {
                st.inflight.take()
            } else {
                None
            }
        };
        let Some(Inflight {
            kind: InflightKind::Publish { delivery, .. },
            ..
        }) = taken
        else {
            return false;
        };
        match rc {
            return_code::ACCEPTED => {}
            // The client lost the registration: forget it and register again (§6.7).
            return_code::REJECTED_INVALID_TOPIC_ID => {
                link.st().topics.remove_id(topic_id);
                link.session.queue.push_front_publish(*delivery);
            }
            return_code::REJECTED_CONGESTION => self.retry_later(link, *delivery, None),
            _ => debug!(
                "MQTT-SN client '{}' rejected a message (code 0x{:02X})",
                link.client_id, rc
            ),
        }
        true
    }

    /// Puts a delivery back and pauses the link for one retry interval (client congestion).
    fn retry_later(&self, link: &SnLink, delivery: Delivery, forget_topic: Option<u16>) {
        let mut st = link.st();
        if let Some(id) = forget_topic {
            st.topics.remove_id(id);
        }
        st.backoff_until =
            Some(Instant::now() + Duration::from_secs(self.config.retry_interval_sec.max(1)));
        drop(st);
        link.session.queue.push_front_publish(delivery);
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
        if topic.len() > MAX_TOPIC_LEN
            || !is_valid_topic_name(&topic)
            || !self.ctx.may_publish(&user, &link.client_id, &topic)
        {
            warn!(
                "MQTT-SN client '{}' Will topic '{}' rejected",
                link.client_id, topic
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
        // MQTT-SN cannot tell a client to use a shorter keep alive, and a (possibly spoofed)
        // client asking for hours would hold its session long after it is gone.
        let max_keep_alive = self.ctx.options.max_keep_alive_sec;
        if max_keep_alive > 0 && duration > max_keep_alive {
            warn!(
                "MQTT-SN CONNECT from '{}' rejected: keep alive {}s exceeds max_keep_alive_sec {}",
                client_id, duration, max_keep_alive
            );
            self.send(&key, &reject(return_code::REJECTED_NOT_SUPPORTED))
                .await;
            return;
        }
        if let Some(old) = existing {
            if old.client_id == client_id && !clean_session && !old.closed.load(Ordering::Acquire) {
                // The same client connecting again without a clean session (e.g. a sleeping
                // client returning to the active state, §6.14) keeps its session in place.
                self.reactivate(&old, will, duration).await;
                return;
            }
            // A client that reconnects from the same address replaces its previous link.
            self.close_link(&old, false);
        }
        let resuming = self
            .ctx
            .session_by_client_id(&client_id)
            .is_some_and(|s| s.transport == Transport::MqttSn);
        if !resuming && self.ctx.session_count_for(Transport::MqttSn) >= self.config.max_sessions {
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
            .open_session(
                &client_id,
                Arc::clone(&user),
                clean_session,
                expiry,
                Transport::MqttSn,
            )
            .await
        {
            Ok(o) => o,
            Err(OpenError::ClientIdInUse | OpenError::Busy | OpenError::SessionLimit) => {
                self.send(&key, &reject(return_code::REJECTED_CONGESTION))
                    .await;
                return;
            }
        };

        // Restore the client data of a resumed persistent session (§6.3).
        let stored = self.persisted().remove(&opened.session.id);
        let restored = if opened.session_present {
            stored.unwrap_or_default()
        } else {
            SnPersisted::default()
        };
        let pubrel_resend = restored.pubrel.map(|msg_id| Inflight {
            msg_id,
            packet: SnPacket::PubRel { msg_id },
            kind: InflightKind::PubRel,
            sent_at: Instant::now(),
            retries: 0,
        });
        let resend_packet = pubrel_resend.as_ref().map(|i| i.packet.clone());
        let link = Arc::new(SnLink {
            key: key.clone(),
            client_id: client_id.clone(),
            session: Arc::clone(&opened.session),
            epoch: opened.epoch,
            owner: user,
            closed: AtomicBool::new(false),
            wake: Notify::new(),
            st: Mutex::new(LinkState {
                keep_alive: duration,
                last_seen: Instant::now(),
                mode: if will { Mode::WillSetup } else { Mode::Active },
                will_topic: None,
                will: if will { None } else { restored.will },
                topics: restored.topics,
                next_msg_id: restored.next_msg_id,
                inflight: pubrel_resend,
                backoff_until: None,
                paused: false,
                release: Some(opened.release),
            }),
        });
        self.links().insert(key.clone(), Arc::clone(&link));
        debug!(
            "MQTT-SN client '{}' connected from {} (will: {}, keep alive: {}s, session present: {})",
            client_id, key.addr, will, duration, opened.session_present
        );

        // CONNACK must precede any PUBLISH / REGISTER of a resumed session (§6.2), so the
        // forwarder only starts after it has been sent.
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
            if let Some(p) = resend_packet {
                self.send(&key, &p).await;
            }
        }
        let fw = Arc::clone(self);
        let fw_link = Arc::clone(&link);
        tokio::spawn(async move { fw.forwarder(fw_link, opened.kick).await });
    }

    /// Re-activates an existing link of the same client (CONNECT without clean session).
    async fn reactivate(&self, link: &Arc<SnLink>, will: bool, duration: u16) {
        let resend = {
            let mut st = link.st();
            st.keep_alive = duration;
            st.last_seen = Instant::now();
            st.mode = Mode::WillSetup;
            st.will_topic = None;
            st.backoff_until = None;
            st.inflight.as_mut().map(|i| {
                i.sent_at = Instant::now();
                i.retries = 0;
                if let SnPacket::Publish { dup, .. } = &mut i.packet {
                    *dup = true;
                }
                i.packet.clone()
            })
        };
        debug!(
            "MQTT-SN client '{}' reconnected at {} without clean session",
            link.client_id, link.key.addr
        );
        if will {
            self.send(&link.key, &SnPacket::WillTopicReq).await;
            return;
        }
        self.send(
            &link.key,
            &SnPacket::ConnAck {
                return_code: return_code::ACCEPTED,
            },
        )
        .await;
        link.st().mode = Mode::Active;
        if let Some(p) = resend {
            self.send(&link.key, &p).await;
        }
        link.session.queue.wake();
        link.wake.notify_one();
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
        // CONNACK first, then let queued messages flow (§6.2).
        self.send(
            &link.key,
            &SnPacket::ConnAck {
                return_code: return_code::ACCEPTED,
            },
        )
        .await;
        link.st().mode = Mode::Active;
        link.session.queue.wake();
        link.wake.notify_one();
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
            let acl_client_id = match &link {
                Some(l) => l.client_id.clone(),
                None => format!("sn-{}", key.addr.ip()),
            };
            if !self.ctx.may_publish(&user, &acl_client_id, &topic) {
                debug!("QoS -1 publish to '{}' from {} denied", topic, key.addr);
                return;
            }
            let retain = retain && self.ctx.options.allow_retained_messages;
            self.ctx
                .publish(None, PublishPacket::new(topic, data).with_retain(retain));
            return;
        }

        // Sleeping clients may publish too ("wake, publish, sleep" sensors).
        let Some(link) = link.filter(|l| l.st().mode != Mode::WillSetup) else {
            debug!("MQTT-SN PUBLISH from unconnected client {}", key.addr);
            if qos > 0 {
                self.send(&key, &puback(return_code::REJECTED_NOT_SUPPORTED))
                    .await;
            }
            return;
        };
        let Some(topic) = self.resolve_topic(Some(&link), topic_id_type, topic_id) else {
            // Also for QoS 0, so the client can register the topic again (§6.7).
            self.send(&key, &puback(return_code::REJECTED_INVALID_TOPIC_ID))
                .await;
            return;
        };
        let user = link.session.user();
        let qos = qos_from_sn(qos as u8);
        if qos > self.ctx.options.maximum_qos
            || !self.ctx.may_publish(&user, &link.client_id, &topic)
        {
            warn!(
                "MQTT-SN publish by '{}' to '{}' denied",
                link.client_id, topic
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
        let Some(filter) = filter.filter(|f| {
            f.len() <= MAX_TOPIC_LEN && crate::routing::validate_topic_filter(f).is_ok()
        }) else {
            self.send(&key, &suback(return_code::REJECTED_INVALID_TOPIC_ID, 0, 0))
                .await;
            return;
        };
        let wildcard = has_wildcards(&filter);
        let user = link.session.user();
        if (wildcard && !self.ctx.options.allow_wildcard_subscriptions)
            || !self.ctx.may_subscribe(&user, &link.client_id, &filter)
        {
            warn!(
                "MQTT-SN subscription of '{}' to '{}' denied",
                link.client_id, filter
            );
            self.send(&key, &suback(return_code::REJECTED_NOT_SUPPORTED, 0, 0))
                .await;
            return;
        }
        let existing = self.ctx.session_filters(link.session.id);
        if existing.len() >= MAX_SUBSCRIPTIONS && !existing.contains(&filter) {
            self.send(&key, &suback(return_code::REJECTED_CONGESTION, 0, 0))
                .await;
            return;
        }
        // Topic id returned in SUBACK (§5.4.16): the registered id for a plain topic name (the
        // same id later used to deliver it), 0 for a wildcard filter, the request's id for
        // predefined topics.
        let returned_id = match topic_id_type {
            TopicIdType::Normal if !wildcard => {
                let id = link.st().topics.id(&filter, true);
                match id {
                    Some(id) => id,
                    None => {
                        self.send(&key, &suback(return_code::REJECTED_CONGESTION, 0, 0))
                            .await;
                        return;
                    }
                }
            }
            TopicIdType::Predefined => topic_id,
            _ => 0,
        };
        let sub = Subscription::new(SubscriptionOptions::new(
            self.ctx.granted_qos(qos_from_sn(qos)),
        ));
        // Retained and live messages for the new subscription wait until the SUBACK is out.
        link.st().paused = true;
        let reply = match self.ctx.subscribe(&link.session, &filter, sub) {
            Ok(_) => suback(return_code::ACCEPTED, returned_id, sub.options.qos as u8),
            Err(SubscribeError::TooManySubscriptions) => {
                suback(return_code::REJECTED_CONGESTION, 0, 0)
            }
            Err(SubscribeError::InvalidFilter(_)) => {
                suback(return_code::REJECTED_INVALID_TOPIC_ID, 0, 0)
            }
        };
        self.send(&key, &reply).await;
        link.st().paused = false;
        self.after_progress(&link).await;
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
        let now = Instant::now();
        if d.is_expired(now)
            || (d.expires_at.is_none()
                && self
                    .ctx
                    .options
                    .default_message_expiry
                    .is_some_and(|max_wait| d.enqueued_at + max_wait <= now))
        {
            self.ctx
                .metrics
                .messages_dropped
                .fetch_add(1, Ordering::Relaxed);
            return;
        }
        let topic = d.publish.topic.clone();
        // A topic the client registered or subscribed to by name keeps the id it was given.
        let registered = link.st().topics.by_name.get(&topic).copied();
        if let Some(id) = registered {
            return self
                .publish_to_client(link, d, TopicIdType::Normal, id)
                .await;
        }
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
            if link.closed.load(Ordering::Acquire) {
                // Closed while this message was being taken from the queue: keep it.
                drop(st);
                link.session.queue.push_front_publish(d);
                return;
            }
            match st.topics.id(&topic, true) {
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
                            then: Box::new(d),
                        },
                        sent_at: Instant::now(),
                        retries: 0,
                    });
                    Some(packet)
                }
                None => None,
            }
        };
        match register {
            Some(packet) => self.send(&link.key, &packet).await,
            None => warn!(
                "MQTT-SN client '{}' has too many topics; message dropped",
                link.client_id
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
        let topic = d.publish.topic.clone();
        let payload_len = d.publish.payload.len();
        let packet = {
            let mut st = link.st();
            if link.closed.load(Ordering::Acquire) {
                // Closed while this message was being taken from the queue: keep it.
                drop(st);
                link.session.queue.push_front_publish(d);
                return;
            }
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
                    kind: InflightKind::Publish {
                        qos,
                        delivery: Box::new(d),
                    },
                    sent_at: Instant::now(),
                    retries: 0,
                });
            }
            packet
        };
        let mut probe = BytesMut::new();
        if packet.encode(&mut probe).is_err() {
            warn!("Message on '{}' too large for MQTT-SN; dropped", topic);
            link.st().inflight = None;
            self.ctx
                .metrics
                .messages_dropped
                .fetch_add(1, Ordering::Relaxed);
            return;
        }
        self.ctx
            .metrics
            .messages_sent
            .fetch_add(1, Ordering::Relaxed);
        self.ctx
            .metrics
            .bytes_sent
            .fetch_add(payload_len as u64, Ordering::Relaxed);
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

    #[test]
    fn topic_ids_skip_reserved_values_and_are_bounded() {
        let mut reg = TopicRegistry {
            next_id: 0xFFFE,
            ..Default::default()
        };
        assert_eq!(reg.id("a", true), Some(0xFFFE));
        // 0xFFFF and 0x0000 are reserved.
        assert_eq!(reg.id("b", true), Some(1));
        assert_eq!(reg.id("a", false), Some(0xFFFE));
        assert_eq!(reg.id("c", false), None);
        reg.remove_id(1);
        assert_eq!(reg.id("b", false), None);
        for i in 0..MAX_REGISTERED_TOPICS {
            reg.id(&format!("t/{i}"), true);
        }
        assert_eq!(reg.by_id.len(), MAX_REGISTERED_TOPICS);
        assert_eq!(reg.id("one/too/many", true), None);
    }

    #[test]
    fn msg_ids_never_use_zero() {
        let mut st = LinkState {
            keep_alive: 0,
            last_seen: Instant::now(),
            mode: Mode::Active,
            will_topic: None,
            will: None,
            topics: TopicRegistry::default(),
            next_msg_id: u16::MAX,
            inflight: None,
            backoff_until: None,
            paused: false,
            release: None,
        };
        assert_eq!(st.next_msg_id(), u16::MAX);
        assert_eq!(st.next_msg_id(), 1);
        st.next_msg_id = 0;
        assert_eq!(st.next_msg_id(), 1);
    }
}
