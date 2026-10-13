use crate::config::MqttSnListenerConfig;
use crate::protocol::sn::{SnPacket, TopicIdType};
use crate::protocol::{MqttPacket, PublishPacket, QoS};
use crate::server::BrokerContext;
use bytes::{Bytes, BytesMut};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};

#[derive(Debug)]
pub struct SnClientSession {
    pub client_id_str: String,
    pub internal_id: u64,
    pub last_seen: Instant,
    pub duration_sec: u16,
    pub asleep: bool,
    pub will: Option<PublishPacket>,
    pub pending_will_topic: Option<(String, QoS, bool)>,
    pub next_topic_id: u16,
    pub topic_id_to_name: HashMap<u16, String>,
    pub name_to_topic_id: HashMap<String, u16>,
    pub subscribed_topics: Vec<String>,
    pub buffered_messages: Vec<BytesMut>,
}

impl SnClientSession {
    pub fn new(client_id_str: String, internal_id: u64, duration_sec: u16) -> Self {
        Self {
            client_id_str,
            internal_id,
            last_seen: Instant::now(),
            duration_sec,
            asleep: false,
            will: None,
            pending_will_topic: None,
            next_topic_id: 100, // IDs 1..99 reserved for predefined topics
            topic_id_to_name: HashMap::new(),
            name_to_topic_id: HashMap::new(),
            subscribed_topics: Vec::new(),
            buffered_messages: Vec::new(),
        }
    }

    pub fn register_topic(&mut self, name: &str) -> u16 {
        if let Some(&id) = self.name_to_topic_id.get(name) {
            return id;
        }
        let id = self.next_topic_id;
        self.next_topic_id = self.next_topic_id.wrapping_add(1);
        self.name_to_topic_id.insert(name.to_string(), id);
        self.topic_id_to_name.insert(id, name.to_string());
        id
    }
}

pub struct MqttSnServer {
    config: MqttSnListenerConfig,
    context: BrokerContext,
    socket: Arc<UdpSocket>,
    predefined_id_to_name: Arc<HashMap<u16, String>>,
    predefined_name_to_id: Arc<HashMap<String, u16>>,
    sessions: Arc<RwLock<HashMap<SocketAddr, SnClientSession>>>,
}

/// Dispatches an MQTT publish packet through the central broker router and retains it if requested.
async fn dispatch_publish(context: &BrokerContext, pub_pkt: PublishPacket) {
    if pub_pkt.retain {
        let mut ret_guard = context.retained.write().await;
        ret_guard.update(pub_pkt.clone());
    }

    let matched_ids = {
        let router_guard = context.router.read().await;
        router_guard.matches(&pub_pkt.topic)
    };

    let mut forward_pkt = pub_pkt;
    forward_pkt.retain = false;
    let mut forward_buf = BytesMut::new();
    if MqttPacket::Publish(forward_pkt)
        .encode(&mut forward_buf)
        .is_ok()
    {
        let frozen = forward_buf.freeze();
        let clients_guard = context.clients.read().await;
        for target_id in matched_ids {
            if let Some(target_tx) = clients_guard.get(&target_id) {
                let _ = target_tx.try_send(frozen.clone());
            }
        }
    }
}

impl MqttSnServer {
    /// Binds the MQTT-SN server to the address specified in the configuration.
    pub async fn bind(
        config: MqttSnListenerConfig,
        context: BrokerContext,
    ) -> Result<Self, std::io::Error> {
        let bind_addr = format!("{}:{}", config.bind_address, config.port);
        let socket = Arc::new(UdpSocket::bind(&bind_addr).await?);
        let mut id_to_name = HashMap::new();
        let mut name_to_id = HashMap::new();

        for (id_str, topic_name) in &config.predefined_topics {
            if let Ok(id) = id_str.parse::<u16>() {
                id_to_name.insert(id, topic_name.clone());
                name_to_id.insert(topic_name.clone(), id);
            }
        }

        Ok(Self {
            config,
            context,
            socket,
            predefined_id_to_name: Arc::new(id_to_name),
            predefined_name_to_id: Arc::new(name_to_id),
            sessions: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Returns the local socket address this MQTT-SN listener is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.socket.local_addr()
    }

    pub async fn run(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let local_addr = self.socket.local_addr()?;
        info!(
            "WolfiMQ MQTT-SN (UDP) listener running on {} (Gateway ID: {})",
            local_addr, self.config.gateway_id
        );

        let (outbound_tx, mut outbound_rx) = mpsc::channel::<(SocketAddr, BytesMut)>(1024);

        // Task 1: Outbound UDP transmitter
        let out_socket = Arc::clone(&self.socket);
        tokio::spawn(async move {
            while let Some((dest, buf)) = outbound_rx.recv().await {
                if let Err(e) = out_socket.send_to(&buf, dest).await {
                    warn!("Failed to send outbound MQTT-SN packet to {}: {}", dest, e);
                }
            }
        });

        // Task 2: Periodic ADVERTISE broadcast
        if self.config.advertise_interval_sec > 0 {
            let adv_socket = Arc::clone(&self.socket);
            let gw_id = self.config.gateway_id;
            let duration = self.config.advertise_interval_sec * 3;
            let interval =
                std::time::Duration::from_secs(self.config.advertise_interval_sec as u64);

            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(interval);
                let adv_pkt = SnPacket::Advertise { gw_id, duration };
                let mut buf = BytesMut::new();
                adv_pkt.encode(&mut buf);

                loop {
                    ticker.tick().await;
                    let _ = adv_socket.send_to(&buf, "255.255.255.255:1884").await;
                }
            });
        }

        // Task 3: Periodic Session Keepalive & LWT monitor (OASIS MQTT-SN v1.2 §5.4.5)
        let reaper_sessions = Arc::clone(&self.sessions);
        let reaper_context = self.context.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_millis(500));
            loop {
                interval.tick().await;
                let now = Instant::now();
                let mut expired_peers = Vec::new();

                {
                    let lock = reaper_sessions.read().await;
                    for (&peer, session) in lock.iter() {
                        if session.duration_sec > 0 {
                            // MQTT-SN standard timeout threshold is 1.5 * duration
                            let timeout_sec = (session.duration_sec as u64) * 3 / 2;
                            if now.duration_since(session.last_seen).as_secs() >= timeout_sec {
                                expired_peers.push((
                                    peer,
                                    session.internal_id,
                                    session.will.clone(),
                                ));
                            }
                        }
                    }
                }

                if !expired_peers.is_empty() {
                    let mut lock = reaper_sessions.write().await;
                    for (peer, internal_id, will) in expired_peers {
                        lock.remove(&peer);
                        {
                            let mut clients_guard = reaper_context.clients.write().await;
                            clients_guard.remove(&internal_id);
                        }
                        if let Some(will_pkt) = will {
                            warn!(
                                "MQTT-SN client at {} timed out. Publishing LWT on topic '{}'",
                                peer, will_pkt.topic
                            );
                            dispatch_publish(&reaper_context, will_pkt).await;
                        }
                    }
                }
            }
        });

        // Main Loop: Inbound Datagram receiver
        let mut recv_buf = [0u8; 4096];
        loop {
            let (len, peer) = match self.socket.recv_from(&mut recv_buf).await {
                Ok(res) => res,
                Err(e) => {
                    error!("Error receiving UDP packet on MQTT-SN listener: {}", e);
                    continue;
                }
            };

            let mut slice = &recv_buf[..len];
            let packet = match SnPacket::decode(&mut slice) {
                Ok(pkt) => pkt,
                Err(e) => {
                    debug!("Failed to decode MQTT-SN packet from {}: {}", peer, e);
                    continue;
                }
            };

            self.handle_packet(packet, peer, &outbound_tx).await;
        }
    }

    async fn handle_packet(
        &self,
        packet: SnPacket,
        peer: SocketAddr,
        outbound: &mpsc::Sender<(SocketAddr, BytesMut)>,
    ) {
        // Refresh keepalive timer on any received packet (OASIS MQTT-SN v1.2 §5.4.18)
        {
            let mut lock = self.sessions.write().await;
            if let Some(session) = lock.get_mut(&peer) {
                session.last_seen = Instant::now();
            }
        }

        match packet {
            SnPacket::SearchGw { .. } => {
                let resp = SnPacket::GwInfo {
                    gw_id: self.config.gateway_id,
                    gw_add: None,
                };
                let mut buf = BytesMut::new();
                resp.encode(&mut buf);
                let _ = outbound.send((peer, buf)).await;
            }

            SnPacket::Connect {
                will,
                clean_session,
                duration,
                client_id,
            } => {
                debug!(
                    "MQTT-SN CONNECT from {} (client_id: '{}', will: {}, duration: {}s)",
                    peer, client_id, will, duration
                );

                let internal_id = self.context.next_client_id();
                {
                    let mut lock = self.sessions.write().await;
                    if clean_session || !lock.contains_key(&peer) {
                        lock.insert(peer, SnClientSession::new(client_id, internal_id, duration));
                    } else if let Some(session) = lock.get_mut(&peer) {
                        session.last_seen = Instant::now();
                        session.duration_sec = duration;
                        session.asleep = false;
                    }
                }

                if will {
                    // OASIS MQTT-SN v1.2 §5.4.4: Gateway prompts client for WillTopic
                    let will_req = SnPacket::WillTopicReq;
                    let mut buf = BytesMut::new();
                    will_req.encode(&mut buf);
                    let _ = outbound.send((peer, buf)).await;
                } else {
                    let connack = SnPacket::ConnAck { return_code: 0x00 };
                    let mut buf = BytesMut::new();
                    connack.encode(&mut buf);
                    let _ = outbound.send((peer, buf)).await;
                }
            }

            SnPacket::WillTopic {
                qos,
                retain,
                will_topic,
            } => {
                debug!(
                    "MQTT-SN WILLTOPIC from {} (topic: '{}', qos: {})",
                    peer, will_topic, qos
                );
                if will_topic.is_empty() {
                    // OASIS MQTT-SN v1.2 §5.4.4: Empty will_topic deletes will and concludes with ConnAck
                    {
                        let mut lock = self.sessions.write().await;
                        if let Some(session) = lock.get_mut(&peer) {
                            session.will = None;
                            session.pending_will_topic = None;
                        }
                    }
                    let connack = SnPacket::ConnAck { return_code: 0x00 };
                    let mut buf = BytesMut::new();
                    connack.encode(&mut buf);
                    let _ = outbound.send((peer, buf)).await;
                } else {
                    let qos_mapped = match qos {
                        1 => QoS::AtLeastOnce,
                        2 => QoS::ExactlyOnce,
                        _ => QoS::AtMostOnce,
                    };
                    {
                        let mut lock = self.sessions.write().await;
                        if let Some(session) = lock.get_mut(&peer) {
                            session.pending_will_topic = Some((will_topic, qos_mapped, retain));
                        }
                    }

                    let msg_req = SnPacket::WillMsgReq;
                    let mut buf = BytesMut::new();
                    msg_req.encode(&mut buf);
                    let _ = outbound.send((peer, buf)).await;
                }
            }

            SnPacket::WillMsg { will_msg } => {
                debug!("MQTT-SN WILLMSG from {} (len: {})", peer, will_msg.len());
                {
                    let mut lock = self.sessions.write().await;
                    if let Some(session) = lock.get_mut(&peer) {
                        session.last_seen = Instant::now();
                        if let Some((topic, qos, retain)) = session.pending_will_topic.take() {
                            session.will = Some(PublishPacket {
                                topic,
                                qos,
                                retain,
                                dup: false,
                                packet_id: None,
                                payload: will_msg,
                            });
                        }
                    }
                }

                let connack = SnPacket::ConnAck { return_code: 0x00 };
                let mut buf = BytesMut::new();
                connack.encode(&mut buf);
                let _ = outbound.send((peer, buf)).await;
            }

            SnPacket::WillTopicUpd {
                qos,
                retain,
                will_topic,
            } => {
                let qos_mapped = match qos {
                    1 => QoS::AtLeastOnce,
                    2 => QoS::ExactlyOnce,
                    _ => QoS::AtMostOnce,
                };
                {
                    let mut lock = self.sessions.write().await;
                    if let Some(session) = lock.get_mut(&peer) {
                        session.last_seen = Instant::now();
                        if let Some(ref mut will) = session.will {
                            will.topic = will_topic;
                            will.qos = qos_mapped;
                            will.retain = retain;
                        } else {
                            session.pending_will_topic = Some((will_topic, qos_mapped, retain));
                        }
                    }
                }
                let resp = SnPacket::WillTopicResp { return_code: 0x00 };
                let mut buf = BytesMut::new();
                resp.encode(&mut buf);
                let _ = outbound.send((peer, buf)).await;
            }

            SnPacket::WillMsgUpd { will_msg } => {
                {
                    let mut lock = self.sessions.write().await;
                    if let Some(session) = lock.get_mut(&peer) {
                        session.last_seen = Instant::now();
                        if let Some(ref mut will) = session.will {
                            will.payload = will_msg;
                        }
                    }
                }
                let resp = SnPacket::WillMsgResp { return_code: 0x00 };
                let mut buf = BytesMut::new();
                resp.encode(&mut buf);
                let _ = outbound.send((peer, buf)).await;
            }

            SnPacket::Register {
                msg_id, topic_name, ..
            } => {
                let mut assigned_id = 0u16;
                {
                    let mut lock = self.sessions.write().await;
                    if let Some(session) = lock.get_mut(&peer) {
                        assigned_id = session.register_topic(&topic_name);
                    }
                }

                let regack = SnPacket::RegAck {
                    topic_id: assigned_id,
                    msg_id,
                    return_code: 0x00,
                };
                let mut buf = BytesMut::new();
                regack.encode(&mut buf);
                let _ = outbound.send((peer, buf)).await;
            }

            SnPacket::Publish {
                qos,
                retain,
                topic_id_type,
                topic_id,
                msg_id,
                data,
                dup,
            } => {
                // Resolve Topic Name
                let resolved_topic = match topic_id_type {
                    TopicIdType::Predefined => self.predefined_id_to_name.get(&topic_id).cloned(),
                    TopicIdType::Short => {
                        let bytes = topic_id.to_be_bytes();
                        Some(String::from_utf8_lossy(&bytes).to_string())
                    }
                    TopicIdType::Normal => {
                        let lock = self.sessions.read().await;
                        lock.get(&peer)
                            .and_then(|s| s.topic_id_to_name.get(&topic_id).cloned())
                    }
                    _ => None,
                };

                if let Some(topic) = resolved_topic {
                    debug!(
                        "MQTT-SN PUBLISH from {} on topic '{}' (qos: {}, len: {})",
                        peer,
                        topic,
                        qos,
                        data.len()
                    );

                    let qos_mapped = match qos {
                        1 => QoS::AtLeastOnce,
                        2 => QoS::ExactlyOnce,
                        _ => QoS::AtMostOnce,
                    };

                    let pub_pkt = PublishPacket {
                        topic: topic.clone(),
                        qos: qos_mapped,
                        retain,
                        dup,
                        packet_id: if qos > 0 { Some(msg_id) } else { None },
                        payload: data.clone(),
                    };

                    dispatch_publish(&self.context, pub_pkt).await;

                    // QoS 1 Acknowledgment
                    if qos == 1 {
                        let puback = SnPacket::PubAck {
                            topic_id,
                            msg_id,
                            return_code: 0x00,
                        };
                        let mut buf = BytesMut::new();
                        puback.encode(&mut buf);
                        let _ = outbound.send((peer, buf)).await;
                    } else if qos == 2 {
                        // OASIS MQTT-SN v1.2 §5.4.10: QoS 2 Handshake step 1 - Gateway sends PubRec
                        let pubrec = SnPacket::PubRec { msg_id };
                        let mut buf = BytesMut::new();
                        pubrec.encode(&mut buf);
                        let _ = outbound.send((peer, buf)).await;
                    }
                } else {
                    warn!(
                        "MQTT-SN PUBLISH rejected from {}: unknown topic_id {} (type: {:?})",
                        peer, topic_id, topic_id_type
                    );
                    if qos == 1 {
                        let puback = SnPacket::PubAck {
                            topic_id,
                            msg_id,
                            return_code: 0x02, // Rejected-Invalid-Topic-ID
                        };
                        let mut buf = BytesMut::new();
                        puback.encode(&mut buf);
                        let _ = outbound.send((peer, buf)).await;
                    }
                }
            }

            SnPacket::Subscribe {
                qos,
                topic_id_type,
                topic_id,
                topic_name,
                msg_id,
                ..
            } => {
                let resolved_topic = match topic_id_type {
                    TopicIdType::Normal => topic_name,
                    TopicIdType::Predefined => self.predefined_id_to_name.get(&topic_id).cloned(),
                    TopicIdType::Short => {
                        let bytes = topic_id.to_be_bytes();
                        Some(String::from_utf8_lossy(&bytes).to_string())
                    }
                    _ => None,
                };

                if let Some(topic) = resolved_topic {
                    let mut assigned_id = topic_id;
                    let mut internal_id = self.context.next_client_id();

                    {
                        let mut lock = self.sessions.write().await;
                        if let Some(session) = lock.get_mut(&peer) {
                            if topic_id_type == TopicIdType::Normal {
                                assigned_id = session.register_topic(&topic);
                            }
                            session.subscribed_topics.push(topic.clone());
                            internal_id = session.internal_id;
                        }
                    }

                    // Register client channel in central context
                    let (tx, mut rx) = mpsc::channel::<Bytes>(1024);
                    {
                        let mut clients_guard = self.context.clients.write().await;
                        clients_guard.insert(internal_id, tx);
                    }

                    {
                        let mut router_guard = self.context.router.write().await;
                        let _ = router_guard.subscribe(&topic, internal_id);
                    }

                    // Spawn forwarder task for this UDP subscriber
                    let forward_outbound = outbound.clone();
                    let forward_predefined = Arc::clone(&self.predefined_name_to_id);
                    let forward_sessions = Arc::clone(&self.sessions);
                    let target_peer = peer;

                    tokio::spawn(async move {
                        while let Some(raw_mqtt_bytes) = rx.recv().await {
                            let mut slice = &raw_mqtt_bytes[..];
                            if let Ok(MqttPacket::Publish(p)) = MqttPacket::decode(&mut slice) {
                                // Find topic id for this topic
                                let (tid_type, tid) = if let Some(&pid) =
                                    forward_predefined.get(&p.topic)
                                {
                                    (TopicIdType::Predefined, pid)
                                } else if p.topic.len() == 2 {
                                    let bytes = p.topic.as_bytes();
                                    let short_id = u16::from_be_bytes([bytes[0], bytes[1]]);
                                    (TopicIdType::Short, short_id)
                                } else {
                                    let mut lock = forward_sessions.write().await;
                                    if let Some(s) = lock.get_mut(&target_peer) {
                                        if let Some(&nid) = s.name_to_topic_id.get(&p.topic) {
                                            (TopicIdType::Normal, nid)
                                        } else {
                                            let nid = s.register_topic(&p.topic);
                                            // Dynamic registration per OASIS MQTT-SN v1.2 §5.4.8
                                            let reg_pkt = SnPacket::Register {
                                                topic_id: nid,
                                                msg_id: 0,
                                                topic_name: p.topic.clone(),
                                            };
                                            let mut reg_buf = BytesMut::new();
                                            reg_pkt.encode(&mut reg_buf);
                                            let _ =
                                                forward_outbound.send((target_peer, reg_buf)).await;
                                            (TopicIdType::Normal, nid)
                                        }
                                    } else {
                                        (TopicIdType::Normal, 0)
                                    }
                                };

                                let fwd_pkt = SnPacket::Publish {
                                    dup: p.dup,
                                    qos: p.qos as i8,
                                    retain: p.retain,
                                    topic_id_type: tid_type,
                                    topic_id: tid,
                                    msg_id: p.packet_id.unwrap_or(0),
                                    data: p.payload,
                                };

                                let mut buf = BytesMut::new();
                                fwd_pkt.encode(&mut buf);

                                let is_asleep = {
                                    let lock = forward_sessions.read().await;
                                    lock.get(&target_peer).map(|s| s.asleep).unwrap_or(false)
                                };

                                if is_asleep {
                                    let mut lock = forward_sessions.write().await;
                                    if let Some(s) = lock.get_mut(&target_peer) {
                                        s.buffered_messages.push(buf);
                                    }
                                } else {
                                    if forward_outbound.send((target_peer, buf)).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                    });

                    let suback = SnPacket::SubAck {
                        qos,
                        topic_id: assigned_id,
                        msg_id,
                        return_code: 0x00,
                    };
                    let mut buf = BytesMut::new();
                    suback.encode(&mut buf);
                    let _ = outbound.send((peer, buf)).await;
                } else {
                    let suback = SnPacket::SubAck {
                        qos,
                        topic_id: 0,
                        msg_id,
                        return_code: 0x02, // Rejected-Invalid-Topic-ID
                    };
                    let mut buf = BytesMut::new();
                    suback.encode(&mut buf);
                    let _ = outbound.send((peer, buf)).await;
                }
            }

            SnPacket::PubRel { msg_id } => {
                // OASIS MQTT-SN v1.2 §5.4.12: QoS 2 Handshake step 2 - Gateway responds with PubComp
                let pubcomp = SnPacket::PubComp { msg_id };
                let mut buf = BytesMut::new();
                pubcomp.encode(&mut buf);
                let _ = outbound.send((peer, buf)).await;
            }

            SnPacket::PubRec { msg_id } => {
                let pubrel = SnPacket::PubRel { msg_id };
                let mut buf = BytesMut::new();
                pubrel.encode(&mut buf);
                let _ = outbound.send((peer, buf)).await;
            }

            SnPacket::Unsubscribe {
                topic_id_type,
                msg_id,
                topic_id,
                topic_name,
            } => {
                let resolved_topic = match topic_id_type {
                    TopicIdType::Normal => topic_name,
                    TopicIdType::Predefined => self.predefined_id_to_name.get(&topic_id).cloned(),
                    TopicIdType::Short => {
                        let bytes = topic_id.to_be_bytes();
                        Some(String::from_utf8_lossy(&bytes).to_string())
                    }
                    _ => None,
                };

                if let Some(topic) = resolved_topic {
                    let mut internal_id = None;
                    {
                        let mut lock = self.sessions.write().await;
                        if let Some(session) = lock.get_mut(&peer) {
                            session.subscribed_topics.retain(|t| t != &topic);
                            internal_id = Some(session.internal_id);
                        }
                    }
                    if let Some(id) = internal_id {
                        let mut router_guard = self.context.router.write().await;
                        let _ = router_guard.unsubscribe(&topic, &id);
                    }
                }

                let unsuback = SnPacket::UnsubAck { msg_id };
                let mut buf = BytesMut::new();
                unsuback.encode(&mut buf);
                let _ = outbound.send((peer, buf)).await;
            }

            SnPacket::PingReq { client_id } => {
                let buffered = {
                    let mut lock = self.sessions.write().await;
                    if let Some(session) = lock.get_mut(&peer) {
                        session.last_seen = Instant::now();
                        if client_id.is_some() {
                            // OASIS MQTT-SN v1.2 §5.4.18 & §5.4.20: Sleeping client wakes up
                            session.asleep = false;
                        }
                        std::mem::take(&mut session.buffered_messages)
                    } else {
                        Vec::new()
                    }
                };

                // Flush buffered messages to awakening sleeping client
                for msg in buffered {
                    let _ = outbound.send((peer, msg)).await;
                }

                let mut buf = BytesMut::new();
                SnPacket::PingResp.encode(&mut buf);
                let _ = outbound.send((peer, buf)).await;
            }

            SnPacket::Disconnect { duration } => {
                if duration.is_none() {
                    // Permanent disconnect: clean up session and central client channel
                    let mut internal_id = None;
                    {
                        let mut lock = self.sessions.write().await;
                        if let Some(session) = lock.remove(&peer) {
                            internal_id = Some(session.internal_id);
                        }
                    }
                    if let Some(id) = internal_id {
                        let mut clients_guard = self.context.clients.write().await;
                        clients_guard.remove(&id);
                    }
                } else {
                    // OASIS MQTT-SN v1.2 §5.4.20: Client enters Asleep state; retain session & subscriptions
                    let mut lock = self.sessions.write().await;
                    if let Some(session) = lock.get_mut(&peer) {
                        session.last_seen = Instant::now();
                        session.asleep = true;
                    }
                }
                let mut buf = BytesMut::new();
                SnPacket::Disconnect { duration: None }.encode(&mut buf);
                let _ = outbound.send((peer, buf)).await;
            }

            SnPacket::EncapMsg {
                ctrl: _,
                wireless_node_id: _,
                payload,
            } => {
                // OASIS MQTT-SN v1.2 §5.5: Forwarder Encapsulation unwrapping
                let mut slice = &payload[..];
                if let Ok(inner) = SnPacket::decode(&mut slice) {
                    Box::pin(self.handle_packet(inner, peer, outbound)).await;
                }
            }

            SnPacket::RegAck {
                topic_id,
                msg_id,
                return_code,
            } => {
                debug!(
                    "MQTT-SN REGACK from {} (topic_id: {}, msg_id: {}, rc: {})",
                    peer, topic_id, msg_id, return_code
                );
            }

            SnPacket::PubAck {
                topic_id,
                msg_id,
                return_code,
            } => {
                debug!(
                    "MQTT-SN PUBACK from {} (topic_id: {}, msg_id: {}, rc: {})",
                    peer, topic_id, msg_id, return_code
                );
            }

            SnPacket::PubComp { msg_id } => {
                debug!("MQTT-SN PUBCOMP from {} (msg_id: {})", peer, msg_id);
            }

            _ => {}
        }
    }
}
