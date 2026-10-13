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
    pub next_topic_id: u16,
    pub topic_id_to_name: HashMap<u16, String>,
    pub name_to_topic_id: HashMap<String, u16>,
    pub subscribed_topics: Vec<String>,
}

impl SnClientSession {
    pub fn new(client_id_str: String, internal_id: u64, duration_sec: u16) -> Self {
        Self {
            client_id_str,
            internal_id,
            last_seen: Instant::now(),
            duration_sec,
            next_topic_id: 100, // IDs 1..99 reserved for predefined topics
            topic_id_to_name: HashMap::new(),
            name_to_topic_id: HashMap::new(),
            subscribed_topics: Vec::new(),
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
    predefined_id_to_name: Arc<HashMap<u16, String>>,
    predefined_name_to_id: Arc<HashMap<String, u16>>,
    sessions: Arc<RwLock<HashMap<SocketAddr, SnClientSession>>>,
}

impl MqttSnServer {
    pub fn new(config: MqttSnListenerConfig, context: BrokerContext) -> Self {
        let mut id_to_name = HashMap::new();
        let mut name_to_id = HashMap::new();

        for (id_str, topic_name) in &config.predefined_topics {
            if let Ok(id) = id_str.parse::<u16>() {
                id_to_name.insert(id, topic_name.clone());
                name_to_id.insert(topic_name.clone(), id);
            }
        }

        Self {
            config,
            context,
            predefined_id_to_name: Arc::new(id_to_name),
            predefined_name_to_id: Arc::new(name_to_id),
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn run(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let bind_addr = format!("{}:{}", self.config.bind_address, self.config.port);
        let socket = Arc::new(UdpSocket::bind(&bind_addr).await?);
        info!(
            "WolfiMQ MQTT-SN (UDP) listener running on {} (Gateway ID: {})",
            bind_addr, self.config.gateway_id
        );

        let (outbound_tx, mut outbound_rx) = mpsc::channel::<(SocketAddr, BytesMut)>(1024);

        // Task 1: Outbound UDP transmitter
        let out_socket = Arc::clone(&socket);
        tokio::spawn(async move {
            while let Some((dest, buf)) = outbound_rx.recv().await {
                if let Err(e) = out_socket.send_to(&buf, dest).await {
                    warn!("Failed to send outbound MQTT-SN packet to {}: {}", dest, e);
                }
            }
        });

        // Task 2: Periodic ADVERTISE broadcast
        if self.config.advertise_interval_sec > 0 {
            let adv_socket = Arc::clone(&socket);
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

        // Main Loop: Inbound Datagram receiver
        let mut recv_buf = [0u8; 4096];
        loop {
            let (len, peer) = match socket.recv_from(&mut recv_buf).await {
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
                clean_session,
                duration,
                client_id,
                ..
            } => {
                debug!(
                    "MQTT-SN CONNECT from {} (client_id: '{}', duration: {}s)",
                    peer, client_id, duration
                );

                let internal_id = self.context.next_client_id();
                {
                    let mut lock = self.sessions.write().await;
                    if clean_session || !lock.contains_key(&peer) {
                        lock.insert(
                            peer,
                            SnClientSession::new(client_id, internal_id, duration),
                        );
                    } else if let Some(session) = lock.get_mut(&peer) {
                        session.last_seen = Instant::now();
                        session.duration_sec = duration;
                    }
                }

                let connack = SnPacket::ConnAck { return_code: 0x00 };
                let mut buf = BytesMut::new();
                connack.encode(&mut buf);
                let _ = outbound.send((peer, buf)).await;
            }

            SnPacket::Register {
                msg_id,
                topic_name,
                ..
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

                    if retain {
                        let mut ret_guard = self.context.retained.write().await;
                        ret_guard.update(pub_pkt.clone());
                    }

                    // Forward to all matching subscribers across TCP, TLS, and SN
                    let matched_ids = {
                        let router_guard = self.context.router.read().await;
                        router_guard.matches(&topic)
                    };

                    let mut forward_pkt = pub_pkt;
                    forward_pkt.retain = false;
                    let mut forward_buf = BytesMut::new();
                    if MqttPacket::Publish(forward_pkt).encode(&mut forward_buf).is_ok() {
                        let frozen = forward_buf.freeze();
                        let clients_guard = self.context.clients.read().await;
                        for target_id in matched_ids {
                            if let Some(target_tx) = clients_guard.get(&target_id) {
                                let _ = target_tx.try_send(frozen.clone());
                            }
                        }
                    }

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
                                let (tid_type, tid) =
                                    if let Some(&pid) = forward_predefined.get(&p.topic) {
                                        (TopicIdType::Predefined, pid)
                                    } else {
                                        let lock = forward_sessions.read().await;
                                        if let Some(s) = lock.get(&target_peer) {
                                            if let Some(&nid) = s.name_to_topic_id.get(&p.topic) {
                                                (TopicIdType::Normal, nid)
                                            } else {
                                                (TopicIdType::Normal, 0)
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
                                if forward_outbound.send((target_peer, buf)).await.is_err() {
                                    break;
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

            SnPacket::PingReq { .. } => {
                {
                    let mut lock = self.sessions.write().await;
                    if let Some(session) = lock.get_mut(&peer) {
                        session.last_seen = Instant::now();
                    }
                }
                let mut buf = BytesMut::new();
                SnPacket::PingResp.encode(&mut buf);
                let _ = outbound.send((peer, buf)).await;
            }

            SnPacket::Disconnect { .. } => {
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
                let mut buf = BytesMut::new();
                SnPacket::Disconnect { duration: None }.encode(&mut buf);
                let _ = outbound.send((peer, buf)).await;
            }

            _ => {}
        }
    }
}
