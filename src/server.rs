use crate::protocol::{MqttPacket, PacketError, QoS};
use crate::routing::TopicTrie;
use bytes::{Buf, Bytes, BytesMut};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};

static NEXT_CLIENT_ID: AtomicU64 = AtomicU64::new(1);

pub struct BrokerServer {
    listener: TcpListener,
    router: Arc<RwLock<TopicTrie<u64>>>,
    clients: Arc<RwLock<HashMap<u64, mpsc::UnboundedSender<Bytes>>>>,
}

impl BrokerServer {
    /// Binds the broker to a specific socket address (e.g., "127.0.0.1:0" for an ephemeral port).
    pub async fn bind(addr: &str) -> Result<Self, std::io::Error> {
        let listener = TcpListener::bind(addr).await?;
        let router = Arc::new(RwLock::new(TopicTrie::new()));
        let clients = Arc::new(RwLock::new(HashMap::new()));
        Ok(Self {
            listener,
            router,
            clients,
        })
    }

    /// Returns the local socket address the server is listening on.
    pub fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.listener.local_addr()
    }

    /// Runs the server event loop accepting client connections concurrently.
    pub async fn run(self) -> Result<(), std::io::Error> {
        let router = self.router;
        let clients = self.clients;
        info!(
            "WolfiMQ TCP server running on {}",
            self.listener.local_addr()?
        );

        loop {
            let (stream, peer_addr) = self.listener.accept().await?;
            let client_id = NEXT_CLIENT_ID.fetch_add(1, Ordering::Relaxed);
            let router_clone = Arc::clone(&router);
            let clients_clone = Arc::clone(&clients);

            tokio::spawn(async move {
                debug!("Client #{} connected from {}", client_id, peer_addr);
                if let Err(e) = Self::handle_client(stream, client_id, router_clone, clients_clone).await {
                    warn!("Client #{} disconnected with error: {}", client_id, e);
                } else {
                    debug!("Client #{} disconnected cleanly", client_id);
                }
            });
        }
    }

    async fn handle_client(
        stream: TcpStream,
        client_id: u64,
        router: Arc<RwLock<TopicTrie<u64>>>,
        clients: Arc<RwLock<HashMap<u64, mpsc::UnboundedSender<Bytes>>>>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (mut read_half, mut write_half) = stream.into_split();
        let (tx, mut rx) = mpsc::unbounded_channel::<Bytes>();

        // Register client sender in the active clients map
        {
            let mut clients_guard = clients.write().await;
            clients_guard.insert(client_id, tx.clone());
        }

        // Spawn a background task to flush outbound messages from the channel to the TCP socket
        let write_task = tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                if write_half.write_all(&msg).await.is_err() {
                    break;
                }
            }
        });

        let mut read_buf = BytesMut::with_capacity(4096);
        let mut subscribed_topics = Vec::new();

        loop {
            let bytes_read = read_half.read_buf(&mut read_buf).await?;
            if bytes_read == 0 {
                // Client closed socket (EOF)
                break;
            }

            // Process all complete MQTT packets in buffer
            while !read_buf.is_empty() {
                let mut slice = &read_buf[..];
                match MqttPacket::decode(&mut slice) {
                    Ok(packet) => {
                        let consumed = read_buf.len() - slice.len();
                        read_buf.advance(consumed);

                        match packet {
                            MqttPacket::Connect(conn) => {
                                debug!("CONNECT from client '{}' (id: {})", conn.client_id, client_id);
                                let connack = MqttPacket::ConnAck {
                                    session_present: false,
                                    reason_code: 0x00,
                                };
                                let mut ack_buf = BytesMut::new();
                                connack.encode(&mut ack_buf)?;
                                tx.send(ack_buf.freeze())?;
                            }
                            MqttPacket::Subscribe { packet_id, topics } => {
                                let mut return_codes = Vec::new();
                                {
                                    let mut router_guard = router.write().await;
                                    for (topic_filter, qos) in &topics {
                                        if router_guard.subscribe(topic_filter, client_id).is_ok() {
                                            subscribed_topics.push(topic_filter.clone());
                                            return_codes.push(*qos as u8);
                                        } else {
                                            return_codes.push(0x80); // Failure
                                        }
                                    }
                                }
                                let suback = MqttPacket::SubAck {
                                    packet_id,
                                    return_codes,
                                };
                                let mut ack_buf = BytesMut::new();
                                suback.encode(&mut ack_buf)?;
                                tx.send(ack_buf.freeze())?;
                            }
                            MqttPacket::Publish(pub_pkt) => {
                                debug!(
                                    "PUBLISH topic '{}', len {}",
                                    pub_pkt.topic,
                                    pub_pkt.payload.len()
                                );

                                // Forward to matching subscribers
                                let matched_ids = {
                                    let router_guard = router.read().await;
                                    router_guard.matches(&pub_pkt.topic)
                                };

                                let mut forward_buf = BytesMut::new();
                                let forward_packet = MqttPacket::Publish(pub_pkt.clone());
                                forward_packet.encode(&mut forward_buf)?;
                                let frozen = forward_buf.freeze();

                                {
                                    let clients_guard = clients.read().await;
                                    for target_id in matched_ids {
                                        if let Some(target_tx) = clients_guard.get(&target_id) {
                                            let _ = target_tx.send(frozen.clone());
                                        }
                                    }
                                }

                                // If QoS 1, respond with PUBACK to the publisher
                                if pub_pkt.qos == QoS::AtLeastOnce {
                                    if let Some(pid) = pub_pkt.packet_id {
                                        let puback = MqttPacket::PubAck { packet_id: pid };
                                        let mut ack_buf = BytesMut::new();
                                        puback.encode(&mut ack_buf)?;
                                        tx.send(ack_buf.freeze())?;
                                    }
                                }
                            }
                            MqttPacket::PingReq => {
                                let mut ping_buf = BytesMut::new();
                                MqttPacket::PingResp.encode(&mut ping_buf)?;
                                tx.send(ping_buf.freeze())?;
                            }
                            MqttPacket::Disconnect => {
                                debug!("DISCONNECT received from client #{}", client_id);
                                break;
                            }
                            _ => {}
                        }
                    }
                    Err(PacketError::BufferUnderflow) => {
                        // Incomplete packet, wait for next TCP read
                        break;
                    }
                    Err(e) => {
                        error!("Packet decode error: {}", e);
                        return Err(Box::new(e));
                    }
                }
            }
        }

        // Clean up subscriptions and connection
        {
            let mut router_guard = router.write().await;
            for topic in subscribed_topics {
                router_guard.unsubscribe(&topic, &client_id);
            }
        }
        {
            let mut clients_guard = clients.write().await;
            clients_guard.remove(&client_id);
        }

        write_task.abort();
        Ok(())
    }
}
