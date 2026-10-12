use crate::auth::{AclEngine, UserAccount, UserRole};
use crate::protocol::{MqttPacket, PacketError, PublishPacket, QoS};
use crate::routing::retained::RetainedStore;
use crate::routing::TopicTrie;
use bytes::{Buf, Bytes, BytesMut};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};

static NEXT_CLIENT_ID: AtomicU64 = AtomicU64::new(1);

pub struct BrokerServer {
    listener: TcpListener,
    router: Arc<RwLock<TopicTrie<u64>>>,
    clients: Arc<RwLock<HashMap<u64, mpsc::UnboundedSender<Bytes>>>>,
    retained: Arc<RwLock<RetainedStore>>,
    acl: Arc<AclEngine>,
}

impl BrokerServer {
    /// Binds the broker to a specific socket address (e.g., "127.0.0.1:0" for an ephemeral port).
    pub async fn bind(addr: &str) -> Result<Self, std::io::Error> {
        let listener = TcpListener::bind(addr).await?;
        let router = Arc::new(RwLock::new(TopicTrie::new()));
        let clients = Arc::new(RwLock::new(HashMap::new()));
        let retained = Arc::new(RwLock::new(RetainedStore::new()));
        let acl = Arc::new(AclEngine::new(true));
        Ok(Self {
            listener,
            router,
            clients,
            retained,
            acl,
        })
    }

    /// Attaches a custom AclEngine to the broker for authentication and authorization.
    pub fn with_acl(mut self, acl: Arc<AclEngine>) -> Self {
        self.acl = acl;
        self
    }

    /// Returns a reference to the broker's AclEngine.
    pub fn acl(&self) -> &Arc<AclEngine> {
        &self.acl
    }

    /// Returns the local socket address the server is listening on.
    pub fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.listener.local_addr()
    }

    /// Runs the server event loop accepting client connections concurrently.
    pub async fn run(self) -> Result<(), std::io::Error> {
        let router = self.router;
        let clients = self.clients;
        let retained = self.retained;
        let acl = self.acl;
        info!(
            "WolfiMQ TCP server running on {}",
            self.listener.local_addr()?
        );

        loop {
            let (stream, peer_addr) = self.listener.accept().await?;
            let client_id = NEXT_CLIENT_ID.fetch_add(1, Ordering::Relaxed);
            let router_clone = Arc::clone(&router);
            let clients_clone = Arc::clone(&clients);
            let retained_clone = Arc::clone(&retained);
            let acl_clone = Arc::clone(&acl);

            tokio::spawn(async move {
                debug!("Client #{} connected from {}", client_id, peer_addr);
                if let Err(e) = Self::handle_stream(
                    stream,
                    client_id,
                    router_clone,
                    clients_clone,
                    retained_clone,
                    acl_clone,
                )
                .await
                {
                    warn!("Client #{} disconnected with error: {}", client_id, e);
                } else {
                    debug!("Client #{} disconnected cleanly", client_id);
                }
            });
        }
    }

    /// Runs the server event loop with TLS encryption enabled.
    pub async fn run_tls(self, acceptor: tokio_rustls::TlsAcceptor) -> Result<(), std::io::Error> {
        let router = self.router;
        let clients = self.clients;
        let retained = self.retained;
        let acl = self.acl;
        info!(
            "WolfiMQ TLS server running on {}",
            self.listener.local_addr()?
        );

        loop {
            let (tcp_stream, peer_addr) = self.listener.accept().await?;
            let client_id = NEXT_CLIENT_ID.fetch_add(1, Ordering::Relaxed);
            let router_clone = Arc::clone(&router);
            let clients_clone = Arc::clone(&clients);
            let retained_clone = Arc::clone(&retained);
            let acl_clone = Arc::clone(&acl);
            let acceptor_clone = acceptor.clone();

            tokio::spawn(async move {
                debug!("TLS Client #{} connecting from {}", client_id, peer_addr);
                match acceptor_clone.accept(tcp_stream).await {
                    Ok(tls_stream) => {
                        debug!(
                            "TLS handshake completed successfully for client #{}",
                            client_id
                        );
                        if let Err(e) = Self::handle_stream(
                            tls_stream,
                            client_id,
                            router_clone,
                            clients_clone,
                            retained_clone,
                            acl_clone,
                        )
                        .await
                        {
                            warn!("TLS Client #{} disconnected with error: {}", client_id, e);
                        } else {
                            debug!("TLS Client #{} disconnected cleanly", client_id);
                        }
                    }
                    Err(e) => {
                        warn!("TLS handshake failed for peer {}: {}", peer_addr, e);
                    }
                }
            });
        }
    }

    async fn handle_stream<S>(
        stream: S,
        client_id: u64,
        router: Arc<RwLock<TopicTrie<u64>>>,
        clients: Arc<RwLock<HashMap<u64, mpsc::UnboundedSender<Bytes>>>>,
        retained: Arc<RwLock<RetainedStore>>,
        acl: Arc<AclEngine>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        let (mut read_half, mut write_half) = tokio::io::split(stream);
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
                let _ = write_half.flush().await;
            }
        });

        let mut read_buf = BytesMut::with_capacity(4096);
        let mut subscribed_topics = Vec::new();
        let mut client_will: Option<PublishPacket> = None;
        let mut clean_disconnect = false;
        let mut current_user: Option<UserAccount> = None;
        let mut connected_client_id: String = String::new();

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
                                debug!(
                                    "CONNECT from client '{}' (id: {})",
                                    conn.client_id, client_id
                                );
                                match acl
                                    .authenticate(
                                        conn.username.as_deref(),
                                        conn.password.as_deref(),
                                        &conn.client_id,
                                    )
                                    .await
                                {
                                    Ok(user) => {
                                        connected_client_id = conn.client_id.clone();
                                        current_user = Some(user);
                                        client_will = conn.will;
                                        let connack = MqttPacket::ConnAck {
                                            session_present: false,
                                            reason_code: 0x00,
                                        };
                                        let mut ack_buf = BytesMut::new();
                                        connack.encode(&mut ack_buf)?;
                                        tx.send(ack_buf.freeze())?;
                                    }
                                    Err(auth_err) => {
                                        warn!(
                                            "Client '{}' failed authentication: {:?}",
                                            conn.client_id, auth_err
                                        );
                                        let reason_code = if conn.version
                                            == crate::protocol::ProtocolVersion::V311
                                        {
                                            0x05
                                        } else {
                                            0x86
                                        };
                                        let connack = MqttPacket::ConnAck {
                                            session_present: false,
                                            reason_code,
                                        };
                                        let mut ack_buf = BytesMut::new();
                                        connack.encode(&mut ack_buf)?;
                                        let _ = tx.send(ack_buf.freeze());
                                        tokio::time::sleep(tokio::time::Duration::from_millis(10))
                                            .await;
                                        break;
                                    }
                                }
                            }
                            MqttPacket::Subscribe { packet_id, topics } => {
                                let mut return_codes = Vec::new();
                                let mut matched_retained = Vec::new();

                                let user = current_user.clone().unwrap_or_else(|| UserAccount {
                                    username: "anonymous".into(),
                                    password_hash: String::new(),
                                    role: UserRole::Custom("anonymous".into()),
                                    allowed_rooms: Vec::new(),
                                    custom_rules: Vec::new(),
                                });

                                {
                                    let mut router_guard = router.write().await;
                                    let retained_guard = retained.read().await;
                                    for (topic_filter, qos) in &topics {
                                        if acl.check_subscribe(
                                            &user,
                                            &connected_client_id,
                                            topic_filter,
                                        ) {
                                            if router_guard
                                                .subscribe(topic_filter, client_id)
                                                .is_ok()
                                            {
                                                subscribed_topics.push(topic_filter.clone());
                                                return_codes.push(*qos as u8);
                                                // Collect matching retained messages for this new subscription
                                                let matches = retained_guard
                                                    .get_matches_for_filter(topic_filter);
                                                matched_retained.extend(matches);
                                            } else {
                                                return_codes.push(0x80); // Failure
                                            }
                                        } else {
                                            warn!(
                                                "Subscribe authorization denied for user '{}' on '{}'",
                                                user.username, topic_filter
                                            );
                                            return_codes.push(0x80); // Unauthorized
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

                                // Deliver matching retained messages to the newly subscribed client
                                for ret_pkt in matched_retained {
                                    let mut ret_buf = BytesMut::new();
                                    let ret_packet = MqttPacket::Publish(ret_pkt);
                                    if ret_packet.encode(&mut ret_buf).is_ok() {
                                        let _ = tx.send(ret_buf.freeze());
                                    }
                                }
                            }
                            MqttPacket::Publish(pub_pkt) => {
                                debug!(
                                    "PUBLISH topic '{}', len {}, retain {}",
                                    pub_pkt.topic,
                                    pub_pkt.payload.len(),
                                    pub_pkt.retain
                                );

                                let user = current_user.clone().unwrap_or_else(|| UserAccount {
                                    username: "anonymous".into(),
                                    password_hash: String::new(),
                                    role: UserRole::Custom("anonymous".into()),
                                    allowed_rooms: Vec::new(),
                                    custom_rules: Vec::new(),
                                });

                                if !acl.check_publish(&user, &connected_client_id, &pub_pkt.topic) {
                                    warn!(
                                        "Publish authorization denied for user '{}' on topic '{}'",
                                        user.username, pub_pkt.topic
                                    );
                                    continue;
                                }

                                // If retain flag is set, update retained messages store
                                if pub_pkt.retain {
                                    let mut retained_guard = retained.write().await;
                                    retained_guard.update(pub_pkt.clone());
                                }

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
                                clean_disconnect = true;
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

        // If disconnected abnormally without a clean DISCONNECT, publish Last Will & Testament (LWT)
        if !clean_disconnect {
            if let Some(will_pkt) = client_will.take() {
                let user_ref = current_user.as_ref();
                let will_allowed = if let Some(u) = user_ref {
                    acl.check_publish(u, &connected_client_id, &will_pkt.topic)
                } else {
                    true
                };

                if will_allowed {
                    info!(
                        "Client #{} dropped connection without DISCONNECT. Triggering LWT on topic '{}'",
                        client_id, will_pkt.topic
                    );
                    if will_pkt.retain {
                        let mut retained_guard = retained.write().await;
                        retained_guard.update(will_pkt.clone());
                    }

                    let matched_ids = {
                        let router_guard = router.read().await;
                        router_guard.matches(&will_pkt.topic)
                    };

                    let mut will_buf = BytesMut::new();
                    let will_packet = MqttPacket::Publish(will_pkt);
                    if will_packet.encode(&mut will_buf).is_ok() {
                        let frozen_will = will_buf.freeze();
                        let clients_guard = clients.read().await;
                        for target_id in matched_ids {
                            if target_id != client_id {
                                if let Some(target_tx) = clients_guard.get(&target_id) {
                                    let _ = target_tx.send(frozen_will.clone());
                                }
                            }
                        }
                    }
                } else {
                    warn!(
                        "LWT publish authorization denied for client #{} on topic '{}'",
                        client_id, will_pkt.topic
                    );
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
