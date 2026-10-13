use crate::auth::{AclEngine, UserAccount, UserRole};
use crate::protocol::{MqttPacket, PacketError, PublishPacket, QoS};
use crate::routing::retained::RetainedStore;
use crate::routing::TopicTrie;
use bytes::{Buf, Bytes, BytesMut};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, warn};

static NEXT_CLIENT_ID: AtomicU64 = AtomicU64::new(1);
const CLIENT_CHANNEL_CAPACITY: usize = 1024;

/// Shared broker state across all network listeners (TCP, TLS, etc.)
#[derive(Clone)]
pub struct BrokerContext {
    pub router: Arc<RwLock<TopicTrie<u64>>>,
    pub clients: Arc<RwLock<HashMap<u64, mpsc::Sender<Bytes>>>>,
    pub retained: Arc<RwLock<RetainedStore>>,
    pub acl: Arc<AclEngine>,
    pub client_sessions: Arc<RwLock<HashMap<String, u64>>>,
}

impl BrokerContext {
    pub fn new(acl: Arc<AclEngine>) -> Self {
        Self {
            router: Arc::new(RwLock::new(TopicTrie::new())),
            clients: Arc::new(RwLock::new(HashMap::new())),
            retained: Arc::new(RwLock::new(RetainedStore::new())),
            acl,
            client_sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn next_client_id(&self) -> u64 {
        NEXT_CLIENT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    /// Starts the background periodic $SYS topic publisher task.
    pub fn start_sys_publisher(&self, interval_sec: u64) {
        let context = self.clone();
        let start_time = std::time::Instant::now();
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(interval_sec.max(1)));
            loop {
                interval.tick().await;
                let uptime = start_time.elapsed().as_secs();
                let clients_count = { context.clients.read().await.len() };
                let retained_count = { context.retained.read().await.count() };

                let sys_metrics: [(&str, Bytes); 4] = [
                    ("$SYS/broker/version", Bytes::from_static(b"0.1.0")),
                    ("$SYS/broker/uptime", Bytes::from(uptime.to_string())),
                    (
                        "$SYS/broker/clients/connected",
                        Bytes::from(clients_count.to_string()),
                    ),
                    (
                        "$SYS/broker/messages/retained",
                        Bytes::from(retained_count.to_string()),
                    ),
                ];

                for (topic, payload) in sys_metrics {
                    let pkt = PublishPacket {
                        topic: topic.into(),
                        qos: QoS::AtMostOnce,
                        retain: true,
                        dup: false,
                        packet_id: None,
                        payload,
                    };

                    {
                        let mut ret_guard = context.retained.write().await;
                        ret_guard.update(pkt.clone());
                    }

                    let matched_ids = {
                        let router_guard = context.router.read().await;
                        router_guard.matches(topic)
                    };

                    let mut fwd_pkt = pkt;
                    fwd_pkt.retain = false;
                    let mut buf = BytesMut::new();
                    if MqttPacket::Publish(fwd_pkt).encode(&mut buf).is_ok() {
                        let frozen = buf.freeze();
                        let clients_guard = context.clients.read().await;
                        for id in matched_ids {
                            if let Some(tx) = clients_guard.get(&id) {
                                let _ = tx.try_send(frozen.clone());
                            }
                        }
                    }
                }
            }
        });
    }
}

pub struct BrokerServer {
    listener: TcpListener,
    context: BrokerContext,
}

impl BrokerServer {
    /// Binds the broker to a specific socket address (e.g., "127.0.0.1:0" for an ephemeral port).
    pub async fn bind(addr: &str) -> Result<Self, std::io::Error> {
        let listener = TcpListener::bind(addr).await?;
        let context = BrokerContext::new(Arc::new(AclEngine::new(true)));
        Ok(Self { listener, context })
    }

    /// Attaches an existing shared BrokerContext to this server instance.
    pub fn with_context(mut self, context: BrokerContext) -> Self {
        self.context = context;
        self
    }

    /// Returns a reference to the shared BrokerContext.
    pub fn context(&self) -> &BrokerContext {
        &self.context
    }

    /// Attaches a custom AclEngine to the broker for authentication and authorization.
    pub fn with_acl(mut self, acl: Arc<AclEngine>) -> Self {
        self.context.acl = acl;
        self
    }

    /// Returns a reference to the broker's AclEngine.
    pub fn acl(&self) -> &Arc<AclEngine> {
        &self.context.acl
    }

    /// Returns the local socket address the server is listening on.
    pub fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.listener.local_addr()
    }

    /// Starts the background periodic $SYS topic publisher task.
    pub fn start_sys_publisher(&self, interval_sec: u64) {
        self.context.start_sys_publisher(interval_sec);
    }

    /// Runs the server event loop accepting client connections concurrently.
    pub async fn run(self) -> Result<(), std::io::Error> {
        let context = self.context;
        info!(
            "WolfiMQ TCP server running on {}",
            self.listener.local_addr()?
        );

        loop {
            let (stream, peer_addr) = self.listener.accept().await?;
            let client_id = NEXT_CLIENT_ID.fetch_add(1, Ordering::Relaxed);
            let ctx = context.clone();

            tokio::spawn(async move {
                debug!("Client #{} connected from {}", client_id, peer_addr);
                Self::handle_stream(stream, client_id, ctx).await;
                debug!("Client #{} connection handler closed", client_id);
            });
        }
    }

    /// Runs the server event loop with TLS encryption enabled.
    pub async fn run_tls(self, acceptor: tokio_rustls::TlsAcceptor) -> Result<(), std::io::Error> {
        let context = self.context;
        info!(
            "WolfiMQ TLS server running on {}",
            self.listener.local_addr()?
        );

        loop {
            let (tcp_stream, peer_addr) = self.listener.accept().await?;
            let client_id = NEXT_CLIENT_ID.fetch_add(1, Ordering::Relaxed);
            let ctx = context.clone();
            let acceptor_clone = acceptor.clone();

            tokio::spawn(async move {
                debug!("TLS Client #{} connecting from {}", client_id, peer_addr);
                match acceptor_clone.accept(tcp_stream).await {
                    Ok(tls_stream) => {
                        debug!(
                            "TLS handshake completed successfully for client #{}",
                            client_id
                        );
                        Self::handle_stream(tls_stream, client_id, ctx).await;
                    }
                    Err(e) => {
                        warn!("TLS handshake failed for peer {}: {}", peer_addr, e);
                    }
                }
            });
        }
    }

    async fn handle_stream<S>(stream: S, client_id: u64, context: BrokerContext)
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        let (mut read_half, mut write_half) = tokio::io::split(stream);
        let (tx, mut rx) = mpsc::channel::<Bytes>(CLIENT_CHANNEL_CAPACITY);

        // Register client sender in the active clients map
        {
            let mut clients_guard = context.clients.write().await;
            clients_guard.insert(client_id, tx.clone());
        }

        // Background task to flush outbound messages from channel to TCP stream
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
        let mut current_user: Option<Arc<UserAccount>> = None;
        let mut connected_client_id: String = String::new();
        let mut is_connected = false;
        let mut client_keep_alive: u16 = 60;
        let mut inflight_qos2_pids: std::collections::HashSet<u16> =
            std::collections::HashSet::new();
        let next_outbound_pid = Arc::new(AtomicU16::new(1));

        'connection: loop {
            let keep_alive_duration = if is_connected && client_keep_alive > 0 {
                std::time::Duration::from_millis((client_keep_alive as u64) * 1500)
            } else {
                std::time::Duration::from_secs(60) // initial connect timeout
            };

            let read_result =
                tokio::time::timeout(keep_alive_duration, read_half.read_buf(&mut read_buf)).await;

            let bytes_read = match read_result {
                Ok(Ok(0)) => break 'connection, // EOF
                Ok(Ok(n)) => n,
                Ok(Err(e)) => {
                    warn!("Client #{} I/O error: {}", client_id, e);
                    break 'connection;
                }
                Err(_) => {
                    warn!(
                        "Client #{} keep-alive timeout exceeded ({}s)",
                        client_id, client_keep_alive
                    );
                    break 'connection;
                }
            };

            let _ = bytes_read;

            // Process all complete MQTT packets in buffer
            while !read_buf.is_empty() {
                let mut slice = &read_buf[..];
                match MqttPacket::decode(&mut slice) {
                    Ok(packet) => {
                        let consumed = read_buf.len() - slice.len();
                        read_buf.advance(consumed);

                        match packet {
                            MqttPacket::Connect(conn) => {
                                if is_connected {
                                    warn!(
                                        "Client #{} sent second CONNECT; disconnecting (protocol violation)",
                                        client_id
                                    );
                                    break 'connection;
                                }

                                if conn.client_id.is_empty() && !conn.clean_start {
                                    // MQTT-3.1.3-1: 0-byte client ID with CleanSession=0 rejected
                                    let connack = MqttPacket::ConnAck {
                                        session_present: false,
                                        reason_code: 0x02, // Identifier rejected
                                    };
                                    let mut ack_buf = BytesMut::new();
                                    if connack
                                        .encode_for_version(&mut ack_buf, conn.version)
                                        .is_ok()
                                    {
                                        let _ = tx.send(ack_buf.freeze()).await;
                                    }
                                    break 'connection;
                                }

                                debug!(
                                    "CONNECT from client '{}' (id: {})",
                                    conn.client_id, client_id
                                );
                                match context
                                    .acl
                                    .authenticate(
                                        conn.username.as_deref(),
                                        conn.password.as_deref(),
                                        &conn.client_id,
                                    )
                                    .await
                                {
                                    Ok(user) => {
                                        is_connected = true;
                                        connected_client_id = conn.client_id.clone();
                                        client_keep_alive = conn.keep_alive_sec;
                                        current_user = Some(user);
                                        client_will = conn.will;

                                        // Duplicate Client ID handling (disconnect old session)
                                        if !connected_client_id.is_empty() {
                                            let mut sessions_guard =
                                                context.client_sessions.write().await;
                                            if let Some(old_id) = sessions_guard
                                                .insert(connected_client_id.clone(), client_id)
                                            {
                                                if old_id != client_id {
                                                    warn!(
                                                        "Client ID '{}' reconnected; disconnecting old session #{}",
                                                        connected_client_id, old_id
                                                    );
                                                    let mut clients_guard =
                                                        context.clients.write().await;
                                                    clients_guard.remove(&old_id);
                                                }
                                            }
                                        }

                                        let connack = MqttPacket::ConnAck {
                                            session_present: false,
                                            reason_code: 0x00,
                                        };
                                        let mut ack_buf = BytesMut::new();
                                        if connack
                                            .encode_for_version(&mut ack_buf, conn.version)
                                            .is_ok()
                                        {
                                            let _ = tx.send(ack_buf.freeze()).await;
                                        }
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
                                        if connack
                                            .encode_for_version(&mut ack_buf, conn.version)
                                            .is_ok()
                                        {
                                            let _ = tx.send(ack_buf.freeze()).await;
                                        }
                                        tokio::time::sleep(tokio::time::Duration::from_millis(10))
                                            .await;
                                        break 'connection;
                                    }
                                }
                            }
                            MqttPacket::Subscribe { packet_id, topics } => {
                                if !is_connected {
                                    warn!(
                                        "Client #{} sent SUBSCRIBE before CONNECT; disconnecting",
                                        client_id
                                    );
                                    break 'connection;
                                }

                                let mut return_codes = Vec::new();
                                let mut authorized_filters = Vec::new();

                                let user = current_user.clone().unwrap_or_else(|| {
                                    Arc::new(UserAccount {
                                        username: "anonymous".into(),
                                        password_hash: String::new(),
                                        role: UserRole::Custom("anonymous".into()),
                                        allowed_rooms: Vec::new(),
                                        custom_rules: Vec::new(),
                                    })
                                });

                                // Step 1: Authorization check outside router write lock
                                for (topic_filter, qos) in &topics {
                                    if context.acl.check_subscribe(
                                        &user,
                                        &connected_client_id,
                                        topic_filter,
                                    ) {
                                        let granted_qos = if *qos == QoS::ExactlyOnce {
                                            QoS::AtLeastOnce
                                        } else {
                                            *qos
                                        };
                                        authorized_filters
                                            .push((topic_filter.clone(), granted_qos));
                                        return_codes.push(granted_qos as u8);
                                    } else {
                                        warn!(
                                            "Subscribe authorization denied for user '{}' on '{}'",
                                            user.username, topic_filter
                                        );
                                        return_codes.push(0x80); // Unauthorized
                                    }
                                }

                                // Step 2: Minimal router write lock to register subscriptions
                                {
                                    let mut router_guard = context.router.write().await;
                                    for (topic_filter, _) in &authorized_filters {
                                        if router_guard.subscribe(topic_filter, client_id).is_ok()
                                            && !subscribed_topics.contains(topic_filter)
                                        {
                                            subscribed_topics.push(topic_filter.clone());
                                        }
                                    }
                                }

                                // Step 3: Respond with SubAck
                                let suback = MqttPacket::SubAck {
                                    packet_id,
                                    return_codes,
                                };
                                let mut ack_buf = BytesMut::new();
                                if suback.encode(&mut ack_buf).is_ok() {
                                    let _ = tx.send(ack_buf.freeze()).await;
                                }

                                // Step 4: Retained message queries with read lock
                                let mut matched_retained = Vec::new();
                                {
                                    let retained_guard = context.retained.read().await;
                                    for (topic_filter, _) in &authorized_filters {
                                        let matches =
                                            retained_guard.get_matches_for_filter(topic_filter);
                                        matched_retained.extend(matches);
                                    }
                                }

                                // Deliver matching retained messages (with retain=true and assigned packet_id)
                                for mut ret_pkt in matched_retained {
                                    ret_pkt.retain = true;
                                    if ret_pkt.qos != QoS::AtMostOnce && ret_pkt.packet_id.is_none()
                                    {
                                        ret_pkt.packet_id =
                                            Some(next_outbound_pid.fetch_add(1, Ordering::Relaxed));
                                    }
                                    let mut ret_buf = BytesMut::new();
                                    let ret_packet = MqttPacket::Publish(ret_pkt);
                                    if ret_packet.encode(&mut ret_buf).is_ok() {
                                        let _ = tx.send(ret_buf.freeze()).await;
                                    }
                                }
                            }
                            MqttPacket::Unsubscribe { packet_id, topics } => {
                                if !is_connected {
                                    warn!("Client #{} sent UNSUBSCRIBE before CONNECT", client_id);
                                    break 'connection;
                                }

                                {
                                    let mut router_guard = context.router.write().await;
                                    for topic in &topics {
                                        router_guard.unsubscribe(topic, &client_id);
                                        subscribed_topics.retain(|t| t != topic);
                                    }
                                }

                                let unsuback = MqttPacket::UnsubAck { packet_id };
                                let mut ack_buf = BytesMut::new();
                                if unsuback.encode(&mut ack_buf).is_ok() {
                                    let _ = tx.send(ack_buf.freeze()).await;
                                }
                            }
                            MqttPacket::Publish(pub_pkt) => {
                                if !is_connected {
                                    warn!(
                                        "Client #{} sent PUBLISH before CONNECT; disconnecting",
                                        client_id
                                    );
                                    break 'connection;
                                }

                                debug!(
                                    "PUBLISH topic '{}', len {}, retain {}",
                                    pub_pkt.topic,
                                    pub_pkt.payload.len(),
                                    pub_pkt.retain
                                );

                                let user = current_user.clone().unwrap_or_else(|| {
                                    Arc::new(UserAccount {
                                        username: "anonymous".into(),
                                        password_hash: String::new(),
                                        role: UserRole::Custom("anonymous".into()),
                                        allowed_rooms: Vec::new(),
                                        custom_rules: Vec::new(),
                                    })
                                });

                                if !context.acl.check_publish(
                                    &user,
                                    &connected_client_id,
                                    &pub_pkt.topic,
                                ) {
                                    warn!(
                                        "Publish authorization denied for user '{}' on topic '{}'",
                                        user.username, pub_pkt.topic
                                    );
                                    continue;
                                }

                                // QoS 2: Prevent duplicate subscriber delivery on re-transmitted packets
                                if pub_pkt.qos == QoS::ExactlyOnce {
                                    if let Some(pid) = pub_pkt.packet_id {
                                        if !inflight_qos2_pids.insert(pid) {
                                            debug!(
                                                "Duplicate QoS 2 packet #{} received from client #{}; acknowledging with PUBREC without re-dispatching",
                                                pid, client_id
                                            );
                                            let pubrec = MqttPacket::PubRec { packet_id: pid };
                                            let mut ack_buf = BytesMut::new();
                                            if pubrec.encode(&mut ack_buf).is_ok() {
                                                let _ = tx.send(ack_buf.freeze()).await;
                                            }
                                            continue;
                                        }
                                    }
                                }

                                // If retain flag is set, update retained messages store
                                if pub_pkt.retain {
                                    let mut retained_guard = context.retained.write().await;
                                    retained_guard.update(pub_pkt.clone());
                                }

                                // Forward to matching subscribers
                                let matched_ids = {
                                    let router_guard = context.router.read().await;
                                    router_guard.matches(&pub_pkt.topic)
                                };

                                let mut forward_pkt = pub_pkt.clone();
                                // MQTT-3.3.1-9: Retain flag is cleared when forwarding to existing subscribers
                                forward_pkt.retain = false;
                                if forward_pkt.qos != QoS::AtMostOnce
                                    && forward_pkt.packet_id.is_none()
                                {
                                    forward_pkt.packet_id =
                                        Some(next_outbound_pid.fetch_add(1, Ordering::Relaxed));
                                }

                                let mut forward_buf = BytesMut::new();
                                let forward_packet = MqttPacket::Publish(forward_pkt);
                                if forward_packet.encode(&mut forward_buf).is_ok() {
                                    let frozen = forward_buf.freeze();
                                    let clients_guard = context.clients.read().await;
                                    for target_id in matched_ids {
                                        if let Some(target_tx) = clients_guard.get(&target_id) {
                                            if target_tx.try_send(frozen.clone()).is_err() {
                                                warn!(
                                                    "Slow consumer queue full (1024) on client #{}, dropping message on topic '{}'",
                                                    target_id, pub_pkt.topic
                                                );
                                            }
                                        }
                                    }
                                }

                                // Acknowledge publisher according to QoS
                                match pub_pkt.qos {
                                    QoS::AtLeastOnce => {
                                        if let Some(pid) = pub_pkt.packet_id {
                                            let puback = MqttPacket::PubAck { packet_id: pid };
                                            let mut ack_buf = BytesMut::new();
                                            if puback.encode(&mut ack_buf).is_ok() {
                                                let _ = tx.send(ack_buf.freeze()).await;
                                            }
                                        }
                                    }
                                    QoS::ExactlyOnce => {
                                        if let Some(pid) = pub_pkt.packet_id {
                                            let pubrec = MqttPacket::PubRec { packet_id: pid };
                                            let mut ack_buf = BytesMut::new();
                                            if pubrec.encode(&mut ack_buf).is_ok() {
                                                let _ = tx.send(ack_buf.freeze()).await;
                                            }
                                        }
                                    }
                                    QoS::AtMostOnce => {}
                                }
                            }
                            MqttPacket::PubRel { packet_id } => {
                                inflight_qos2_pids.remove(&packet_id);
                                let pubcomp = MqttPacket::PubComp { packet_id };
                                let mut ack_buf = BytesMut::new();
                                if pubcomp.encode(&mut ack_buf).is_ok() {
                                    let _ = tx.send(ack_buf.freeze()).await;
                                }
                            }
                            MqttPacket::PubRec { packet_id } => {
                                // OASIS MQTT v3.1.1 & v5.0 §4.3.3: Step 2 of outbound QoS 2 delivery to subscriber
                                let pubrel = MqttPacket::PubRel { packet_id };
                                let mut ack_buf = BytesMut::new();
                                if pubrel.encode(&mut ack_buf).is_ok() {
                                    let _ = tx.send(ack_buf.freeze()).await;
                                }
                            }
                            MqttPacket::PubComp { packet_id } => {
                                // OASIS MQTT v3.1.1 & v5.0 §4.3.3: Step 4 concludes outbound QoS 2 delivery
                                debug!(
                                    "PUBCOMP received from subscriber client #{} for packet_id {}",
                                    client_id, packet_id
                                );
                            }
                            MqttPacket::PubAck { packet_id } => {
                                debug!(
                                    "PUBACK received from subscriber client #{} for packet_id {}",
                                    client_id, packet_id
                                );
                            }
                            MqttPacket::PingReq => {
                                let mut ping_buf = BytesMut::new();
                                if MqttPacket::PingResp.encode(&mut ping_buf).is_ok() {
                                    let _ = tx.send(ping_buf.freeze()).await;
                                }
                            }
                            MqttPacket::Disconnect => {
                                clean_disconnect = true;
                                debug!("DISCONNECT received from client #{}", client_id);
                                break 'connection;
                            }
                            _ => {}
                        }
                    }
                    Err(PacketError::BufferUnderflow) => {
                        // Incomplete packet in buffer; wait for next network read
                        break;
                    }
                    Err(e) => {
                        warn!("Client #{} packet decode error: {}", client_id, e);
                        break 'connection;
                    }
                }
            }
        }

        // Guaranteed cleanup & Last Will and Testament (LWT) execution on connection exit
        if !clean_disconnect {
            if let Some(will_pkt) = client_will.take() {
                let user_ref = current_user.as_ref();
                let will_allowed = if let Some(u) = user_ref {
                    context
                        .acl
                        .check_publish(u.as_ref(), &connected_client_id, &will_pkt.topic)
                } else {
                    true
                };

                if will_allowed {
                    info!(
                        "Client #{} dropped connection without DISCONNECT. Triggering LWT on topic '{}'",
                        client_id, will_pkt.topic
                    );
                    if will_pkt.retain {
                        let mut retained_guard = context.retained.write().await;
                        retained_guard.update(will_pkt.clone());
                    }

                    let matched_ids = {
                        let router_guard = context.router.read().await;
                        router_guard.matches(&will_pkt.topic)
                    };

                    let mut forward_will = will_pkt.clone();
                    forward_will.retain = false;
                    if forward_will.qos != QoS::AtMostOnce && forward_will.packet_id.is_none() {
                        forward_will.packet_id =
                            Some(next_outbound_pid.fetch_add(1, Ordering::Relaxed));
                    }

                    let mut will_buf = BytesMut::new();
                    let will_packet = MqttPacket::Publish(forward_will);
                    if will_packet.encode(&mut will_buf).is_ok() {
                        let frozen_will = will_buf.freeze();
                        let clients_guard = context.clients.read().await;
                        for target_id in matched_ids {
                            if target_id != client_id {
                                if let Some(target_tx) = clients_guard.get(&target_id) {
                                    if target_tx.try_send(frozen_will.clone()).is_err() {
                                        warn!(
                                            "Slow consumer queue full on client #{}, dropping LWT message",
                                            target_id
                                        );
                                    }
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

        // Clean up subscriptions from router
        {
            let mut router_guard = context.router.write().await;
            for topic in subscribed_topics {
                router_guard.unsubscribe(&topic, &client_id);
            }
        }

        // Clean up active client sender
        {
            let mut clients_guard = context.clients.write().await;
            clients_guard.remove(&client_id);
        }

        // Clean up client session map
        if !connected_client_id.is_empty() {
            let mut sessions_guard = context.client_sessions.write().await;
            if sessions_guard.get(&connected_client_id) == Some(&client_id) {
                sessions_guard.remove(&connected_client_id);
            }
        }

        write_task.abort();
    }
}
