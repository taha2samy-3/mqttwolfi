//! MQTT v3.1.1 / v5.0 connection handler, generic over the transport (TCP or wolfSSL TLS).
//!
//! Each connection runs two tasks: this reader, which decodes and handles client packets, and a
//! writer that drains the session's outbound queue and encodes every packet for the client's
//! protocol version.

use crate::broker::{
    connack_capabilities, granted_subscription, BrokerContext, OpenError, OpenedSession,
};
use crate::protocol::{
    connack_v3, reason, ConnectPacket, MqttPacket, PacketError, Properties, Property,
    ProtocolVersion, PublishPacket, QoS, RetainHandling,
};
use crate::queue::Outbound;
use crate::routing::topic::has_wildcards;
use crate::routing::{is_valid_topic_name, parse_shared_subscription, validate_topic_filter};
use crate::session::{InflightOut, Session, Transport};
use bytes::{Bytes, BytesMut};
use rand_core::{OsRng, RngCore};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::oneshot;
use tokio::time::Instant;
use tracing::{debug, info, warn};

/// Largest batch the writer assembles before one socket write.
const WRITE_BATCH_BYTES: usize = 64 * 1024;
/// How long teardown waits for the writer to flush.
const WRITER_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Facts about the remote peer established by the listener.
#[derive(Debug, Clone, Default)]
pub struct PeerInfo {
    pub addr: Option<SocketAddr>,
    /// Identities (subject CN and SANs) of a verified TLS client certificate. `None` on plain TCP.
    pub tls_identities: Option<Vec<String>>,
}

/// Why the connection ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Exit {
    /// DISCONNECT with reason 0x00: the Will is discarded.
    Normal,
    /// DISCONNECT with reason 0x04 or any other client-side reason: the Will is published.
    ClientDisconnectWithWill,
    /// Socket closed or failed.
    Closed,
    /// The broker closes the connection with this v5.0 reason code.
    Server(u8),
}

impl Exit {
    fn publishes_will(self) -> bool {
        self != Exit::Normal
    }
}

async fn write_direct<W: AsyncWrite + Unpin>(
    wr: &mut W,
    pkt: &MqttPacket,
    version: ProtocolVersion,
) -> std::io::Result<()> {
    let bytes = pkt.to_bytes(version).map_err(std::io::Error::other)?;
    wr.write_all(&bytes).await?;
    wr.flush().await
}

/// Writes a refusing CONNACK and closes the connection.
async fn refuse<W: AsyncWrite + Unpin>(
    wr: &mut W,
    version: ProtocolVersion,
    code_v3: u8,
    code_v5: u8,
) {
    let code = if version == ProtocolVersion::V500 {
        code_v5
    } else {
        code_v3
    };
    let _ = write_direct(wr, &MqttPacket::connack(false, code), version).await;
    let _ = wr.shutdown().await;
}

fn generate_client_id() -> String {
    let mut raw = [0u8; 8];
    OsRng.fill_bytes(&mut raw);
    let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    format!("wolfimq-{hex}")
}

/// Serves one client connection until it ends.
pub async fn serve<S>(stream: S, peer: PeerInfo, ctx: BrokerContext)
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (mut rd, mut wr) = tokio::io::split(stream);
    let max_packet = ctx.options.max_packet_size;
    let mut buf = BytesMut::with_capacity(4096);

    // ── 1. Read the CONNECT packet within the connect timeout (§3.1, MQTT-3.1.0-1) ──────────
    let deadline = Instant::now() + ctx.options.connect_timeout;
    let first = loop {
        match MqttPacket::decode_from(&mut buf, ProtocolVersion::V311, max_packet) {
            Ok(Some(p)) => break p,
            Ok(None) => {}
            Err(PacketError::UnsupportedProtocolVersion(level)) => {
                debug!(
                    "Peer {:?} uses unsupported protocol level {}",
                    peer.addr, level
                );
                refuse(
                    &mut wr,
                    ProtocolVersion::V311,
                    connack_v3::UNACCEPTABLE_PROTOCOL_VERSION,
                    0,
                )
                .await;
                return;
            }
            Err(e) => {
                debug!("Invalid first packet from {:?}: {}", peer.addr, e);
                return;
            }
        }
        match tokio::time::timeout_at(deadline, rd.read_buf(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => {}
            Ok(_) => return,
            Err(_) => {
                debug!(
                    "Peer {:?} did not send CONNECT within the connect timeout",
                    peer.addr
                );
                return;
            }
        }
    };
    let MqttPacket::Connect(connect) = first else {
        debug!("First packet from {:?} is not CONNECT; closing", peer.addr);
        return;
    };

    // ── 2. Validate and authenticate ─────────────────────────────────────────────────────
    let Some(accepted) = accept_connect(&ctx, &peer, connect, &mut wr).await else {
        return;
    };

    // ── 3. Attach to the session and start the writer ─────────────────────────────────────
    let Accepted {
        connect,
        client_id,
        assigned_id,
        user,
        keep_alive,
        server_keep_alive,
        expiry,
        expiry_overridden,
    } = accepted;
    let version = connect.version;
    let v5 = version == ProtocolVersion::V500;

    let opened = match ctx
        .open_session(
            &client_id,
            Arc::clone(&user),
            connect.clean_start,
            expiry,
            Transport::Mqtt,
        )
        .await
    {
        Ok(o) => o,
        Err(OpenError::ClientIdInUse) => {
            refuse(
                &mut wr,
                version,
                connack_v3::IDENTIFIER_REJECTED,
                reason::CLIENT_IDENTIFIER_NOT_VALID,
            )
            .await;
            return;
        }
        Err(OpenError::Busy) => {
            refuse(
                &mut wr,
                version,
                connack_v3::SERVER_UNAVAILABLE,
                reason::SERVER_BUSY,
            )
            .await;
            return;
        }
    };
    let OpenedSession {
        session,
        session_present,
        epoch,
        mut kick,
        release,
    } = opened;

    let mut connack_props = Properties::new();
    if v5 {
        connack_props = connack_capabilities(&ctx.options);
        if let Some(id) = &assigned_id {
            connack_props.push(Property::AssignedClientIdentifier(id.clone()));
        }
        if expiry_overridden {
            connack_props.push(Property::SessionExpiryInterval(expiry));
        }
        if let Some(ka) = server_keep_alive {
            connack_props.push(Property::ServerKeepAlive(ka));
        }
    }
    let connack = MqttPacket::ConnAck {
        session_present,
        reason_code: reason::SUCCESS,
        properties: connack_props,
    };
    let Ok(connack) = connack.to_bytes(version) else {
        ctx.connection_closed(&session, epoch, None);
        return;
    };
    info!(
        "Client '{}' connected from {:?} (MQTT {}, user '{}', session present: {})",
        client_id,
        peer.addr,
        if v5 { "5.0" } else { "3.1.1" },
        user.username,
        session_present
    );

    let client_receive_max = connect.properties.receive_maximum().unwrap_or(u16::MAX) as usize;
    let client_max_packet = connect
        .properties
        .maximum_packet_size()
        .map(|m| m as usize)
        .unwrap_or(usize::MAX);
    let (stop_tx, stop_rx) = oneshot::channel::<Option<u8>>();
    let mut writer = tokio::spawn(run_writer(
        wr,
        ctx.clone(),
        Arc::clone(&session),
        connack,
        WriterParams {
            version,
            client_receive_max,
            client_max_packet,
            resend_inflight: session_present,
        },
        stop_rx,
    ));

    // ── 4. Packet loop ─────────────────────────────────────────────────────────────────────
    let mut conn = Conn {
        ctx: &ctx,
        session: &session,
        version,
        user,
        will: connect.will.clone(),
        connect_expiry: expiry,
        topic_aliases: HashMap::new(),
    };
    let ka = (keep_alive > 0).then(|| Duration::from_millis(keep_alive as u64 * 1500));
    let mut ka_deadline = ka.map(|d| Instant::now() + d);
    let mut writer_done = false;

    let exit = 'conn: loop {
        loop {
            match MqttPacket::decode_from(&mut buf, version, max_packet) {
                Ok(Some(pkt)) => {
                    if let Some(d) = ka {
                        ka_deadline = Some(Instant::now() + d);
                    }
                    if let Some(exit) = conn.handle(pkt) {
                        break 'conn exit;
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    warn!("Client '{}' sent an invalid packet: {}", client_id, e);
                    break 'conn Exit::Server(e.reason_code());
                }
            }
        }

        let read = async {
            match ka_deadline {
                Some(d) => tokio::time::timeout_at(d, rd.read_buf(&mut buf)).await,
                None => Ok(rd.read_buf(&mut buf).await),
            }
        };
        tokio::select! {
            biased;
            code = &mut kick => {
                break Exit::Server(code.unwrap_or(reason::SESSION_TAKEN_OVER));
            }
            _ = &mut writer => {
                writer_done = true;
                break Exit::Closed;
            }
            r = read => match r {
                Err(_) => {
                    info!("Client '{}' keep-alive timeout ({}s)", client_id, keep_alive);
                    break Exit::Server(reason::KEEP_ALIVE_TIMEOUT);
                }
                Ok(Ok(0)) | Ok(Err(_)) => break Exit::Closed,
                Ok(Ok(_)) => {}
            }
        }
    };

    // ── 5. Teardown ────────────────────────────────────────────────────────────────────────
    let notify_code = match exit {
        Exit::Server(code) if v5 => Some(code),
        _ => None,
    };
    let _ = stop_tx.send(notify_code);
    if !writer_done
        && tokio::time::timeout(WRITER_DRAIN_TIMEOUT, &mut writer)
            .await
            .is_err()
    {
        writer.abort();
    }
    let will = if exit.publishes_will() {
        conn.will.take()
    } else {
        None
    };
    info!("Client '{}' disconnected ({:?})", client_id, exit);
    ctx.connection_closed(&session, epoch, will);
    drop(release);
}

/// Result of a successful CONNECT validation.
struct Accepted {
    connect: ConnectPacket,
    client_id: String,
    assigned_id: Option<String>,
    user: Arc<crate::auth::UserAccount>,
    keep_alive: u16,
    server_keep_alive: Option<u16>,
    expiry: u32,
    expiry_overridden: bool,
}

/// Validates the CONNECT packet; on rejection writes the CONNACK and returns `None`.
async fn accept_connect<W: AsyncWrite + Unpin>(
    ctx: &BrokerContext,
    peer: &PeerInfo,
    mut connect: ConnectPacket,
    wr: &mut W,
) -> Option<Accepted> {
    let version = connect.version;
    let v5 = version == ProtocolVersion::V500;
    let opts = &ctx.options;

    if (v5 && !opts.allow_v500) || (!v5 && !opts.allow_v311) {
        refuse(
            wr,
            version,
            connack_v3::UNACCEPTABLE_PROTOCOL_VERSION,
            reason::UNSUPPORTED_PROTOCOL_VERSION,
        )
        .await;
        return None;
    }
    if v5 && connect.properties.authentication_method().is_some() {
        // Enhanced authentication (AUTH packets) is not supported (§4.12).
        refuse(wr, version, 0, reason::BAD_AUTHENTICATION_METHOD).await;
        return None;
    }

    // Zero-length ClientID: assign one (§3.1.3.1). v3.1.1 requires CleanSession = 1 for that.
    let mut assigned_id = None;
    if connect.client_id.is_empty() {
        if !v5 && !connect.clean_start {
            refuse(wr, version, connack_v3::IDENTIFIER_REJECTED, 0).await;
            return None;
        }
        let id = generate_client_id();
        connect.client_id = id.clone();
        assigned_id = Some(id);
    }
    let client_id = connect.client_id.clone();

    let user = match ctx
        .acl
        .authenticate(
            connect.username.as_deref(),
            connect.password.as_deref(),
            &client_id,
        )
        .await
    {
        Ok(u) => u,
        Err(e) => {
            use crate::auth::AuthError;
            warn!(
                "Client '{}' from {:?} failed authentication: {}",
                client_id, peer.addr, e
            );
            let (v3, v5code) = match e {
                AuthError::BadCredentials => (
                    connack_v3::BAD_USER_NAME_OR_PASSWORD,
                    reason::BAD_USER_NAME_OR_PASSWORD,
                ),
                AuthError::AnonymousNotAllowed => {
                    (connack_v3::NOT_AUTHORIZED, reason::NOT_AUTHORIZED)
                }
                AuthError::ClientIdMismatch => (
                    connack_v3::IDENTIFIER_REJECTED,
                    reason::CLIENT_IDENTIFIER_NOT_VALID,
                ),
            };
            refuse(wr, version, v3, v5code).await;
            return None;
        }
    };

    // Bind the MQTT ClientID to the TLS client certificate when configured.
    if opts.verify_client_identity {
        if let Some(ids) = &peer.tls_identities {
            if !ids.iter().any(|i| i == &client_id) {
                warn!(
                    "ClientID '{}' does not match the client certificate identities {:?}",
                    client_id, ids
                );
                refuse(
                    wr,
                    version,
                    connack_v3::NOT_AUTHORIZED,
                    reason::NOT_AUTHORIZED,
                )
                .await;
                return None;
            }
        }
    }

    if let Some(will) = connect.will.as_mut() {
        if !ctx.acl.check_publish(&user, &client_id, &will.topic) {
            warn!(
                "Client '{}' Will topic '{}' is not authorized",
                client_id, will.topic
            );
            refuse(
                wr,
                version,
                connack_v3::NOT_AUTHORIZED,
                reason::NOT_AUTHORIZED,
            )
            .await;
            return None;
        }
        if will.qos > opts.maximum_qos {
            if v5 {
                refuse(wr, version, 0, 0x9B).await; // QoS not supported
                return None;
            }
            will.qos = opts.maximum_qos;
        }
        if will.retain && !opts.allow_retained_messages {
            if v5 {
                refuse(wr, version, 0, reason::RETAIN_NOT_SUPPORTED).await;
                return None;
            }
            will.retain = false;
        }
    }

    // Keep alive: v5.0 clients can be told a lower value via Server Keep Alive (§3.2.2.3.14).
    let mut keep_alive = connect.keep_alive_sec;
    let mut server_keep_alive = None;
    if v5
        && opts.max_keep_alive_sec > 0
        && (keep_alive == 0 || keep_alive > opts.max_keep_alive_sec)
    {
        keep_alive = opts.max_keep_alive_sec;
        server_keep_alive = Some(keep_alive);
    }

    let requested = connect.properties.session_expiry_interval();
    let expiry = ctx.session_expiry_for(requested, connect.clean_start, v5);
    let expiry_overridden = v5 && requested.unwrap_or(0) != expiry;

    Some(Accepted {
        connect,
        client_id,
        assigned_id,
        user,
        keep_alive,
        server_keep_alive,
        expiry,
        expiry_overridden,
    })
}

/// Per-connection state used while handling client packets.
struct Conn<'a> {
    ctx: &'a BrokerContext,
    session: &'a Arc<Session>,
    version: ProtocolVersion,
    user: Arc<crate::auth::UserAccount>,
    will: Option<PublishPacket>,
    connect_expiry: u32,
    /// Client-to-server topic aliases (MQTT v5.0 §3.3.2.3.4).
    topic_aliases: HashMap<u16, String>,
}

impl Conn<'_> {
    fn v5(&self) -> bool {
        self.version == ProtocolVersion::V500
    }

    fn send(&self, pkt: MqttPacket) -> Option<Exit> {
        if self.session.queue.push_control(pkt) {
            None
        } else {
            warn!(
                "Client '{}' is not reading replies; closing",
                self.session.client_id
            );
            Some(Exit::Server(reason::QUOTA_EXCEEDED))
        }
    }

    /// Handles one packet; returns `Some` when the connection must end.
    fn handle(&mut self, pkt: MqttPacket) -> Option<Exit> {
        match pkt {
            MqttPacket::Publish(p) => self.on_publish(p),
            MqttPacket::PubAck { packet_id, .. } => {
                let mut st = self.session.state();
                if matches!(st.inflight.get(&packet_id), Some(InflightOut::Publish(p)) if p.qos == QoS::AtLeastOnce)
                {
                    st.inflight.remove(&packet_id);
                    drop(st);
                    self.session.queue.wake();
                }
                None
            }
            MqttPacket::PubRec {
                packet_id,
                reason_code,
            } => {
                let mut st = self.session.state();
                let known = matches!(st.inflight.get(&packet_id), Some(InflightOut::Publish(p)) if p.qos == QoS::ExactlyOnce)
                    || matches!(st.inflight.get(&packet_id), Some(InflightOut::PubRel));
                if known && reason_code >= 0x80 {
                    // The receiver refused the message; the QoS 2 flow ends here (§4.3.3).
                    st.inflight.remove(&packet_id);
                    drop(st);
                    self.session.queue.wake();
                    return None;
                }
                if known {
                    st.inflight.insert(packet_id, InflightOut::PubRel);
                }
                drop(st);
                let code = if known || !self.v5() {
                    reason::SUCCESS
                } else {
                    reason::PACKET_IDENTIFIER_NOT_FOUND
                };
                self.send(MqttPacket::PubRel {
                    packet_id,
                    reason_code: code,
                })
            }
            MqttPacket::PubComp { packet_id, .. } => {
                let mut st = self.session.state();
                if matches!(st.inflight.get(&packet_id), Some(InflightOut::PubRel)) {
                    st.inflight.remove(&packet_id);
                    drop(st);
                    self.session.queue.wake();
                }
                None
            }
            MqttPacket::PubRel { packet_id, .. } => {
                let known = self.session.state().inbound_qos2.remove(&packet_id);
                let code = if known || !self.v5() {
                    reason::SUCCESS
                } else {
                    reason::PACKET_IDENTIFIER_NOT_FOUND
                };
                self.send(MqttPacket::PubComp {
                    packet_id,
                    reason_code: code,
                })
            }
            MqttPacket::Subscribe {
                packet_id,
                filters,
                properties,
            } => self.on_subscribe(packet_id, filters, properties),
            MqttPacket::Unsubscribe { packet_id, filters } => {
                let reason_codes = filters
                    .iter()
                    .map(|f| {
                        if self.ctx.unsubscribe(self.session.id, f) {
                            reason::SUCCESS
                        } else {
                            reason::NO_SUBSCRIPTION_EXISTED
                        }
                    })
                    .collect();
                self.send(MqttPacket::UnsubAck {
                    packet_id,
                    reason_codes,
                })
            }
            MqttPacket::PingReq => self.send(MqttPacket::PingResp),
            MqttPacket::Disconnect {
                reason_code,
                properties,
            } => {
                if let Some(new_expiry) = properties.session_expiry_interval() {
                    // §3.14.2.2.2: a session that was not persistent cannot become persistent.
                    if self.connect_expiry == 0 && new_expiry != 0 {
                        return Some(Exit::Server(reason::PROTOCOL_ERROR));
                    }
                    self.session.state().expiry_interval =
                        new_expiry.min(self.ctx.options.max_session_expiry_sec);
                }
                debug!(
                    "Client '{}' sent DISCONNECT (0x{:02X})",
                    self.session.client_id, reason_code
                );
                Some(if reason_code == reason::SUCCESS {
                    Exit::Normal
                } else {
                    Exit::ClientDisconnectWithWill
                })
            }
            MqttPacket::Connect(_) => {
                warn!("Client '{}' sent a second CONNECT", self.session.client_id);
                Some(Exit::Server(reason::PROTOCOL_ERROR))
            }
            // Enhanced authentication was not negotiated, so AUTH is a protocol error (§4.12).
            MqttPacket::Auth { .. }
            | MqttPacket::ConnAck { .. }
            | MqttPacket::SubAck { .. }
            | MqttPacket::UnsubAck { .. }
            | MqttPacket::PingResp => Some(Exit::Server(reason::PROTOCOL_ERROR)),
        }
    }

    fn on_publish(&mut self, mut p: PublishPacket) -> Option<Exit> {
        let ctx = self.ctx;
        let opts = &ctx.options;
        if p.qos > opts.maximum_qos {
            return Some(Exit::Server(0x9B)); // QoS not supported
        }
        if p.retain && !opts.allow_retained_messages {
            if self.v5() {
                return Some(Exit::Server(reason::RETAIN_NOT_SUPPORTED));
            }
            p.retain = false;
        }

        if self.v5() {
            if p.properties.subscription_identifiers().next().is_some() {
                return Some(Exit::Server(reason::PROTOCOL_ERROR));
            }
            if let Some(alias) = p.properties.topic_alias() {
                if alias == 0 || alias > opts.topic_alias_maximum {
                    return Some(Exit::Server(reason::TOPIC_ALIAS_INVALID));
                }
                if p.topic.is_empty() {
                    match self.topic_aliases.get(&alias) {
                        Some(t) => p.topic = t.clone(),
                        None => return Some(Exit::Server(reason::PROTOCOL_ERROR)),
                    }
                } else {
                    self.topic_aliases.insert(alias, p.topic.clone());
                }
                p.properties
                    .retain(|pr| !matches!(pr, Property::TopicAlias(_)));
            }
        }
        if !is_valid_topic_name(&p.topic) {
            return Some(Exit::Server(reason::TOPIC_NAME_INVALID));
        }

        let pid = p.packet_id;
        let ack = |code: u8| -> Option<MqttPacket> {
            match (p.qos, pid) {
                (QoS::AtLeastOnce, Some(packet_id)) => Some(MqttPacket::PubAck {
                    packet_id,
                    reason_code: code,
                }),
                (QoS::ExactlyOnce, Some(packet_id)) => Some(MqttPacket::PubRec {
                    packet_id,
                    reason_code: code,
                }),
                _ => None,
            }
        };

        // Payload Format Indicator 1 requires UTF-8 payload (§3.3.2.3.2).
        let utf8_declared = p
            .properties
            .iter()
            .any(|pr| matches!(pr, Property::PayloadFormatIndicator(1)));
        if utf8_declared && std::str::from_utf8(&p.payload).is_err() {
            return ack(reason::PAYLOAD_FORMAT_INVALID).and_then(|a| self.send(a));
        }

        if !self
            .ctx
            .acl
            .check_publish(&self.user, &self.session.client_id, &p.topic)
        {
            warn!(
                "Publish by '{}' to '{}' denied",
                self.session.client_id, p.topic
            );
            // v3.1.1 has no negative acknowledgement, so the publish is acknowledged and dropped.
            let code = if self.v5() {
                reason::NOT_AUTHORIZED
            } else {
                reason::SUCCESS
            };
            if p.qos == QoS::ExactlyOnce && !self.v5() {
                if let Some(id) = pid {
                    self.session.state().inbound_qos2.insert(id);
                }
            }
            return ack(code).and_then(|a| self.send(a));
        }

        if p.qos == QoS::ExactlyOnce {
            let id = pid.expect("decoder guarantees a packet id for QoS 2");
            let mut st = self.session.state();
            if st.inbound_qos2.contains(&id) {
                // Retransmission of a message already accepted: acknowledge, do not redeliver.
                drop(st);
                return self.send(MqttPacket::pubrec(id));
            }
            if self.v5() && st.inbound_qos2.len() >= opts.receive_maximum as usize {
                return Some(Exit::Server(reason::RECEIVE_MAXIMUM_EXCEEDED));
            }
            st.inbound_qos2.insert(id);
        }

        let mut routed = p.clone();
        routed.packet_id = None;
        routed.dup = false;
        self.ctx.publish(Some(self.session.id), routed);
        ack(reason::SUCCESS).and_then(|a| self.send(a))
    }

    fn on_subscribe(
        &mut self,
        packet_id: u16,
        filters: Vec<(String, crate::protocol::SubscriptionOptions)>,
        properties: Properties,
    ) -> Option<Exit> {
        let v5 = self.v5();
        let ctx = self.ctx;
        let opts = &ctx.options;
        let sub_id = properties.subscription_identifiers().next();
        let mut codes = Vec::with_capacity(filters.len());
        let mut retained_requests = Vec::new();

        for (filter, requested) in filters {
            let fail = |v5code: u8| if v5 { v5code } else { 0x80 };
            let shared = match parse_shared_subscription(&filter) {
                Ok(s) => s,
                Err(_) => {
                    codes.push(fail(reason::TOPIC_FILTER_INVALID));
                    continue;
                }
            };
            let effective_filter = shared.map(|(_, inner)| inner).unwrap_or(&filter);
            if validate_topic_filter(effective_filter).is_err() {
                codes.push(fail(reason::TOPIC_FILTER_INVALID));
                continue;
            }
            if shared.is_some() {
                if !opts.allow_shared_subscriptions {
                    codes.push(fail(reason::SHARED_SUBSCRIPTIONS_NOT_SUPPORTED));
                    continue;
                }
                if requested.no_local {
                    // §3.8.3.1: No Local on a shared subscription is a protocol error.
                    return Some(Exit::Server(reason::PROTOCOL_ERROR));
                }
            }
            if !opts.allow_wildcard_subscriptions && has_wildcards(effective_filter) {
                codes.push(fail(reason::WILDCARD_SUBSCRIPTIONS_NOT_SUPPORTED));
                continue;
            }
            if !self
                .ctx
                .acl
                .check_subscribe(&self.user, &self.session.client_id, effective_filter)
            {
                warn!(
                    "Subscription of '{}' to '{}' denied",
                    self.session.client_id, filter
                );
                codes.push(fail(reason::NOT_AUTHORIZED));
                continue;
            }
            let sub = granted_subscription(self.ctx, requested, sub_id);
            match self.ctx.subscribe(self.session.id, &filter, sub) {
                Ok(is_new) => {
                    codes.push(sub.options.qos as u8);
                    let send_retained = match sub.options.retain_handling {
                        RetainHandling::SendAlways => true,
                        RetainHandling::SendIfNew => is_new,
                        RetainHandling::DoNotSend => false,
                    };
                    if send_retained {
                        retained_requests.push((filter, sub));
                    }
                }
                Err(_) => codes.push(fail(reason::TOPIC_FILTER_INVALID)),
            }
        }

        if let Some(exit) = self.send(MqttPacket::SubAck {
            packet_id,
            reason_codes: codes,
        }) {
            return Some(exit);
        }
        for (filter, sub) in retained_requests {
            self.ctx.deliver_retained(self.session, &filter, &sub);
        }
        None
    }
}

struct WriterParams {
    version: ProtocolVersion,
    client_receive_max: usize,
    client_max_packet: usize,
    resend_inflight: bool,
}

/// Drains the session queue to the socket until stopped, the queue closes or a write fails.
async fn run_writer<W>(
    mut wr: W,
    ctx: BrokerContext,
    session: Arc<Session>,
    connack: Bytes,
    params: WriterParams,
    mut stop: oneshot::Receiver<Option<u8>>,
) where
    W: AsyncWrite + Unpin + Send,
{
    let mut out = BytesMut::with_capacity(16 * 1024);
    out.extend_from_slice(&connack);
    if params.resend_inflight {
        // §4.4: resend unacknowledged PUBLISH (DUP = 1) and PUBREL with their original ids.
        let pending: Vec<(u16, InflightOut)> = session
            .state()
            .inflight
            .iter()
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        for (pid, item) in pending {
            let pkt = match item {
                InflightOut::Publish(mut p) => {
                    p.dup = true;
                    MqttPacket::Publish(p)
                }
                InflightOut::PubRel => MqttPacket::pubrel(pid),
            };
            let _ = pkt.encode(params.version, &mut out);
        }
    }
    if wr.write_all(&out).await.is_err() || wr.flush().await.is_err() {
        return;
    }

    let recv_max = params.client_receive_max.max(1);
    let can_publish = || session.state().inflight_count() < recv_max;
    loop {
        let item = tokio::select! {
            biased;
            r = &mut stop => {
                if let Ok(Some(code)) = r {
                    let _ = write_direct(&mut wr, &MqttPacket::disconnect(code), params.version).await;
                }
                break;
            }
            item = session.queue.pop(can_publish) => match item {
                Some(item) => item,
                None => break,
            },
        };
        out.clear();
        encode_outbound(&ctx, &session, &params, item, &mut out);
        while out.len() < WRITE_BATCH_BYTES {
            match session.queue.try_pop(can_publish()) {
                Some(item) => encode_outbound(&ctx, &session, &params, item, &mut out),
                None => break,
            }
        }
        if out.is_empty() {
            continue;
        }
        if wr.write_all(&out).await.is_err() || wr.flush().await.is_err() {
            break;
        }
    }
    let _ = wr.shutdown().await;
}

/// Encodes one queued item into `out`, assigning packet ids and enforcing message expiry and the
/// client's Maximum Packet Size.
fn encode_outbound(
    ctx: &BrokerContext,
    session: &Session,
    params: &WriterParams,
    item: Outbound,
    out: &mut BytesMut,
) {
    let delivery = match item {
        Outbound::Control(pkt) => {
            let _ = pkt.encode(params.version, out);
            return;
        }
        Outbound::Publish(d) => d,
    };
    let now = std::time::Instant::now();
    if delivery.is_expired(now)
        || (delivery.expires_at.is_none()
            && ctx
                .options
                .default_message_expiry
                .is_some_and(|max_wait| delivery.enqueued_at + max_wait <= now))
    {
        ctx.metrics.messages_dropped.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let mut p = delivery.publish;
    if let Some(at) = delivery.expires_at {
        // §3.3.2.3.3: forward the remaining lifetime of the message.
        let remaining = at.saturating_duration_since(now).as_secs_f64().ceil() as u32;
        p.properties
            .retain(|pr| !matches!(pr, Property::MessageExpiryInterval(_)));
        p.properties
            .push(Property::MessageExpiryInterval(remaining.max(1)));
    }
    if p.qos != QoS::AtMostOnce {
        match session.state().track_outbound(p) {
            Some(tracked) => p = tracked,
            None => return,
        }
    }
    let (packet_id, payload_len) = (p.packet_id, p.payload.len());
    let start = out.len();
    if MqttPacket::Publish(p).encode(params.version, out).is_err()
        || out.len() - start > params.client_max_packet
    {
        // §3.1.2.11.4: a packet larger than the client's maximum is discarded.
        out.truncate(start);
        if let Some(pid) = packet_id {
            session.state().inflight.remove(&pid);
        }
        ctx.metrics.messages_dropped.fetch_add(1, Ordering::Relaxed);
        return;
    }
    ctx.metrics.messages_sent.fetch_add(1, Ordering::Relaxed);
    ctx.metrics
        .bytes_sent
        .fetch_add(payload_len as u64, Ordering::Relaxed);
}
