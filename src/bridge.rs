//! MQTT bridges: outbound connections from this broker to other MQTT brokers
//! (`[bridges.<name>]`), for edge-to-cloud forwarding.
//!
//! A bridge is an internal broker session plus an MQTT client towards the remote broker:
//!
//! * **out** topics: the session subscribes locally (with No Local, so messages the bridge itself
//!   brought in are not sent back). Its queue buffers messages while the remote broker is
//!   unreachable; a message leaves the queue only when the remote broker acknowledges it.
//! * **in** topics: the bridge subscribes at the remote broker and publishes what it receives
//!   locally, on behalf of its session and under its own ACL identity.
//!
//! Loops are prevented by No Local on both sides (MQTT v5.0), by a hop count carried in the
//! user property `wolfimq-bridge-hops`, and, for MQTT v3.1.1 remotes, by refusing overlapping
//! in / out topics in the configuration. TLS uses wolfSSL; the server certificate and host
//! name are always verified.

use crate::auth::UserAccount;
use crate::broker::{BrokerContext, OpenedSession};
use crate::client::ClientStream;
use crate::config::{split_host_port, BridgeConfig, BridgeDirection, QueueFullPolicy};
use crate::crypto::Rng;
use crate::protocol::{
    reason, ConnectPacket, MqttPacket, Properties, Property, ProtocolVersion, PublishPacket, QoS,
    RetainHandling, SubscriptionOptions,
};
use crate::queue::{Delivery, Outbound, QueueLimits};
use crate::routing::{topic_matches_filter, Subscription};
use crate::session::{Session, Transport};
use crate::tls::{create_tls_client, TlsClientConfig, TlsVersion, WolfTlsConnector};
use bytes::{Bytes, BytesMut};
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

/// User property counting the bridges a message has crossed.
pub const HOPS_PROPERTY: &str = "wolfimq-bridge-hops";
/// Time allowed for TCP connect and for the CONNACK.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// A topic rule with its full local and remote filters.
#[derive(Debug, Clone)]
struct Rule {
    direction: BridgeDirection,
    qos: QoS,
    retain: bool,
    local_prefix: String,
    remote_prefix: String,
    local_filter: String,
    remote_filter: String,
}

impl Rule {
    fn outgoing(&self) -> bool {
        matches!(self.direction, BridgeDirection::Out | BridgeDirection::Both)
    }

    fn incoming(&self) -> bool {
        matches!(self.direction, BridgeDirection::In | BridgeDirection::Both)
    }
}

fn rules(cfg: &BridgeConfig) -> Vec<Rule> {
    cfg.topics
        .iter()
        .map(|t| Rule {
            direction: t.direction,
            qos: QoS::try_from(t.qos.min(2)).unwrap_or(QoS::AtLeastOnce),
            retain: t.retain,
            local_prefix: t.local_prefix.clone(),
            remote_prefix: t.remote_prefix.clone(),
            local_filter: format!("{}{}", t.local_prefix, t.pattern),
            remote_filter: format!("{}{}", t.remote_prefix, t.pattern),
        })
        .collect()
}

/// Local topic -> (rule, remote topic), by the first matching outgoing rule.
fn map_out<'a>(rules: &'a [Rule], topic: &str) -> Option<(&'a Rule, String)> {
    rules
        .iter()
        .filter(|r| r.outgoing())
        .find(|r| {
            topic.starts_with(&r.local_prefix) && topic_matches_filter(&r.local_filter, topic)
        })
        .map(|r| {
            (
                r,
                format!("{}{}", r.remote_prefix, &topic[r.local_prefix.len()..]),
            )
        })
}

/// Remote topic -> (rule, local topic), by the first matching incoming rule.
fn map_in<'a>(rules: &'a [Rule], topic: &str) -> Option<(&'a Rule, String)> {
    rules
        .iter()
        .filter(|r| r.incoming())
        .find(|r| {
            topic.starts_with(&r.remote_prefix) && topic_matches_filter(&r.remote_filter, topic)
        })
        .map(|r| {
            (
                r,
                format!("{}{}", r.local_prefix, &topic[r.remote_prefix.len()..]),
            )
        })
}

fn hops(props: &Properties) -> u8 {
    props
        .iter()
        .find_map(|p| match p {
            Property::UserProperty(k, v) if k == HOPS_PROPERTY => v.parse().ok(),
            _ => None,
        })
        .unwrap_or(0)
}

/// Properties for a forwarded message: transport-level ones removed, hop count updated.
fn forwarded_properties(props: &Properties, hop: u8) -> Properties {
    let mut out = props.clone();
    out.retain(|p| {
        !matches!(
            p,
            Property::TopicAlias(_)
                | Property::SubscriptionIdentifier(_)
                | Property::MessageExpiryInterval(_)
        ) && !matches!(p, Property::UserProperty(k, _) if k == HOPS_PROPERTY)
    });
    out.push(Property::UserProperty(
        HOPS_PROPERTY.into(),
        hop.to_string(),
    ));
    out
}

/// Exponential backoff with full jitter.
struct Backoff {
    min: Duration,
    max: Duration,
    ceiling: Duration,
    rng: Rng,
}

impl Backoff {
    fn new(min: Duration, max: Duration) -> Self {
        Self {
            min,
            max,
            ceiling: min,
            rng: Rng::new(),
        }
    }

    fn reset(&mut self) {
        self.ceiling = self.min;
    }

    /// A random delay between `min` and the current ceiling; the ceiling then doubles.
    fn next_delay(&mut self) -> Duration {
        let mut b = [0u8; 4];
        self.rng.fill(&mut b);
        let span = self.ceiling.saturating_sub(self.min).as_millis() as u64;
        let jitter = if span == 0 {
            0
        } else {
            u64::from(u32::from_le_bytes(b)) % (span + 1)
        };
        self.ceiling = (self.ceiling * 2).min(self.max);
        self.min + Duration::from_millis(jitter)
    }
}

/// What the remote broker announced in CONNACK.
#[derive(Debug, Clone, Copy)]
struct RemoteLimits {
    maximum_qos: QoS,
    retain_available: bool,
    maximum_packet_size: usize,
    receive_maximum: usize,
    keep_alive: u16,
}

/// Outbound QoS 1/2 message waiting for the remote broker.
#[derive(Debug, Clone)]
struct OutEntry {
    seq: u64,
    /// The local delivery, put back into the queue if the remote session is lost.
    delivery: Delivery,
    /// The packet as sent to the remote broker (resent with DUP).
    publish: PublishPacket,
    /// PUBREC received: waiting for PUBCOMP.
    released: bool,
}

/// QoS state towards the remote broker; survives reconnects of a persistent remote session.
#[derive(Debug, Default)]
struct RemoteState {
    out: BTreeMap<u16, OutEntry>,
    next_pid: u16,
    next_seq: u64,
    /// Inbound QoS 2 packet ids awaiting PUBREL.
    inbound_qos2: HashSet<u16>,
}

impl RemoteState {
    fn allocate(&mut self) -> Option<u16> {
        for _ in 0..u16::MAX {
            self.next_pid = self.next_pid.checked_add(1).unwrap_or(1);
            if !self.out.contains_key(&self.next_pid) {
                return Some(self.next_pid);
            }
        }
        None
    }

    fn in_send_order(&self) -> Vec<(u16, OutEntry)> {
        let mut v: Vec<(u16, OutEntry)> = self.out.iter().map(|(k, e)| (*k, e.clone())).collect();
        v.sort_by_key(|(_, e)| e.seq);
        v
    }
}

enum End {
    /// The broker is shutting down or the bridge session ended.
    Stop,
    /// The remote connection was lost; reconnect.
    Lost(String),
}

type Writer = WriteHalf<ClientStream>;

struct Bridge {
    name: String,
    cfg: BridgeConfig,
    rules: Vec<Rule>,
    ctx: BrokerContext,
    user: Arc<UserAccount>,
    local_client_id: String,
    connector: Option<WolfTlsConnector>,
    password: Option<Bytes>,
    version: ProtocolVersion,
}

/// Validates the runtime prerequisites of a bridge (ACL identity and permissions, TLS files,
/// password file) and starts it. Errors are configuration errors.
pub async fn start(
    name: &str,
    cfg: BridgeConfig,
    ctx: BrokerContext,
) -> Result<JoinHandle<()>, String> {
    let bridge = prepare(name, cfg, ctx).await?;
    let local = &bridge.cfg;
    let limits = QueueLimits {
        max_messages: local.max_queued_messages,
        max_bytes: local.max_queued_bytes,
        policy: if local.queue_full_policy == "drop_newest" {
            QueueFullPolicy::DropNewest
        } else {
            QueueFullPolicy::DropOldest
        },
        max_control: bridge.ctx.options.queue_limits.max_control,
    };
    let opened = bridge
        .ctx
        .open_session_with_limits(
            &bridge.local_client_id,
            Arc::clone(&bridge.user),
            true,
            0,
            Transport::Bridge,
            limits,
        )
        .await
        .map_err(|e| format!("bridge '{name}': cannot open its local session: {e:?}"))?;
    for rule in bridge.rules.iter().filter(|r| r.outgoing()) {
        let options = SubscriptionOptions {
            qos: rule.qos,
            // Messages the bridge brought in are not sent back out.
            no_local: true,
            retain_as_published: true,
            retain_handling: RetainHandling::SendAlways,
        };
        bridge
            .ctx
            .subscribe(
                &opened.session,
                &rule.local_filter,
                Subscription::new(options),
            )
            .map_err(|e| format!("bridge '{name}': local subscription failed: {e:?}"))?;
    }
    Ok(tokio::spawn(bridge.run(opened)))
}

/// Checks a bridge without starting it (used by `--check-config`).
pub async fn check(name: &str, cfg: BridgeConfig, ctx: BrokerContext) -> Result<(), String> {
    prepare(name, cfg, ctx).await.map(|_| ())
}

async fn prepare(name: &str, cfg: BridgeConfig, ctx: BrokerContext) -> Result<Bridge, String> {
    let err = |m: String| format!("bridge '{name}': {m}");
    let user = ctx.acl.get_user(&cfg.acl_user).await.ok_or_else(|| {
        err(format!(
            "acl_user '{}' is not defined in the ACL file",
            cfg.acl_user
        ))
    })?;
    let local_client_id = format!("$bridge/{name}");
    let rules = rules(&cfg);
    for r in rules.iter().filter(|r| r.outgoing()) {
        if !ctx.may_subscribe(&user, &local_client_id, &r.local_filter) {
            return Err(err(format!(
                "acl_user '{}' may not read '{}'",
                cfg.acl_user, r.local_filter
            )));
        }
    }
    let connector = if cfg.tls.enabled {
        let t = &cfg.tls;
        let client = TlsClientConfig {
            ca_file: t.ca_file.clone(),
            client_cert: (!t.cert_file.is_empty())
                .then(|| (t.cert_file.clone(), t.key_file.clone())),
            min_version: if t.min_tls_version == "TLSv1.3" {
                TlsVersion::Tls13
            } else {
                TlsVersion::Tls12
            },
            alpn_protocols: t.alpn_protocols.clone(),
        };
        Some(create_tls_client(&client).map_err(|e| err(format!("TLS setup failed: {e}")))?)
    } else {
        None
    };
    let password = if !cfg.password_file.is_empty() {
        let raw = std::fs::read_to_string(&cfg.password_file)
            .map_err(|e| err(format!("cannot read password_file: {e}")))?;
        warn_if_world_readable(name, &cfg.password_file);
        Some(Bytes::from(raw.trim_end_matches(['\r', '\n']).to_owned()))
    } else if !cfg.password.is_empty() {
        Some(Bytes::from(cfg.password.clone()))
    } else {
        None
    };
    let version = if cfg.protocol_version == 4 {
        ProtocolVersion::V311
    } else {
        ProtocolVersion::V500
    };
    Ok(Bridge {
        name: name.to_owned(),
        rules,
        ctx,
        user,
        local_client_id,
        connector,
        password,
        version,
        cfg,
    })
}

#[cfg(unix)]
fn warn_if_world_readable(name: &str, path: &str) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        if meta.permissions().mode() & 0o004 != 0 {
            warn!("bridge '{name}': password_file {path} is readable by every user");
        }
    }
}

#[cfg(not(unix))]
fn warn_if_world_readable(_name: &str, _path: &str) {}

async fn write_packet(
    wr: &mut Writer,
    pkt: &MqttPacket,
    version: ProtocolVersion,
) -> std::io::Result<()> {
    let bytes = pkt
        .to_bytes(version)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    wr.write_all(&bytes).await?;
    wr.flush().await
}

impl Bridge {
    fn remote_client_id(&self) -> String {
        if self.cfg.client_id.is_empty() {
            format!("wolfimq-bridge-{}", self.name)
        } else {
            self.cfg.client_id.clone()
        }
    }

    fn persistent_remote(&self) -> bool {
        !self.cfg.clean_start
            && (self.version == ProtocolVersion::V311 || self.cfg.session_expiry_sec > 0)
    }

    fn publish_state(&self, connected: bool) {
        let msg = PublishPacket::new(
            format!("$SYS/broker/bridges/{}/state", self.name),
            Bytes::from_static(if connected { b"1" } else { b"0" }),
        )
        .with_retain(true);
        self.ctx.publish(None, msg);
    }

    async fn run(self, opened: OpenedSession) {
        let OpenedSession {
            session,
            epoch,
            release,
            ..
        } = opened;
        let mut shutdown = self.ctx.shutdown_signal();
        let mut state = RemoteState::default();
        let mut backoff = Backoff::new(
            Duration::from_secs(self.cfg.reconnect_min_sec),
            Duration::from_secs(self.cfg.reconnect_max_sec),
        );
        let mut address = 0usize;
        self.publish_state(false);
        info!(
            "Bridge '{}' started ({} topic rules, remote {:?})",
            self.name,
            self.rules.len(),
            self.cfg.addresses
        );
        loop {
            if *shutdown.borrow() || session.queue.is_closed() {
                break;
            }
            let target = self.cfg.addresses[address % self.cfg.addresses.len()].clone();
            let attempt = tokio::select! {
                r = self.connect(&target) => r,
                _ = shutdown.changed() => break,
            };
            match attempt {
                Ok((stream, buf, limits, session_present)) => {
                    info!(
                        "Bridge '{}' connected to {} (session present: {})",
                        self.name, target, session_present
                    );
                    let started = Instant::now();
                    let end = self
                        .connected(
                            stream,
                            buf,
                            limits,
                            session_present,
                            &session,
                            &mut state,
                            &mut shutdown,
                        )
                        .await;
                    self.publish_state(false);
                    if started.elapsed() >= Duration::from_secs(self.cfg.reconnect_stable_sec) {
                        backoff.reset();
                    }
                    match end {
                        End::Stop => break,
                        End::Lost(why) => warn!(
                            "Bridge '{}': connection to {} lost: {}",
                            self.name, target, why
                        ),
                    }
                }
                Err(e) => {
                    warn!(
                        "Bridge '{}': cannot connect to {}: {}",
                        self.name, target, e
                    );
                    address += 1;
                }
            }
            let delay = backoff.next_delay();
            debug!("Bridge '{}' reconnects in {:?}", self.name, delay);
            tokio::select! {
                _ = tokio::time::sleep(delay) => {}
                _ = shutdown.changed() => break,
            }
        }
        info!("Bridge '{}' stopped", self.name);
        self.ctx.connection_closed(&session, epoch, None);
        drop(release);
    }

    /// Opens the transport and performs CONNECT / CONNACK.
    async fn connect(
        &self,
        address: &str,
    ) -> Result<(ClientStream, BytesMut, RemoteLimits, bool), String> {
        let (host, port) = split_host_port(address).ok_or("invalid address")?;
        let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((host.as_str(), port)))
            .await
            .map_err(|_| "TCP connect timed out".to_string())?
            .map_err(|e| e.to_string())?;
        let _ = tcp.set_nodelay(true);
        let mut stream = match &self.connector {
            Some(connector) => {
                let name = if self.cfg.tls.server_name.is_empty() {
                    host.clone()
                } else {
                    self.cfg.tls.server_name.clone()
                };
                let timeout = Duration::from_secs(self.cfg.tls.handshake_timeout_sec.max(1));
                let tls = tokio::time::timeout(timeout, connector.connect(&name, tcp))
                    .await
                    .map_err(|_| "TLS handshake timed out".to_string())?
                    .map_err(|e| format!("TLS handshake failed: {e}"))?;
                ClientStream::Tls(Box::new(tls))
            }
            None => ClientStream::Tcp(tcp),
        };

        let mut connect = ConnectPacket::new(self.remote_client_id())
            .with_version(self.version)
            .with_keep_alive(self.cfg.keep_alive_sec);
        connect.clean_start = self.cfg.clean_start;
        if !self.cfg.username.is_empty() {
            connect.username = Some(self.cfg.username.clone());
            connect.password = self.password.clone();
        }
        if self.version == ProtocolVersion::V500 && self.cfg.session_expiry_sec > 0 {
            connect.properties = Properties(vec![Property::SessionExpiryInterval(
                self.cfg.session_expiry_sec,
            )]);
        }
        if !self.cfg.notification_topic.is_empty() {
            connect.will = Some(
                PublishPacket::new(
                    self.cfg.notification_topic.clone(),
                    Bytes::from_static(b"0"),
                )
                .with_qos(QoS::AtLeastOnce, None)
                .with_retain(true),
            );
        }
        let bytes = MqttPacket::Connect(connect)
            .to_bytes(self.version)
            .map_err(|e| e.to_string())?;
        stream.write_all(&bytes).await.map_err(|e| e.to_string())?;

        let mut buf = BytesMut::with_capacity(4096);
        let connack = tokio::time::timeout(CONNECT_TIMEOUT, async {
            loop {
                if let Some(p) = MqttPacket::decode_from(&mut buf, self.version, usize::MAX)
                    .map_err(|e| e.to_string())?
                {
                    return Ok::<MqttPacket, String>(p);
                }
                if stream.read_buf(&mut buf).await.map_err(|e| e.to_string())? == 0 {
                    return Err("connection closed before CONNACK".into());
                }
            }
        })
        .await
        .map_err(|_| "no CONNACK in time".to_string())??;
        let MqttPacket::ConnAck {
            session_present,
            reason_code,
            properties,
        } = connack
        else {
            return Err(format!("expected CONNACK, got {connack:?}"));
        };
        if reason_code != 0 {
            return Err(format!("refused with CONNACK code 0x{reason_code:02X}"));
        }
        let mut limits = RemoteLimits {
            maximum_qos: QoS::ExactlyOnce,
            retain_available: true,
            maximum_packet_size: properties
                .maximum_packet_size()
                .map_or(usize::MAX, |m| m as usize),
            receive_maximum: properties.receive_maximum().unwrap_or(u16::MAX) as usize,
            keep_alive: self.cfg.keep_alive_sec,
        };
        for p in properties.iter() {
            match p {
                Property::MaximumQoS(q) => {
                    limits.maximum_qos = QoS::try_from(*q).unwrap_or(QoS::AtMostOnce)
                }
                Property::RetainAvailable(r) => limits.retain_available = *r == 1,
                Property::ServerKeepAlive(k) => limits.keep_alive = *k,
                _ => {}
            }
        }
        Ok((stream, buf, limits, session_present))
    }

    #[allow(clippy::too_many_arguments)]
    async fn connected(
        &self,
        stream: ClientStream,
        mut buf: BytesMut,
        limits: RemoteLimits,
        session_present: bool,
        session: &Arc<Session>,
        state: &mut RemoteState,
        shutdown: &mut watch::Receiver<bool>,
    ) -> End {
        let (mut rd, mut wr) = tokio::io::split(stream);
        let v = self.version;
        let lost = |e: std::io::Error| End::Lost(e.to_string());

        // 1. Unacknowledged messages: resent as they were if the remote session survived
        //    (MQTT-4.4.0-1), otherwise back to the front of the local queue.
        if session_present && self.persistent_remote() {
            for (pid, entry) in state.in_send_order() {
                let pkt = if entry.released {
                    MqttPacket::pubrel(pid)
                } else {
                    let mut p = entry.publish.clone();
                    p.dup = true;
                    MqttPacket::Publish(p)
                };
                if let Err(e) = write_packet(&mut wr, &pkt, v).await {
                    return lost(e);
                }
            }
        } else {
            for (_, entry) in state.in_send_order().into_iter().rev() {
                session.queue.push_front_publish(entry.delivery);
            }
            state.out.clear();
            state.inbound_qos2.clear();
        }

        // 2. Remote subscriptions for incoming topics (repeated after every connect).
        let filters: Vec<(String, SubscriptionOptions)> = self
            .rules
            .iter()
            .filter(|r| r.incoming())
            .map(|r| {
                let mut o = SubscriptionOptions::new(r.qos);
                o.no_local = v == ProtocolVersion::V500;
                o.retain_as_published = r.retain;
                (r.remote_filter.clone(), o)
            })
            .collect();
        if !filters.is_empty() {
            let pid = state.allocate().unwrap_or(1);
            if let Err(e) = write_packet(&mut wr, &MqttPacket::subscribe(pid, filters), v).await {
                return lost(e);
            }
        }

        // 3. Connection state.
        if !self.cfg.notification_topic.is_empty() {
            let online = PublishPacket::new(
                self.cfg.notification_topic.clone(),
                Bytes::from_static(b"1"),
            )
            .with_retain(true);
            if let Err(e) = write_packet(&mut wr, &MqttPacket::Publish(online), v).await {
                return lost(e);
            }
        }
        self.publish_state(true);

        // 4. Traffic.
        let window = (self.cfg.max_inflight as usize)
            .min(limits.receive_maximum)
            .max(1);
        let ka = Duration::from_secs(u64::from(limits.keep_alive.max(1)));
        let mut keep_alive = tokio::time::interval_at(tokio::time::Instant::now() + ka, ka);
        let mut ping_pending = false;
        loop {
            let allow = state.out.len() < window;
            tokio::select! {
                biased;
                _ = shutdown.changed() => {
                    if !self.cfg.notification_topic.is_empty() {
                        let offline = PublishPacket::new(
                            self.cfg.notification_topic.clone(),
                            Bytes::from_static(b"0"),
                        )
                        .with_retain(true);
                        let _ = write_packet(&mut wr, &MqttPacket::Publish(offline), v).await;
                    }
                    let _ = write_packet(&mut wr, &MqttPacket::disconnect(reason::SUCCESS), v).await;
                    let _ = wr.shutdown().await;
                    return End::Stop;
                }
                r = rd.read_buf(&mut buf) => {
                    match r {
                        Ok(0) => return End::Lost("closed by the remote broker".into()),
                        Err(e) => return lost(e),
                        Ok(_) => {}
                    }
                    loop {
                        let pkt = match MqttPacket::decode_from(&mut buf, v, usize::MAX) {
                            Ok(Some(p)) => p,
                            Ok(None) => break,
                            Err(e) => return End::Lost(format!("invalid packet: {e}")),
                        };
                        ping_pending = false;
                        if let Some(end) = self.incoming(pkt, &mut wr, state, session).await {
                            return end;
                        }
                    }
                }
                item = session.queue.pop(move || allow) => match item {
                    Some(Outbound::Publish(d)) => {
                        if let Err(e) = self.outgoing(d, &limits, &mut wr, state).await {
                            return lost(e);
                        }
                    }
                    Some(Outbound::Control(_)) => {}
                    None => return End::Stop,
                },
                _ = keep_alive.tick() => {
                    if limits.keep_alive == 0 {
                        continue;
                    }
                    if ping_pending {
                        return End::Lost("no PINGRESP within the keep alive".into());
                    }
                    if let Err(e) = write_packet(&mut wr, &MqttPacket::PingReq, v).await {
                        return lost(e);
                    }
                    ping_pending = true;
                }
            }
        }
    }

    /// Handles a packet from the remote broker.
    async fn incoming(
        &self,
        pkt: MqttPacket,
        wr: &mut Writer,
        state: &mut RemoteState,
        session: &Arc<Session>,
    ) -> Option<End> {
        let v = self.version;
        let reply = match pkt {
            MqttPacket::Publish(p) => {
                let pid = p.packet_id;
                let duplicate = match (p.qos, pid) {
                    (QoS::ExactlyOnce, Some(id)) => !state.inbound_qos2.insert(id),
                    _ => false,
                };
                if !duplicate {
                    self.deliver_locally(p.clone(), session);
                }
                match (p.qos, pid) {
                    (QoS::AtLeastOnce, Some(id)) => Some(MqttPacket::puback(id)),
                    (QoS::ExactlyOnce, Some(id)) => Some(MqttPacket::pubrec(id)),
                    _ => None,
                }
            }
            MqttPacket::PubAck {
                packet_id,
                reason_code,
            } => {
                if let Some(e) = state.out.remove(&packet_id) {
                    if reason_code >= 0x80 {
                        warn!(
                            "Bridge '{}': remote broker refused '{}' (0x{:02X})",
                            self.name, e.publish.topic, reason_code
                        );
                    }
                }
                session.queue.wake();
                None
            }
            MqttPacket::PubRec {
                packet_id,
                reason_code,
            } => {
                if reason_code >= 0x80 {
                    state.out.remove(&packet_id);
                    session.queue.wake();
                    None
                } else {
                    if let Some(e) = state.out.get_mut(&packet_id) {
                        e.released = true;
                    }
                    Some(MqttPacket::pubrel(packet_id))
                }
            }
            MqttPacket::PubComp { packet_id, .. } => {
                state.out.remove(&packet_id);
                session.queue.wake();
                None
            }
            MqttPacket::PubRel { packet_id, .. } => {
                state.inbound_qos2.remove(&packet_id);
                Some(MqttPacket::pubcomp(packet_id))
            }
            MqttPacket::SubAck { reason_codes, .. } => {
                if reason_codes.iter().any(|c| *c >= 0x80) {
                    warn!(
                        "Bridge '{}': the remote broker refused some subscriptions: {:02X?}",
                        self.name, reason_codes
                    );
                }
                None
            }
            MqttPacket::Disconnect {
                reason_code,
                properties,
            } => {
                return Some(End::Lost(format!(
                    "DISCONNECT 0x{reason_code:02X} {}",
                    properties.reason_string().unwrap_or_default()
                )));
            }
            _ => None,
        };
        if let Some(r) = reply {
            if let Err(e) = write_packet(wr, &r, v).await {
                return Some(End::Lost(e.to_string()));
            }
        }
        None
    }

    /// Publishes a message received from the remote broker locally.
    fn deliver_locally(&self, p: PublishPacket, session: &Arc<Session>) {
        let Some((rule, local_topic)) = map_in(&self.rules, &p.topic) else {
            debug!("Bridge '{}': no incoming rule for '{}'", self.name, p.topic);
            return;
        };
        let hop = hops(&p.properties).saturating_add(1);
        if self.version == ProtocolVersion::V500 && hop > self.cfg.max_hops {
            debug!(
                "Bridge '{}': '{}' crossed {} bridges already; dropped",
                self.name,
                p.topic,
                hop - 1
            );
            self.ctx
                .metrics
                .messages_dropped
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return;
        }
        if !self
            .ctx
            .may_publish(&self.user, &self.local_client_id, &local_topic)
        {
            warn!(
                "Bridge '{}': acl_user may not publish '{}'; message dropped",
                self.name, local_topic
            );
            return;
        }
        let mut msg = PublishPacket::new(local_topic, p.payload)
            .with_qos(p.qos.min(rule.qos), None)
            .with_retain(p.retain && rule.retain);
        if self.version == ProtocolVersion::V500 {
            msg.properties = forwarded_properties(&p.properties, hop);
            if let Some(mei) = p.properties.message_expiry_interval() {
                msg.properties.push(Property::MessageExpiryInterval(mei));
            }
        }
        // On behalf of the bridge session: its No Local subscriptions do not send it back.
        self.ctx.publish(Some(session.id), msg);
    }

    /// Sends a local message to the remote broker.
    async fn outgoing(
        &self,
        d: Delivery,
        limits: &RemoteLimits,
        wr: &mut Writer,
        state: &mut RemoteState,
    ) -> std::io::Result<()> {
        let now = tokio::time::Instant::now().into_std();
        if d.is_expired(now) {
            return Ok(());
        }
        let Some((rule, remote_topic)) = map_out(&self.rules, &d.publish.topic) else {
            return Ok(());
        };
        let hop = hops(&d.publish.properties).saturating_add(1);
        if self.version == ProtocolVersion::V500 && hop > self.cfg.max_hops {
            debug!(
                "Bridge '{}': '{}' crossed {} bridges already; not forwarded",
                self.name,
                d.publish.topic,
                hop - 1
            );
            return Ok(());
        }
        let qos = d.publish.qos.min(limits.maximum_qos);
        let mut p = PublishPacket::new(remote_topic, d.publish.payload.clone())
            .with_qos(qos, None)
            .with_retain(d.publish.retain && rule.retain && limits.retain_available);
        if self.version == ProtocolVersion::V500 {
            p.properties = forwarded_properties(&d.publish.properties, hop);
            if let Some(at) = d.expires_at {
                let remaining = at.saturating_duration_since(now).as_secs_f64().ceil() as u32;
                p.properties
                    .push(Property::MessageExpiryInterval(remaining.max(1)));
            }
        }
        let pid = if qos == QoS::AtMostOnce {
            None
        } else {
            // Every packet id in flight cannot happen with the window, but never reuse one.
            let Some(pid) = state.allocate() else {
                return Ok(());
            };
            Some(pid)
        };
        p.packet_id = pid;
        let bytes = match MqttPacket::Publish(p.clone()).to_bytes(self.version) {
            Ok(b) if b.len() <= limits.maximum_packet_size => b,
            _ => {
                warn!(
                    "Bridge '{}': message too large for the remote broker; dropped",
                    self.name
                );
                return Ok(());
            }
        };
        if let Some(pid) = pid {
            state.next_seq += 1;
            state.out.insert(
                pid,
                OutEntry {
                    seq: state.next_seq,
                    delivery: d,
                    publish: p,
                    released: false,
                },
            );
        }
        write_all(wr, &bytes).await
    }
}

async fn write_all<W: AsyncWrite + Unpin>(wr: &mut W, bytes: &[u8]) -> std::io::Result<()> {
    wr.write_all(bytes).await?;
    wr.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BridgeTopicConfig;

    fn cfg(topics: Vec<BridgeTopicConfig>) -> BridgeConfig {
        BridgeConfig {
            addresses: vec!["cloud:8883".into()],
            acl_user: "bridge".into(),
            topics,
            ..Default::default()
        }
    }

    fn topic(
        pattern: &str,
        direction: BridgeDirection,
        local: &str,
        remote: &str,
    ) -> BridgeTopicConfig {
        BridgeTopicConfig {
            pattern: pattern.into(),
            direction,
            qos: 1,
            local_prefix: local.into(),
            remote_prefix: remote.into(),
            retain: true,
        }
    }

    #[test]
    fn topics_are_mapped_with_prefixes() {
        let r = rules(&cfg(vec![
            topic("telemetry/#", BridgeDirection::Out, "site/", "edge-07/"),
            topic("commands/#", BridgeDirection::In, "site/", "edge-07/"),
        ]));
        assert_eq!(
            map_out(&r, "site/telemetry/temp").map(|(_, t)| t),
            Some("edge-07/telemetry/temp".into())
        );
        assert!(map_out(&r, "site/commands/x").is_none(), "in-only rule");
        assert!(map_out(&r, "other/telemetry/x").is_none());
        assert_eq!(
            map_in(&r, "edge-07/commands/reboot").map(|(_, t)| t),
            Some("site/commands/reboot".into())
        );
        assert!(map_in(&r, "edge-07/telemetry/x").is_none(), "out-only rule");
    }

    #[test]
    fn hop_count_is_replaced_not_appended() {
        let props = Properties(vec![
            Property::UserProperty(HOPS_PROPERTY.into(), "1".into()),
            Property::UserProperty("app".into(), "x".into()),
            Property::SubscriptionIdentifier(4),
        ]);
        assert_eq!(hops(&props), 1);
        let out = forwarded_properties(&props, 2);
        assert_eq!(hops(&out), 2);
        assert_eq!(
            out.iter()
                .filter(|p| matches!(p, Property::UserProperty(k, _) if k == HOPS_PROPERTY))
                .count(),
            1
        );
        assert!(out
            .iter()
            .any(|p| matches!(p, Property::UserProperty(k, _) if k == "app")));
        assert!(!out
            .iter()
            .any(|p| matches!(p, Property::SubscriptionIdentifier(_))));
        assert_eq!(hops(&Properties::new()), 0);
    }

    #[test]
    fn backoff_grows_with_jitter_and_resets() {
        let mut b = Backoff::new(Duration::from_millis(100), Duration::from_millis(800));
        for _ in 0..20 {
            let d = b.next_delay();
            assert!(d >= Duration::from_millis(100) && d <= Duration::from_millis(800));
        }
        assert_eq!(b.ceiling, Duration::from_millis(800));
        b.reset();
        assert_eq!(b.next_delay(), Duration::from_millis(100));
    }

    #[test]
    fn configuration_is_validated() {
        let ok = cfg(vec![topic("a/#", BridgeDirection::Both, "", "")]);
        assert!(ok.validate("cloud").is_ok());
        let mut v3_both = ok.clone();
        v3_both.protocol_version = 4;
        assert!(v3_both.validate("cloud").unwrap_err().contains("both"));
        // MQTT v3.1.1: out and in topics overlapping at the remote broker would loop.
        let mut v3_overlap = cfg(vec![
            topic("x/#", BridgeDirection::Out, "", "edge/"),
            topic("+/y", BridgeDirection::In, "", "edge/"),
        ]);
        v3_overlap.protocol_version = 4;
        assert!(v3_overlap.validate("c").unwrap_err().contains("overlap"));
        let mut v3_disjoint = cfg(vec![
            topic("up/#", BridgeDirection::Out, "", "edge/"),
            topic("down/#", BridgeDirection::In, "", "edge/"),
        ]);
        v3_disjoint.protocol_version = 4;
        assert!(v3_disjoint.validate("c").is_ok());
        let wildcard_prefix = cfg(vec![topic("a", BridgeDirection::Out, "+/", "")]);
        assert!(wildcard_prefix.validate("c").is_err());
        let mut no_acl = ok.clone();
        no_acl.acl_user.clear();
        assert!(no_acl.validate("c").is_err());
        let mut bad_addr = ok.clone();
        bad_addr.addresses = vec!["cloud".into()];
        assert!(bad_addr.validate("c").is_err());
        assert!(ok.validate("bad name").is_err());
        let mut tls_no_ca = ok;
        tls_no_ca.tls.enabled = true;
        assert!(tls_no_ca.validate("c").is_err());
    }
}
