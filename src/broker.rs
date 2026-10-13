//! Shared broker state used by every listener (TCP, TLS, MQTT-SN): sessions, subscriptions,
//! retained messages, message fan-out, Will handling, session expiry and `$SYS` metrics.

use crate::auth::{AclEngine, UserAccount};
use crate::config::AppConfig;
use crate::protocol::{Properties, Property, PublishPacket, QoS, SubscriptionOptions};
use crate::queue::{Delivery, PushResult, QueueLimits};
use crate::routing::{RetainOutcome, RetainedStore, Router, SessionId, Subscription, TopicError};
use crate::session::{Attachment, Session, Transport};
use bytes::Bytes;
use std::collections::HashMap;
use std::ops::Deref;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::{oneshot, watch};
use tracing::{debug, info, warn};

/// Runtime limits and feature switches derived from [`AppConfig`].
#[derive(Debug, Clone)]
pub struct BrokerOptions {
    pub node_id: String,
    pub max_connections: usize,
    pub connect_timeout: Duration,
    pub max_packet_size: usize,
    pub allow_v311: bool,
    pub allow_v500: bool,
    pub receive_maximum: u16,
    pub topic_alias_maximum: u16,
    pub max_keep_alive_sec: u16,
    pub maximum_qos: QoS,
    pub allow_wildcard_subscriptions: bool,
    pub allow_retained_messages: bool,
    pub allow_shared_subscriptions: bool,
    pub queue_limits: QueueLimits,
    pub default_message_expiry: Option<Duration>,
    pub max_session_expiry_sec: u32,
    pub client_id_takeover_any: bool,
    pub verify_client_identity: bool,
    pub retained_max_messages: usize,
    pub retained_max_bytes: usize,
    pub sys_interval: Option<Duration>,
}

impl Default for BrokerOptions {
    fn default() -> Self {
        Self::from(&AppConfig::default())
    }
}

impl From<&AppConfig> for BrokerOptions {
    fn from(c: &AppConfig) -> Self {
        let p = &c.mqtt.protocol;
        let q = &c.mqtt.queues;
        Self {
            node_id: c.broker.node_id.clone(),
            max_connections: c.broker.max_connections,
            connect_timeout: Duration::from_secs(c.broker.connect_timeout_sec.max(1)),
            max_packet_size: p.max_packet_size as usize,
            allow_v311: p.allow_v311,
            allow_v500: p.allow_v500,
            receive_maximum: p.receive_maximum,
            topic_alias_maximum: p.topic_alias_maximum,
            max_keep_alive_sec: p.max_keep_alive_sec,
            maximum_qos: QoS::try_from(p.maximum_qos.min(2)).unwrap_or(QoS::ExactlyOnce),
            allow_wildcard_subscriptions: p.allow_wildcard_subscriptions,
            allow_retained_messages: p.allow_retained_messages,
            allow_shared_subscriptions: p.allow_shared_subscriptions,
            queue_limits: QueueLimits {
                max_messages: q.max_queued_messages,
                max_bytes: q.max_queued_bytes,
                policy: q.policy(),
                max_control: 4096,
            },
            default_message_expiry: (q.default_message_expiry_sec > 0)
                .then(|| Duration::from_secs(q.default_message_expiry_sec as u64)),
            max_session_expiry_sec: q.max_session_expiry_sec,
            client_id_takeover_any: c.security.auth.client_id_takeover == "any",
            verify_client_identity: c.listeners.tls.enabled
                && c.security.tls.verify_client_identity,
            retained_max_messages: c.mqtt.retained.max_messages,
            retained_max_bytes: c.mqtt.retained.max_bytes,
            sys_interval: c
                .monitoring
                .sys_topics_enabled
                .then(|| Duration::from_secs(c.monitoring.sys_update_interval_sec.max(1) as u64)),
        }
    }
}

impl BrokerOptions {
    /// Compiled defaults without the periodic `$SYS` publisher; convenient for embedding and
    /// tests. Authorization is decided by the [`AclEngine`] passed alongside.
    pub fn permissive() -> Self {
        Self {
            sys_interval: None,
            ..Self::default()
        }
    }
}

/// Broker-wide counters published under `$SYS/broker/...`.
#[derive(Debug, Default)]
pub struct Metrics {
    pub messages_received: AtomicU64,
    pub messages_sent: AtomicU64,
    pub messages_dropped: AtomicU64,
    pub bytes_received: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub connections_total: AtomicU64,
    pub connections_active: AtomicUsize,
}

/// Why a session could not be opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenError {
    /// The ClientID belongs to a session of a different user and takeover is restricted.
    ClientIdInUse,
    /// The previous connection did not release the session in time.
    Busy,
}

/// A connection's handle on its session.
#[derive(Debug)]
pub struct OpenedSession {
    pub session: Arc<Session>,
    pub session_present: bool,
    pub epoch: u64,
    /// Fires when another connection takes over the session or the broker shuts down.
    pub kick: oneshot::Receiver<u8>,
    /// Dropped by the connection once it no longer touches the session.
    pub release: oneshot::Sender<()>,
}

pub struct Broker {
    pub options: BrokerOptions,
    pub acl: Arc<AclEngine>,
    pub metrics: Metrics,
    router: RwLock<Router>,
    retained: Mutex<RetainedStore>,
    sessions: RwLock<HashMap<SessionId, Arc<Session>>>,
    client_ids: Mutex<HashMap<String, SessionId>>,
    next_session_id: AtomicU64,
    started: Instant,
    shutdown_tx: watch::Sender<bool>,
}

/// Cheaply clonable handle to the shared broker state.
#[derive(Clone)]
pub struct BrokerContext {
    inner: Arc<Broker>,
}

impl Deref for BrokerContext {
    type Target = Broker;

    fn deref(&self) -> &Broker {
        &self.inner
    }
}

fn read<T>(l: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    l.read().unwrap_or_else(|e| e.into_inner())
}

fn write<T>(l: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    l.write().unwrap_or_else(|e| e.into_inner())
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Reason code sent to a connection that loses its session to a newer connection.
pub const KICK_SESSION_TAKEN_OVER: u8 = crate::protocol::reason::SESSION_TAKEN_OVER;
/// Reason code sent to connections when the broker shuts down.
pub const KICK_SERVER_SHUTTING_DOWN: u8 = crate::protocol::reason::SERVER_SHUTTING_DOWN;

impl BrokerContext {
    pub fn new(acl: Arc<AclEngine>) -> Self {
        Self::with_options(acl, BrokerOptions::permissive())
    }

    pub fn with_options(acl: Arc<AclEngine>, options: BrokerOptions) -> Self {
        let retained =
            RetainedStore::with_limits(options.retained_max_messages, options.retained_max_bytes);
        let (shutdown_tx, _) = watch::channel(false);
        Self {
            inner: Arc::new(Broker {
                options,
                acl,
                metrics: Metrics::default(),
                router: RwLock::new(Router::new()),
                retained: Mutex::new(retained),
                sessions: RwLock::new(HashMap::new()),
                client_ids: Mutex::new(HashMap::new()),
                next_session_id: AtomicU64::new(1),
                started: Instant::now(),
                shutdown_tx,
            }),
        }
    }

    pub fn from_config(config: &AppConfig, acl: Arc<AclEngine>) -> Self {
        Self::with_options(acl, BrokerOptions::from(config))
    }

    // ── Shutdown ─────────────────────────────────────────────────────────────

    pub fn shutdown_signal(&self) -> watch::Receiver<bool> {
        self.shutdown_tx.subscribe()
    }

    pub fn is_shutting_down(&self) -> bool {
        *self.shutdown_tx.borrow()
    }

    /// Stops listeners and asks every connection to close.
    pub fn shutdown(&self) {
        self.shutdown_tx.send_replace(true);
        let sessions: Vec<Arc<Session>> = read(&self.sessions).values().cloned().collect();
        for s in sessions {
            let kick = s.state().attachment.as_mut().and_then(|a| a.kick.take());
            if let Some(k) = kick {
                let _ = k.send(KICK_SERVER_SHUTTING_DOWN);
            }
        }
    }

    // ── Sessions ─────────────────────────────────────────────────────────────

    pub fn session(&self, id: SessionId) -> Option<Arc<Session>> {
        read(&self.sessions).get(&id).cloned()
    }

    pub fn session_by_client_id(&self, client_id: &str) -> Option<Arc<Session>> {
        let id = *lock(&self.client_ids).get(client_id)?;
        self.session(id)
    }

    pub fn session_count(&self) -> usize {
        read(&self.sessions).len()
    }

    pub fn connected_count(&self) -> usize {
        read(&self.sessions)
            .values()
            .filter(|s| s.is_connected())
            .count()
    }

    /// Effective session expiry for a new connection.
    pub fn session_expiry_for(&self, requested: Option<u32>, clean_start: bool, v5: bool) -> u32 {
        let wanted = if v5 {
            requested.unwrap_or(0)
        } else if clean_start {
            0
        } else {
            u32::MAX
        };
        wanted.min(self.options.max_session_expiry_sec)
    }

    /// Opens (or resumes) the session for `client_id` and attaches the calling connection.
    ///
    /// An existing connection using the same ClientID is disconnected first (§3.1.4 step 2).
    pub async fn open_session(
        &self,
        client_id: &str,
        user: Arc<UserAccount>,
        clean_start: bool,
        expiry_interval: u32,
        transport: Transport,
    ) -> Result<OpenedSession, OpenError> {
        for _ in 0..5 {
            // 1. Disconnect whoever currently holds a session with this ClientID.
            if let Some(old) = self.session_by_client_id(client_id) {
                if !self.options.client_id_takeover_any && old.user().username != user.username {
                    warn!(
                        "ClientID '{}' is in use by user '{}'; takeover by '{}' refused",
                        client_id,
                        old.user().username,
                        user.username
                    );
                    return Err(OpenError::ClientIdInUse);
                }
                let attachment = old.state().attachment.take();
                if let Some(mut att) = attachment {
                    info!(
                        "ClientID '{}' reconnected; closing the previous connection",
                        client_id
                    );
                    old.state().disconnected_at = Some(Instant::now());
                    if let Some(kick) = att.kick.take() {
                        let _ = kick.send(KICK_SESSION_TAKEN_OVER);
                    }
                    if let Some(released) = att.released.take() {
                        let _ = tokio::time::timeout(Duration::from_secs(5), released).await;
                    }
                }
            }

            // 2. Resume or create, then attach — all under the ClientID lock.
            let mut discarded = None;
            let opened = {
                let mut ids = lock(&self.client_ids);
                let existing = ids.get(client_id).and_then(|id| self.session(*id));
                if existing.as_ref().is_some_and(|s| s.is_connected()) {
                    // Another connection attached in the meantime; go around again.
                    continue;
                }
                let (session, present) = match existing {
                    Some(s) if !clean_start && !s.queue.is_closed() => (s, true),
                    other => {
                        discarded = other;
                        let id = self.next_session_id.fetch_add(1, Ordering::Relaxed);
                        let s = Arc::new(Session::new(
                            id,
                            client_id.to_owned(),
                            transport,
                            Arc::clone(&user),
                            expiry_interval,
                            self.options.queue_limits,
                        ));
                        write(&self.sessions).insert(id, Arc::clone(&s));
                        ids.insert(client_id.to_owned(), id);
                        (s, false)
                    }
                };
                let (kick_tx, kick_rx) = oneshot::channel();
                let (release_tx, release_rx) = oneshot::channel();
                let epoch = {
                    let mut st = session.state();
                    let epoch = st.new_epoch();
                    st.attachment = Some(Attachment {
                        epoch,
                        kick: Some(kick_tx),
                        released: Some(release_rx),
                    });
                    st.user = Arc::clone(&user);
                    st.expiry_interval = expiry_interval;
                    st.disconnected_at = None;
                    // A delayed Will is cancelled when the session is resumed (§3.1.3.2.2).
                    st.pending_will = None;
                    epoch
                };
                OpenedSession {
                    session,
                    session_present: present,
                    epoch,
                    kick: kick_rx,
                    release: release_tx,
                }
            };
            if let Some(old) = discarded {
                self.discard_session(&old);
            }
            return Ok(opened);
        }
        Err(OpenError::Busy)
    }

    /// Called when a connection ends. `will` is the connection's Will Message if it must be
    /// published (i.e. the connection did not end with a normal DISCONNECT).
    pub fn connection_closed(
        &self,
        session: &Arc<Session>,
        epoch: u64,
        will: Option<PublishPacket>,
    ) {
        let now = Instant::now();
        let will_delay = |w: &PublishPacket| w.properties.will_delay_interval().unwrap_or(0);
        let mut st = session.state();
        if st.current_epoch() != Some(epoch) {
            // Taken over by a newer connection: the session continues, so only an undelayed
            // Will is published (§3.1.3.2.2).
            drop(st);
            if let Some(w) = will.filter(|w| will_delay(w) == 0) {
                self.publish_will(session, w);
            }
            return;
        }
        st.attachment = None;
        st.disconnected_at = Some(now);
        let expiry = st.expiry_interval;
        let mut publish_now = None;
        if let Some(w) = will {
            let delay = will_delay(&w).min(expiry);
            if delay == 0 {
                publish_now = Some(w);
            } else {
                st.pending_will = Some((w, now + Duration::from_secs(delay as u64)));
            }
        }
        drop(st);
        session.queue.clear_control();
        if let Some(w) = publish_now {
            self.publish_will(session, w);
        }
        if expiry == 0 {
            self.discard_session(session);
        } else {
            debug!(
                "Session '{}' kept for {}s after disconnect",
                session.client_id, expiry
            );
        }
    }

    /// Ends a session: removes its subscriptions, drops queued messages and publishes a Will
    /// that was still waiting for its delay.
    pub fn discard_session(&self, session: &Arc<Session>) {
        {
            let mut ids = lock(&self.client_ids);
            if ids.get(&session.client_id) == Some(&session.id) {
                ids.remove(&session.client_id);
            }
        }
        write(&self.sessions).remove(&session.id);
        write(&self.router).remove_session(session.id);
        session.queue.close();
        let pending = session.state().pending_will.take();
        if let Some((w, _)) = pending {
            self.publish_will(session, w);
        }
    }

    fn publish_will(&self, session: &Arc<Session>, mut will: PublishPacket) {
        let user = session.user();
        if !self
            .acl
            .check_publish(&user, &session.client_id, &will.topic)
        {
            warn!(
                "Will of '{}' on '{}' not published: not authorized",
                session.client_id, will.topic
            );
            return;
        }
        info!(
            "Publishing Will of '{}' on '{}'",
            session.client_id, will.topic
        );
        will.properties
            .retain(|p| !matches!(p, Property::WillDelayInterval(_)));
        will.packet_id = None;
        will.dup = false;
        self.route_message(None, will);
    }

    // ── Subscriptions ────────────────────────────────────────────────────────

    /// Adds a subscription; returns whether it is new (for Retain Handling).
    pub fn subscribe(
        &self,
        session: SessionId,
        filter: &str,
        sub: Subscription,
    ) -> Result<bool, TopicError> {
        write(&self.router).subscribe(session, filter, sub)
    }

    pub fn unsubscribe(&self, session: SessionId, filter: &str) -> bool {
        write(&self.router).unsubscribe(session, filter)
    }

    pub fn subscription_count(&self) -> usize {
        read(&self.router).subscription_count()
    }

    pub fn session_filters(&self, session: SessionId) -> Vec<String> {
        read(&self.router).session_filters(session)
    }

    /// Queues the retained messages matching a new subscription (§3.3.1.3).
    pub fn deliver_retained(&self, session: &Session, filter: &str, sub: &Subscription) -> usize {
        // Shared subscriptions never receive retained messages (§4.8.2).
        if filter.starts_with("$share/") {
            return 0;
        }
        let matches = lock(&self.retained).matches_for_filter(filter);
        let user = session.user();
        let mut n = 0;
        for (mut p, expires_at) in matches {
            if !self.acl.check_read(&user, &session.client_id, &p.topic) {
                continue;
            }
            p.qos = p.qos.min(sub.options.qos);
            p.retain = true;
            if let Some(id) = sub.identifier {
                p.properties.push(Property::SubscriptionIdentifier(id));
            }
            if session.queue.push_publish(Delivery::new(p, expires_at)) != PushResult::Dropped {
                n += 1;
            }
        }
        n
    }

    // ── Publishing ───────────────────────────────────────────────────────────

    /// Routes a message to every matching session and updates the retained store.
    /// `origin` is the publishing session (for No Local). Returns the number of targets.
    pub fn publish(&self, origin: Option<SessionId>, msg: PublishPacket) -> usize {
        self.metrics
            .messages_received
            .fetch_add(1, Ordering::Relaxed);
        self.metrics
            .bytes_received
            .fetch_add(msg.payload.len() as u64, Ordering::Relaxed);
        self.route_message(origin, msg)
    }

    /// Fan-out without traffic accounting (broker-generated messages).
    fn route_message(&self, origin: Option<SessionId>, msg: PublishPacket) -> usize {
        let now = Instant::now();
        let expires_at = msg
            .properties
            .message_expiry_interval()
            .map(|s| now + Duration::from_secs(s as u64));

        if msg.retain && self.options.allow_retained_messages {
            let mut stored = msg.clone();
            stored.properties.retain(|p| {
                !matches!(
                    p,
                    Property::TopicAlias(_) | Property::SubscriptionIdentifier(_)
                )
            });
            if lock(&self.retained).update(stored, expires_at) == RetainOutcome::RejectedQuota {
                self.metrics
                    .messages_dropped
                    .fetch_add(1, Ordering::Relaxed);
            }
        }

        let targets: Vec<(Arc<Session>, crate::routing::Target)> = {
            let router = read(&self.router);
            let sessions = read(&self.sessions);
            router
                .route(&msg.topic, origin, |id| {
                    sessions.get(&id).is_some_and(|s| s.is_connected())
                })
                .into_iter()
                .filter_map(|t| sessions.get(&t.session).map(|s| (Arc::clone(s), t)))
                .collect()
        };

        let mut base = msg;
        base.dup = false;
        base.packet_id = None;
        base.properties.retain(|p| {
            !matches!(
                p,
                Property::TopicAlias(_) | Property::SubscriptionIdentifier(_)
            )
        });
        let count = targets.len();
        for (session, target) in targets {
            let mut p = base.clone();
            p.qos = p.qos.min(target.qos);
            p.retain = p.retain && target.retain_as_published;
            for id in &target.subscription_ids {
                p.properties.push(Property::SubscriptionIdentifier(*id));
            }
            match session.queue.push_publish(Delivery::new(p, expires_at)) {
                PushResult::Queued | PushResult::Closed => {}
                PushResult::QueuedDroppedOldest | PushResult::Dropped => {
                    self.metrics
                        .messages_dropped
                        .fetch_add(1, Ordering::Relaxed);
                    debug!("Queue full for '{}'; message dropped", session.client_id);
                }
            }
        }
        count
    }

    pub fn retained_count(&self) -> usize {
        lock(&self.retained).count()
    }

    /// Clamps a requested QoS to the broker maximum.
    pub fn granted_qos(&self, requested: QoS) -> QoS {
        requested.min(self.options.maximum_qos)
    }

    pub fn uptime(&self) -> Duration {
        self.started.elapsed()
    }

    // ── Housekeeping ─────────────────────────────────────────────────────────

    /// Expires sessions and delayed Wills, purges expired retained messages.
    pub fn housekeeping(&self, now: Instant) {
        let sessions: Vec<Arc<Session>> = read(&self.sessions).values().cloned().collect();
        for s in sessions {
            let (expired, due_will) = {
                let mut st = s.state();
                let expired = st.attachment.is_none()
                    && st
                        .disconnected_at
                        .is_some_and(|t| now >= t + Duration::from_secs(st.expiry_interval as u64));
                let due = if st.pending_will.as_ref().is_some_and(|(_, at)| *at <= now) {
                    st.pending_will.take().map(|(w, _)| w)
                } else {
                    None
                };
                (expired, due)
            };
            if let Some(w) = due_will {
                self.publish_will(&s, w);
            }
            if expired {
                info!("Session '{}' expired", s.client_id);
                self.discard_session(&s);
            }
        }
        lock(&self.retained).purge_expired(now);
    }

    fn publish_sys_metrics(&self) {
        let m = &self.metrics;
        let metrics: [(&str, String); 11] = [
            (
                "$SYS/broker/version",
                format!("WolfiMQ {}", env!("CARGO_PKG_VERSION")),
            ),
            ("$SYS/broker/uptime", self.uptime().as_secs().to_string()),
            (
                "$SYS/broker/clients/connected",
                self.connected_count().to_string(),
            ),
            (
                "$SYS/broker/clients/total",
                self.session_count().to_string(),
            ),
            (
                "$SYS/broker/messages/received",
                m.messages_received.load(Ordering::Relaxed).to_string(),
            ),
            (
                "$SYS/broker/messages/sent",
                m.messages_sent.load(Ordering::Relaxed).to_string(),
            ),
            (
                "$SYS/broker/messages/dropped",
                m.messages_dropped.load(Ordering::Relaxed).to_string(),
            ),
            (
                "$SYS/broker/bytes/received",
                m.bytes_received.load(Ordering::Relaxed).to_string(),
            ),
            (
                "$SYS/broker/bytes/sent",
                m.bytes_sent.load(Ordering::Relaxed).to_string(),
            ),
            (
                "$SYS/broker/retained/count",
                self.retained_count().to_string(),
            ),
            (
                "$SYS/broker/subscriptions/count",
                self.subscription_count().to_string(),
            ),
        ];
        for (topic, value) in metrics {
            self.route_message(
                None,
                PublishPacket::new(topic, Bytes::from(value)).with_retain(true),
            );
        }
    }

    /// Spawns the periodic housekeeping / `$SYS` task. Stops when the broker shuts down.
    pub fn start_background_tasks(&self) {
        let ctx = self.clone();
        let mut shutdown = self.shutdown_signal();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut last_sys: Option<Instant> = None;
            loop {
                tokio::select! {
                    _ = tick.tick() => {}
                    _ = shutdown.changed() => break,
                }
                let now = Instant::now();
                ctx.housekeeping(now);
                if let Some(every) = ctx.options.sys_interval {
                    if last_sys.is_none_or(|t| now.duration_since(t) >= every) {
                        last_sys = Some(now);
                        ctx.publish_sys_metrics();
                    }
                }
            }
        });
    }
}

/// Builds the CONNACK property list advertising this broker's capabilities (MQTT v5.0 §3.2.2.3).
pub fn connack_capabilities(options: &BrokerOptions) -> Properties {
    let mut props = Properties::new();
    if options.receive_maximum < u16::MAX {
        props.push(Property::ReceiveMaximum(options.receive_maximum));
    }
    if options.maximum_qos != QoS::ExactlyOnce {
        props.push(Property::MaximumQoS(options.maximum_qos as u8));
    }
    if !options.allow_retained_messages {
        props.push(Property::RetainAvailable(0));
    }
    props.push(Property::MaximumPacketSize(options.max_packet_size as u32));
    if options.topic_alias_maximum > 0 {
        props.push(Property::TopicAliasMaximum(options.topic_alias_maximum));
    }
    if !options.allow_wildcard_subscriptions {
        props.push(Property::WildcardSubscriptionAvailable(0));
    }
    if !options.allow_shared_subscriptions {
        props.push(Property::SharedSubscriptionAvailable(0));
    }
    props
}

/// Builds a subscription from requested options, clamped to the broker maximum QoS.
pub fn granted_subscription(
    ctx: &BrokerContext,
    mut options: SubscriptionOptions,
    identifier: Option<u32>,
) -> Subscription {
    options.qos = ctx.granted_qos(options.qos);
    Subscription {
        options,
        identifier,
    }
}
