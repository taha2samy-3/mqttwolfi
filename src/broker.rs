//! Shared broker state used by every listener (TCP, TLS, MQTT-SN): sessions, subscriptions,
//! retained messages, message fan-out, Will handling, session expiry and `$SYS` metrics.

use crate::auth::{AclEngine, UserAccount};
use crate::config::AppConfig;
use crate::protocol::{
    Properties, Property, PublishPacket, QoS, RetainHandling, SubscriptionOptions,
};
use crate::queue::{Delivery, PushResult, QueueLimits};
use crate::routing::{RetainOutcome, RetainedStore, Router, SessionId, Subscription, TopicError};
use crate::session::{Attachment, PendingWill, Session, Transport};
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
    /// Sessions kept by the broker, connected or offline (0 = unlimited).
    pub max_sessions: usize,
    /// Subscriptions one session may hold (0 = unlimited).
    pub max_subscriptions_per_session: usize,
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
    /// Server-side cap on unacknowledged outbound QoS 1/2 messages per session.
    pub max_inflight_messages: usize,
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
            max_sessions: c.broker.max_sessions,
            max_subscriptions_per_session: p.max_subscriptions_per_session,
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
            max_inflight_messages: q.max_inflight_messages.max(1) as usize,
            default_message_expiry: (q.default_message_expiry_sec > 0)
                .then(|| Duration::from_secs(q.default_message_expiry_sec as u64)),
            max_session_expiry_sec: q.max_session_expiry_sec,
            client_id_takeover_any: c.security.auth.client_id_takeover == "any",
            verify_client_identity: (c.listeners.tls.enabled || c.listeners.wss.enabled)
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
    /// The broker holds `max_sessions` sessions already.
    SessionLimit,
}

/// Why a subscription was not added.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubscribeError {
    InvalidFilter(TopicError),
    /// The session holds `max_subscriptions_per_session` subscriptions already.
    TooManySubscriptions,
}

impl From<TopicError> for SubscribeError {
    fn from(e: TopicError) -> Self {
        SubscribeError::InvalidFilter(e)
    }
}

/// Result of routing one message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Routed {
    /// Sessions the message was queued for.
    pub receivers: usize,
    /// The message asked to be retained but the retained store quota refused it (the previous
    /// retained message of the topic was removed).
    pub retained_rejected: bool,
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

    /// Sessions (connected or persisted) created by one transport.
    pub fn session_count_for(&self, transport: Transport) -> usize {
        read(&self.sessions)
            .values()
            .filter(|s| s.transport == transport)
            .count()
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
        let limits = self.options.queue_limits;
        self.open_session_with_limits(
            client_id,
            user,
            clean_start,
            expiry_interval,
            transport,
            limits,
        )
        .await
    }

    /// Like [`Broker::open_session`], with queue limits of its own for a new session (used by
    /// bridges, whose queue buffers messages while the remote broker is unreachable).
    pub async fn open_session_with_limits(
        &self,
        client_id: &str,
        user: Arc<UserAccount>,
        clean_start: bool,
        expiry_interval: u32,
        transport: Transport,
        limits: QueueLimits,
    ) -> Result<OpenedSession, OpenError> {
        for _ in 0..5 {
            // 1. Disconnect whoever currently holds a session with this ClientID.
            if let Some(old) = self.session_by_client_id(client_id) {
                // A connected client of another user keeps its ClientID. An offline session of
                // another user is replaced (never resumed), so nobody can lock an account out of
                // its ClientID by parking a persistent session on it.
                // MQTT-SN clients are not authenticated, so they never replace the MQTT session of
                // another user, connected or not.
                if !self.options.client_id_takeover_any
                    && old.user().username != user.username
                    && (old.is_connected()
                        || (transport == Transport::MqttSn && old.transport == Transport::Mqtt))
                {
                    warn!(
                        "ClientID '{}' is in use by user '{}'; takeover by '{}' refused",
                        client_id,
                        old.user().username,
                        user.username
                    );
                    return Err(OpenError::ClientIdInUse);
                }
                // The attachment stays until the old connection has released the session, so
                // a third connection cannot attach while the old one is still running.
                let handles = old
                    .state()
                    .attachment
                    .as_mut()
                    .map(|att| (att.epoch, att.kick.take(), att.released.take()));
                if let Some((epoch, kick, released)) = handles {
                    info!(
                        "ClientID '{}' reconnected; closing the previous connection",
                        client_id
                    );
                    if let Some(kick) = kick {
                        let _ = kick.send(KICK_SESSION_TAKEN_OVER);
                    }
                    match released {
                        Some(released) => {
                            if tokio::time::timeout(Duration::from_secs(5), released)
                                .await
                                .is_err()
                            {
                                // The old connection did not finish in time: detach it.
                                let mut st = old.state();
                                if st.current_epoch() == Some(epoch) {
                                    st.attachment = None;
                                    st.disconnected_at = Some(Instant::now());
                                }
                            }
                        }
                        // Another connection is already taking the session over.
                        None => tokio::time::sleep(Duration::from_millis(100)).await,
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
                // Only a persistent session (expiry > 0) of the same user and protocol family
                // can be resumed (MQTT-3.1.2-6 / §3.1.2.4); anything else starts fresh. MQTT and
                // MQTT-SN keep different inflight state, so they never resume each other's
                // sessions.
                let resumable = |s: &Arc<Session>| {
                    let st = s.state();
                    !s.queue.is_closed()
                        && st.expiry_interval > 0
                        && st.user.username == user.username
                        && s.transport == transport
                };
                let (session, present) = match existing {
                    Some(s) if !clean_start && resumable(&s) => {
                        // Replies queued for the previous connection must not reach this one.
                        s.queue.clear_control();
                        (s, true)
                    }
                    other => {
                        let limit = self.options.max_sessions;
                        if other.is_none() && limit > 0 && read(&self.sessions).len() >= limit {
                            warn!(
                                "Session limit ({}) reached; refusing ClientID '{}'",
                                limit, client_id
                            );
                            return Err(OpenError::SessionLimit);
                        }
                        discarded = other;
                        let id = self.next_session_id.fetch_add(1, Ordering::Relaxed);
                        let s = Arc::new(Session::new(
                            id,
                            client_id.to_owned(),
                            transport,
                            Arc::clone(&user),
                            expiry_interval,
                            limits,
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

    /// Called when a connection ends. `will` is the connection's Will Message and the account
    /// that set it, if it must be published (the connection did not end with a normal
    /// DISCONNECT).
    pub fn connection_closed(
        &self,
        session: &Arc<Session>,
        epoch: u64,
        will: Option<(PublishPacket, Arc<UserAccount>)>,
    ) {
        let now = Instant::now();
        let mut st = session.state();
        let taken_over = st.current_epoch() != Some(epoch);
        if !taken_over {
            st.attachment = None;
            st.disconnected_at = Some(now);
            // Cleared under the state lock so a resuming connection cannot interleave.
            session.queue.clear_control();
        }
        let expiry = st.expiry_interval;
        let mut publish_now = None;
        if let Some((w, owner)) = will {
            let delay = w.properties.will_delay_interval().unwrap_or(0).min(expiry);
            if delay == 0 || session.queue.is_closed() {
                // No delay, or the session already ended (taken over with a clean start).
                publish_now = Some((w, owner));
            } else if st.attachment.is_none() {
                st.pending_will = Some(PendingWill {
                    message: w,
                    owner,
                    due: now + Duration::from_secs(delay as u64),
                });
            }
            // Otherwise a new connection already resumed the session within the Will Delay
            // Interval, which cancels the Will (§3.1.3.2.2).
        }
        drop(st);
        if let Some((w, owner)) = publish_now {
            self.publish_will(session, &owner, w);
        }
        if !taken_over {
            if expiry == 0 {
                self.discard_if_expired(session, now);
            } else {
                debug!(
                    "Session '{}' kept for {}s after disconnect",
                    session.client_id, expiry
                );
            }
        }
    }

    /// Discards a session whose connection is gone and whose expiry interval has elapsed. The
    /// check and the removal of the ClientID mapping happen under the ClientID lock, so a
    /// connection resuming the session at the same moment cannot lose it.
    fn discard_if_expired(&self, session: &Arc<Session>, now: Instant) -> bool {
        let pending = {
            let mut ids = lock(&self.client_ids);
            let mut st = session.state();
            let expired = st.attachment.is_none()
                && st
                    .disconnected_at
                    .is_some_and(|t| now >= t + Duration::from_secs(st.expiry_interval as u64));
            if !expired {
                return false;
            }
            if ids.get(&session.client_id) == Some(&session.id) {
                ids.remove(&session.client_id);
            }
            st.pending_will.take()
        };
        self.remove_session(session);
        if let Some(pw) = pending {
            self.publish_will(session, &pw.owner, pw.message);
        }
        true
    }

    /// Ends a session unconditionally (it was replaced by a clean start): removes its
    /// subscriptions, drops queued messages and publishes a Will still waiting for its delay.
    pub fn discard_session(&self, session: &Arc<Session>) {
        {
            let mut ids = lock(&self.client_ids);
            if ids.get(&session.client_id) == Some(&session.id) {
                ids.remove(&session.client_id);
            }
        }
        self.remove_session(session);
        let pending = session.state().pending_will.take();
        if let Some(pw) = pending {
            self.publish_will(session, &pw.owner, pw.message);
        }
    }

    fn remove_session(&self, session: &Arc<Session>) {
        // Closed first: `subscribe` refuses closed sessions under the router lock, so a late
        // SUBSCRIBE of a dying connection cannot leave router entries behind.
        session.queue.close();
        write(&self.sessions).remove(&session.id);
        write(&self.router).remove_session(session.id);
    }

    fn publish_will(&self, session: &Session, owner: &UserAccount, mut will: PublishPacket) {
        let client_id = &session.client_id;
        if !self.may_publish(owner, client_id, &will.topic) {
            warn!(
                "Will of '{}' on '{}' not published: not authorized",
                client_id, will.topic
            );
            return;
        }
        info!("Publishing Will of '{}' on '{}'", client_id, will.topic);
        will.properties
            .retain(|p| !matches!(p, Property::WillDelayInterval(_)));
        will.packet_id = None;
        will.dup = false;
        // Published on behalf of the session, so its own No Local subscriptions skip it.
        self.route_message(Some(session.id), will);
    }

    // ── Authorization ────────────────────────────────────────────────────────
    //
    // Decisions use the account as currently defined in the ACL, not the copy taken at
    // CONNECT, so an ACL reload (SIGHUP) applies to existing connections and subscriptions,
    // and a removed account loses all access.

    pub fn may_publish(&self, user: &UserAccount, client_id: &str, topic: &str) -> bool {
        self.acl
            .current_account(&user.username)
            .is_some_and(|u| self.acl.check_publish(&u, client_id, topic))
    }

    pub fn may_subscribe(&self, user: &UserAccount, client_id: &str, filter: &str) -> bool {
        self.acl
            .current_account(&user.username)
            .is_some_and(|u| self.acl.check_subscribe(&u, client_id, filter))
    }

    pub fn may_read(&self, user: &UserAccount, client_id: &str, topic: &str) -> bool {
        self.acl
            .current_account(&user.username)
            .is_some_and(|u| self.acl.check_read(&u, client_id, topic))
    }

    // ── Subscriptions ────────────────────────────────────────────────────────

    /// Adds (or replaces) a subscription and queues the retained messages its Retain Handling
    /// asks for (§3.3.1.3). Returns whether the subscription is new.
    ///
    /// Both happen under the router write lock, and publishers update the retained store under
    /// the router read lock, so a message published at the same moment is either part of the
    /// retained snapshot or routed live to the new subscription: never both, never out of
    /// order (§4.6).
    pub fn subscribe(
        &self,
        session: &Session,
        filter: &str,
        sub: Subscription,
    ) -> Result<bool, SubscribeError> {
        let mut router = write(&self.router);
        if session.queue.is_closed() {
            // The session ended while this SUBSCRIBE was being processed.
            return Ok(false);
        }
        let limit = self.options.max_subscriptions_per_session;
        if limit > 0
            && router.subscription_count_of(session.id) >= limit
            && !router.has_subscription(session.id, filter)
        {
            return Err(SubscribeError::TooManySubscriptions);
        }
        let is_new = router.subscribe(session.id, filter, sub)?;
        let send_retained = match sub.options.retain_handling {
            RetainHandling::SendAlways => true,
            RetainHandling::SendIfNew => is_new,
            RetainHandling::DoNotSend => false,
        };
        if send_retained {
            self.queue_retained(session, filter, &sub);
        }
        Ok(is_new)
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

    /// Queues the retained messages matching a new subscription (§3.3.1.3). Called with the
    /// router write lock held.
    fn queue_retained(&self, session: &Session, filter: &str, sub: &Subscription) -> usize {
        // Shared subscriptions never receive retained messages (§4.8.2).
        if filter.starts_with("$share/") {
            return 0;
        }
        let matches = lock(&self.retained).matches_for_filter(filter);
        let user = session.user();
        let mut n = 0;
        for (mut p, expires_at) in matches {
            if !self.may_read(&user, &session.client_id, &p.topic) {
                continue;
            }
            p.qos = p.qos.min(sub.options.qos);
            p.retain = true;
            if let Some(id) = sub.identifier {
                p.properties.push(Property::SubscriptionIdentifier(id));
            }
            match session.queue.push_publish(Delivery::new(p, expires_at)) {
                PushResult::Queued => n += 1,
                PushResult::QueuedDroppedOldest(evicted) => {
                    n += 1;
                    self.count_dropped(evicted);
                }
                PushResult::Dropped => self.count_dropped(1),
                PushResult::Closed => {}
            }
        }
        n
    }

    fn count_dropped(&self, n: usize) {
        self.metrics
            .messages_dropped
            .fetch_add(n as u64, Ordering::Relaxed);
    }

    // ── Publishing ───────────────────────────────────────────────────────────

    /// Routes a message to every matching session and updates the retained store.
    /// `origin` is the publishing session (for No Local).
    pub fn publish(&self, origin: Option<SessionId>, msg: PublishPacket) -> Routed {
        self.metrics
            .messages_received
            .fetch_add(1, Ordering::Relaxed);
        self.metrics
            .bytes_received
            .fetch_add(msg.payload.len() as u64, Ordering::Relaxed);
        self.route_message(origin, msg)
    }

    /// Fan-out without traffic accounting (broker-generated messages).
    fn route_message(&self, origin: Option<SessionId>, msg: PublishPacket) -> Routed {
        let now = Instant::now();
        let expires_at = msg
            .properties
            .message_expiry_interval()
            .map(|s| now + Duration::from_secs(s as u64));

        // Held until every target is queued; see `subscribe` for why.
        let router = read(&self.router);
        let mut retained_rejected = false;
        if msg.retain && self.options.allow_retained_messages {
            let mut stored = msg.clone();
            stored.properties.retain(|p| {
                !matches!(
                    p,
                    Property::TopicAlias(_) | Property::SubscriptionIdentifier(_)
                )
            });
            retained_rejected =
                lock(&self.retained).update(stored, expires_at) == RetainOutcome::RejectedQuota;
        }

        let targets: Vec<(Arc<Session>, crate::routing::Target)> = {
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
        let mut count = 0;
        for (session, target) in targets {
            // Re-check read access at delivery time: covers ACL reloads and sessions whose
            // subscriptions predate a rule change.
            if !self.may_read(&session.user(), &session.client_id, &base.topic) {
                continue;
            }
            count += 1;
            let mut p = base.clone();
            p.qos = p.qos.min(target.qos);
            p.retain = p.retain && target.retain_as_published;
            for id in &target.subscription_ids {
                p.properties.push(Property::SubscriptionIdentifier(*id));
            }
            match session.queue.push_publish(Delivery::new(p, expires_at)) {
                PushResult::Queued | PushResult::Closed => {}
                PushResult::QueuedDroppedOldest(evicted) => {
                    self.count_dropped(evicted);
                    debug!(
                        "Queue full for '{}'; {} older message(s) dropped",
                        session.client_id, evicted
                    );
                }
                PushResult::Dropped => {
                    self.count_dropped(1);
                    debug!("Queue full for '{}'; message dropped", session.client_id);
                }
            }
        }
        drop(router);
        Routed {
            receivers: count,
            retained_rejected,
        }
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
            let due_will = {
                let mut st = s.state();
                let due = st.attachment.is_none()
                    && st.pending_will.as_ref().is_some_and(|pw| pw.due <= now);
                if due {
                    st.pending_will.take()
                } else {
                    None
                }
            };
            if let Some(pw) = due_will {
                self.publish_will(&s, &pw.owner, pw.message);
            }
            if self.discard_if_expired(&s, now) {
                info!("Session '{}' expired", s.client_id);
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
