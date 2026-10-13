//! Subscription registry: maps sessions to topic filters and resolves the delivery targets of a
//! published message (subscription options, subscription identifiers, shared subscriptions).

use crate::protocol::{QoS, SubscriptionOptions};
use crate::routing::topic::{parse_shared_subscription, topic_matches_filter, TopicError};
use crate::routing::trie::TopicTrie;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};

pub type SessionId = u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Subscription {
    pub options: SubscriptionOptions,
    /// MQTT v5.0 Subscription Identifier (§3.8.2.1.2).
    pub identifier: Option<u32>,
}

impl Subscription {
    pub fn new(options: SubscriptionOptions) -> Self {
        Self {
            options,
            identifier: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum SubscriberKey {
    Session(SessionId),
    SharedGroup(u64),
}

#[derive(Debug)]
struct SharedGroup {
    members: Vec<(SessionId, Subscription)>,
    next: AtomicUsize,
}

/// One session that should receive a published message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub session: SessionId,
    /// Highest QoS granted by the matching subscriptions (before downgrading to the message QoS).
    pub qos: QoS,
    pub retain_as_published: bool,
    pub subscription_ids: Vec<u32>,
}

#[derive(Debug, Default)]
pub struct Router {
    trie: TopicTrie<SubscriberKey>,
    /// Non-shared subscriptions of every session, keyed by filter.
    sessions: HashMap<SessionId, HashMap<String, Subscription>>,
    /// Shared subscriptions of every session: full `$share/...` filter -> group id.
    session_shares: HashMap<SessionId, HashMap<String, u64>>,
    /// (share name, filter) -> group id.
    group_ids: HashMap<(String, String), u64>,
    groups: HashMap<u64, SharedGroup>,
    next_group_id: u64,
}

impl Router {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds or replaces a subscription. Returns `Ok(true)` when the subscription did not exist
    /// before (needed for Retain Handling 1, §3.8.3.1).
    pub fn subscribe(
        &mut self,
        session: SessionId,
        filter: &str,
        sub: Subscription,
    ) -> Result<bool, TopicError> {
        if let Some((share, inner)) = parse_shared_subscription(filter)? {
            let key = (share.to_owned(), inner.to_owned());
            let group_id = match self.group_ids.get(&key) {
                Some(id) => *id,
                None => {
                    let id = self.next_group_id;
                    self.next_group_id += 1;
                    self.trie.subscribe(inner, SubscriberKey::SharedGroup(id))?;
                    self.group_ids.insert(key, id);
                    self.groups.insert(
                        id,
                        SharedGroup {
                            members: Vec::new(),
                            next: AtomicUsize::new(0),
                        },
                    );
                    id
                }
            };
            let group = self.groups.get_mut(&group_id).expect("group exists");
            let is_new = match group.members.iter_mut().find(|(s, _)| *s == session) {
                Some(entry) => {
                    entry.1 = sub;
                    false
                }
                None => {
                    group.members.push((session, sub));
                    true
                }
            };
            self.session_shares
                .entry(session)
                .or_default()
                .insert(filter.to_owned(), group_id);
            return Ok(is_new);
        }

        self.trie
            .subscribe(filter, SubscriberKey::Session(session))?;
        let previous = self
            .sessions
            .entry(session)
            .or_default()
            .insert(filter.to_owned(), sub);
        Ok(previous.is_none())
    }

    /// Removes a subscription. Returns true if it existed.
    pub fn unsubscribe(&mut self, session: SessionId, filter: &str) -> bool {
        if let Some(shares) = self.session_shares.get_mut(&session) {
            if let Some(group_id) = shares.remove(filter) {
                if shares.is_empty() {
                    self.session_shares.remove(&session);
                }
                self.leave_group(session, group_id);
                return true;
            }
        }
        let Some(subs) = self.sessions.get_mut(&session) else {
            return false;
        };
        if subs.remove(filter).is_none() {
            return false;
        }
        if subs.is_empty() {
            self.sessions.remove(&session);
        }
        self.trie
            .unsubscribe(filter, &SubscriberKey::Session(session));
        true
    }

    fn leave_group(&mut self, session: SessionId, group_id: u64) {
        let Some(group) = self.groups.get_mut(&group_id) else {
            return;
        };
        group.members.retain(|(s, _)| *s != session);
        if group.members.is_empty() {
            self.groups.remove(&group_id);
            if let Some((key, _)) = self.group_ids.iter().find(|(_, id)| **id == group_id) {
                let key = key.clone();
                self.group_ids.remove(&key);
                self.trie
                    .unsubscribe(&key.1, &SubscriberKey::SharedGroup(group_id));
            }
        }
    }

    /// Removes every subscription of a session.
    pub fn remove_session(&mut self, session: SessionId) {
        if let Some(subs) = self.sessions.remove(&session) {
            for filter in subs.keys() {
                self.trie
                    .unsubscribe(filter, &SubscriberKey::Session(session));
            }
        }
        if let Some(shares) = self.session_shares.remove(&session) {
            for group_id in shares.into_values() {
                self.leave_group(session, group_id);
            }
        }
    }

    /// Returns the filters a session is subscribed to (shared ones in `$share/` form).
    pub fn session_filters(&self, session: SessionId) -> Vec<String> {
        let mut out: Vec<String> = self
            .sessions
            .get(&session)
            .map(|s| s.keys().cloned().collect())
            .unwrap_or_default();
        if let Some(shares) = self.session_shares.get(&session) {
            out.extend(shares.keys().cloned());
        }
        out
    }

    pub fn subscription_count(&self) -> usize {
        self.sessions.values().map(HashMap::len).sum::<usize>()
            + self
                .session_shares
                .values()
                .map(HashMap::len)
                .sum::<usize>()
    }

    /// Resolves the sessions that receive a message published on `topic`.
    ///
    /// * `origin` is the publishing session, used for the No Local option.
    /// * `is_online` lets shared subscriptions prefer members that are currently connected.
    pub fn route(
        &self,
        topic: &str,
        origin: Option<SessionId>,
        is_online: impl Fn(SessionId) -> bool,
    ) -> Vec<Target> {
        let mut targets = Vec::new();
        for key in self.trie.matches(topic) {
            match key {
                SubscriberKey::Session(session) => {
                    let Some(subs) = self.sessions.get(&session) else {
                        continue;
                    };
                    let mut target: Option<Target> = None;
                    for (filter, sub) in subs {
                        if !topic_matches_filter(filter, topic) {
                            continue;
                        }
                        // No Local: never deliver to the session that published it (§3.8.3.1).
                        if sub.options.no_local && origin == Some(session) {
                            continue;
                        }
                        let t = target.get_or_insert_with(|| Target {
                            session,
                            qos: QoS::AtMostOnce,
                            retain_as_published: false,
                            subscription_ids: Vec::new(),
                        });
                        t.qos = t.qos.max(sub.options.qos);
                        t.retain_as_published |= sub.options.retain_as_published;
                        if let Some(id) = sub.identifier {
                            t.subscription_ids.push(id);
                        }
                    }
                    if let Some(mut t) = target {
                        t.subscription_ids.sort_unstable();
                        targets.push(t);
                    }
                }
                SubscriberKey::SharedGroup(group_id) => {
                    let Some(group) = self.groups.get(&group_id) else {
                        continue;
                    };
                    let n = group.members.len();
                    if n == 0 {
                        continue;
                    }
                    let start = group.next.fetch_add(1, Ordering::Relaxed);
                    // Round-robin, preferring connected members; fall back to the next in line.
                    let pick = (0..n)
                        .map(|i| &group.members[(start + i) % n])
                        .find(|(s, _)| is_online(*s))
                        .unwrap_or(&group.members[start % n]);
                    let (session, sub) = *pick;
                    targets.push(Target {
                        session,
                        qos: sub.options.qos,
                        retain_as_published: sub.options.retain_as_published,
                        subscription_ids: sub.identifier.into_iter().collect(),
                    });
                }
            }
        }
        targets
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sub(qos: QoS) -> Subscription {
        Subscription::new(SubscriptionOptions::new(qos))
    }

    #[test]
    fn overlapping_subscriptions_yield_one_target_with_max_qos_and_all_ids() {
        let mut r = Router::new();
        r.subscribe(
            1,
            "a/+",
            Subscription {
                identifier: Some(5),
                ..sub(QoS::AtMostOnce)
            },
        )
        .unwrap();
        r.subscribe(
            1,
            "a/#",
            Subscription {
                identifier: Some(2),
                ..sub(QoS::ExactlyOnce)
            },
        )
        .unwrap();
        let t = r.route("a/b", None, |_| true);
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].qos, QoS::ExactlyOnce);
        assert_eq!(t[0].subscription_ids, vec![2, 5]);
    }

    #[test]
    fn no_local_skips_the_publisher_only() {
        let mut r = Router::new();
        let mut opts = SubscriptionOptions::new(QoS::AtLeastOnce);
        opts.no_local = true;
        r.subscribe(1, "chat", Subscription::new(opts)).unwrap();
        r.subscribe(2, "chat", Subscription::new(opts)).unwrap();
        let t = r.route("chat", Some(1), |_| true);
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].session, 2);
    }

    #[test]
    fn subscribe_reports_whether_new_and_unsubscribe_cleans_up() {
        let mut r = Router::new();
        assert_eq!(r.subscribe(1, "x/y", sub(QoS::AtMostOnce)), Ok(true));
        assert_eq!(r.subscribe(1, "x/y", sub(QoS::AtLeastOnce)), Ok(false));
        assert_eq!(r.route("x/y", None, |_| true)[0].qos, QoS::AtLeastOnce);
        assert!(r.unsubscribe(1, "x/y"));
        assert!(!r.unsubscribe(1, "x/y"));
        assert!(r.route("x/y", None, |_| true).is_empty());
        assert_eq!(r.subscription_count(), 0);
    }

    #[test]
    fn shared_subscription_round_robin_prefers_online_members() {
        let mut r = Router::new();
        r.subscribe(1, "$share/g/jobs/#", sub(QoS::AtLeastOnce))
            .unwrap();
        r.subscribe(2, "$share/g/jobs/#", sub(QoS::AtLeastOnce))
            .unwrap();
        r.subscribe(3, "jobs/#", sub(QoS::AtMostOnce)).unwrap();

        let mut counts = HashMap::new();
        for _ in 0..10 {
            for t in r.route("jobs/1", None, |_| true) {
                *counts.entry(t.session).or_insert(0) += 1;
            }
        }
        // The normal subscriber sees every message; the group splits them.
        assert_eq!(counts[&3], 10);
        assert_eq!(counts[&1] + counts[&2], 10);
        assert!(counts[&1] > 0 && counts[&2] > 0);

        // Only session 2 online: all group messages go to it.
        for _ in 0..4 {
            let t = r.route("jobs/1", None, |s| s == 2);
            assert!(t.iter().any(|t| t.session == 2));
            assert!(!t.iter().any(|t| t.session == 1));
        }
    }

    #[test]
    fn removing_sessions_dissolves_empty_groups() {
        let mut r = Router::new();
        r.subscribe(1, "$share/g/a", sub(QoS::AtMostOnce)).unwrap();
        r.subscribe(1, "b", sub(QoS::AtMostOnce)).unwrap();
        assert_eq!(r.session_filters(1).len(), 2);
        r.remove_session(1);
        assert!(r.route("a", None, |_| true).is_empty());
        assert!(r.route("b", None, |_| true).is_empty());
        assert_eq!(r.subscription_count(), 0);
        assert!(r.groups.is_empty() && r.group_ids.is_empty());
    }

    #[test]
    fn invalid_filters_are_rejected() {
        let mut r = Router::new();
        assert!(r.subscribe(1, "a/#/b", sub(QoS::AtMostOnce)).is_err());
        assert!(r.subscribe(1, "$share/g", sub(QoS::AtMostOnce)).is_err());
    }
}
