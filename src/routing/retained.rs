//! Retained message store (OASIS MQTT v5.0 §3.3.1.3) with count/byte quotas and
//! Message Expiry Interval support (§3.3.2.3.3).

use crate::protocol::PublishPacket;
use crate::routing::topic::{has_wildcards, topic_matches_filter};
use std::collections::HashMap;
use std::time::Instant;

#[derive(Debug, Clone)]
struct RetainedEntry {
    packet: PublishPacket,
    expires_at: Option<Instant>,
}

/// Outcome of [`RetainedStore::update`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetainOutcome {
    Stored,
    Cleared,
    /// Nothing changed (e.g. clearing a topic that had no retained message).
    Unchanged,
    RejectedQuota,
}

#[derive(Debug, Clone)]
pub struct RetainedStore {
    messages: HashMap<String, RetainedEntry>,
    max_messages: usize,
    current_bytes: usize,
    max_bytes: usize,
}

impl Default for RetainedStore {
    fn default() -> Self {
        Self::with_limits(100_000, 64 * 1024 * 1024)
    }
}

fn entry_size(p: &PublishPacket) -> usize {
    p.memory_size()
}

impl RetainedStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_max_messages(max_messages: usize) -> Self {
        Self::with_limits(max_messages, 64 * 1024 * 1024)
    }

    pub fn with_limits(max_messages: usize, max_bytes: usize) -> Self {
        Self {
            messages: HashMap::new(),
            max_messages,
            current_bytes: 0,
            max_bytes,
        }
    }

    pub fn current_bytes(&self) -> usize {
        self.current_bytes
    }

    pub fn max_bytes(&self) -> usize {
        self.max_bytes
    }

    /// Stores or deletes the retained message for `packet.topic`.
    /// A zero-length payload deletes the retained message (§3.3.1.3).
    /// `expires_at` is derived from the Message Expiry Interval, if any.
    pub fn update(
        &mut self,
        mut packet: PublishPacket,
        expires_at: Option<Instant>,
    ) -> RetainOutcome {
        let old_size = self
            .messages
            .get(&packet.topic)
            .map(|e| entry_size(&e.packet))
            .unwrap_or(0);

        if packet.payload.is_empty() {
            return match self.messages.remove(&packet.topic) {
                Some(_) => {
                    self.current_bytes = self.current_bytes.saturating_sub(old_size);
                    RetainOutcome::Cleared
                }
                None => RetainOutcome::Unchanged,
            };
        }

        if self.messages.len() >= self.max_messages && !self.messages.contains_key(&packet.topic) {
            tracing::warn!(
                "Retained store count quota exceeded ({}/{}); rejecting topic '{}'",
                self.messages.len(),
                self.max_messages,
                packet.topic
            );
            return RetainOutcome::RejectedQuota;
        }

        let new_total = self.current_bytes.saturating_sub(old_size) + entry_size(&packet);
        if new_total > self.max_bytes {
            tracing::warn!(
                "Retained store byte quota exceeded ({}/{} bytes); rejecting topic '{}'",
                new_total,
                self.max_bytes,
                packet.topic
            );
            // The new message MUST replace the old one (MQTT-3.3.1-5): when it cannot be
            // stored, the stale value must not be served to new subscribers either.
            if self.messages.remove(&packet.topic).is_some() {
                self.current_bytes = self.current_bytes.saturating_sub(old_size);
            }
            return RetainOutcome::RejectedQuota;
        }

        self.current_bytes = new_total;
        packet.retain = true;
        packet.dup = false;
        packet.packet_id = None;
        self.messages
            .insert(packet.topic.clone(), RetainedEntry { packet, expires_at });
        RetainOutcome::Stored
    }

    /// Returns all live retained messages matching `topic_filter`, with their expiry instants.
    pub fn matches_for_filter(&self, topic_filter: &str) -> Vec<(PublishPacket, Option<Instant>)> {
        let now = Instant::now();
        let live = |e: &&RetainedEntry| e.expires_at.is_none_or(|t| t > now);
        if !has_wildcards(topic_filter) {
            return self
                .messages
                .get(topic_filter)
                .filter(live)
                .map(|e| vec![(e.packet.clone(), e.expires_at)])
                .unwrap_or_default();
        }
        self.messages
            .iter()
            .filter(|(topic, _)| topic_matches_filter(topic_filter, topic))
            .map(|(_, e)| e)
            .filter(live)
            .map(|e| (e.packet.clone(), e.expires_at))
            .collect()
    }

    /// Convenience wrapper returning only the packets.
    pub fn get_matches_for_filter(&self, topic_filter: &str) -> Vec<PublishPacket> {
        self.matches_for_filter(topic_filter)
            .into_iter()
            .map(|(p, _)| p)
            .collect()
    }

    /// Drops every message whose expiry interval has elapsed. Returns how many were removed.
    pub fn purge_expired(&mut self, now: Instant) -> usize {
        let before = self.messages.len();
        let mut freed = 0;
        self.messages.retain(|_, e| {
            let keep = e.expires_at.is_none_or(|t| t > now);
            if !keep {
                freed += entry_size(&e.packet);
            }
            keep
        });
        self.current_bytes = self.current_bytes.saturating_sub(freed);
        before - self.messages.len()
    }

    /// Total count of retained messages currently stored.
    pub fn count(&self) -> usize {
        self.messages.len()
    }

    /// Checks if a concrete topic currently has a retained message.
    pub fn contains_topic(&self, topic: &str) -> bool {
        self.messages.contains_key(topic)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::QoS;
    use bytes::Bytes;
    use std::time::Duration;

    fn msg(topic: &str, payload: &'static [u8]) -> PublishPacket {
        PublishPacket::new(topic, Bytes::from_static(payload))
    }

    #[test]
    fn store_and_match_with_wildcards() {
        let mut store = RetainedStore::new();
        let p1 = msg("factory/line1/temp", b"25.0").with_qos(QoS::AtLeastOnce, Some(1));
        assert_eq!(store.update(p1, None), RetainOutcome::Stored);
        store.update(msg("factory/line2/temp", b"30.0"), None);
        store.update(msg("factory", b"root"), None);
        assert_eq!(store.count(), 3);

        assert_eq!(store.get_matches_for_filter("factory/+/temp").len(), 2);
        // `factory/#` also matches the parent topic `factory`.
        assert_eq!(store.get_matches_for_filter("factory/#").len(), 3);
        let single = store.get_matches_for_filter("factory/line1/temp");
        assert_eq!(single.len(), 1);
        assert_eq!(single[0].payload, Bytes::from_static(b"25.0"));
        // Stored copies never carry the publisher's packet id.
        assert_eq!(single[0].packet_id, None);
        assert!(single[0].retain);
    }

    #[test]
    fn root_wildcards_do_not_return_dollar_topics() {
        let mut store = RetainedStore::new();
        store.update(msg("$SYS/broker/uptime", b"1"), None);
        assert!(store.get_matches_for_filter("#").is_empty());
        assert_eq!(store.get_matches_for_filter("$SYS/#").len(), 1);
    }

    #[test]
    fn empty_payload_erases() {
        let mut store = RetainedStore::new();
        store.update(msg("device/status", b"ONLINE"), None);
        assert_eq!(
            store.update(msg("device/status", b""), None),
            RetainOutcome::Cleared
        );
        assert_eq!(
            store.update(msg("device/status", b""), None),
            RetainOutcome::Unchanged
        );
        assert_eq!(store.count(), 0);
        assert_eq!(store.current_bytes(), 0);
    }

    #[test]
    fn count_quota() {
        let mut store = RetainedStore::with_max_messages(2);
        assert_eq!(
            store.update(msg("topic/1", b"v1"), None),
            RetainOutcome::Stored
        );
        assert_eq!(
            store.update(msg("topic/2", b"v2"), None),
            RetainOutcome::Stored
        );
        assert_eq!(
            store.update(msg("topic/3", b"v3"), None),
            RetainOutcome::RejectedQuota
        );
        // Replacing an existing topic is allowed at the quota.
        assert_eq!(
            store.update(msg("topic/1", b"v1b"), None),
            RetainOutcome::Stored
        );
        assert_eq!(store.count(), 2);
    }

    #[test]
    fn byte_quota() {
        let mut store = RetainedStore::with_limits(100, 30);
        assert_eq!(
            store.update(msg("t/01", b"0123456789"), None),
            RetainOutcome::Stored
        );
        assert_eq!(
            store.update(msg("t/02", b"0123456789"), None),
            RetainOutcome::Stored
        );
        assert_eq!(store.current_bytes(), 28);
        assert_eq!(
            store.update(msg("t/03", b"12345"), None),
            RetainOutcome::RejectedQuota
        );
        store.update(msg("t/01", b""), None);
        assert_eq!(store.current_bytes(), 14);
        assert_eq!(
            store.update(msg("t/03", b"12345"), None),
            RetainOutcome::Stored
        );
        assert_eq!(store.current_bytes(), 23);
        // A replacement that does not fit removes the old value instead of keeping it.
        assert_eq!(
            store.update(msg("t/02", b"0123456789-too-large"), None),
            RetainOutcome::RejectedQuota
        );
        assert!(store.matches_for_filter("t/02").is_empty());
        assert_eq!(store.current_bytes(), 9);
    }

    #[test]
    fn expired_messages_are_hidden_and_purged() {
        let mut store = RetainedStore::new();
        let past = Instant::now() - Duration::from_secs(1);
        let future = Instant::now() + Duration::from_secs(60);
        store.update(msg("a/old", b"x"), Some(past));
        store.update(msg("a/new", b"y"), Some(future));
        assert!(store.get_matches_for_filter("a/old").is_empty());
        assert_eq!(store.get_matches_for_filter("a/#").len(), 1);
        assert_eq!(store.purge_expired(Instant::now()), 1);
        assert_eq!(store.count(), 1);
        assert_eq!(store.current_bytes(), "a/new".len() + 1);
    }
}
