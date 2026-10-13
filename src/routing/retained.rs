use crate::protocol::PublishPacket;
use crate::routing::TopicTrie;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct RetainedStore {
    messages: HashMap<String, PublishPacket>,
    max_messages: usize,
    current_bytes: usize,
    max_bytes: usize,
}

impl Default for RetainedStore {
    fn default() -> Self {
        Self::with_limits(100_000, 64 * 1024 * 1024)
    }
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

    /// Stores or deletes a retained message according to MQTT specifications.
    /// If payload is empty (zero-length), the retained message for this topic is deleted.
    pub fn update(&mut self, mut packet: PublishPacket) -> bool {
        let old_size = self
            .messages
            .get(&packet.topic)
            .map(|p| p.payload.len() + p.topic.len())
            .unwrap_or(0);

        if packet.payload.is_empty() {
            // OASIS Spec: Empty payload clears the retained message
            if self.messages.remove(&packet.topic).is_some() {
                self.current_bytes = self.current_bytes.saturating_sub(old_size);
                true
            } else {
                false
            }
        } else {
            let new_size = packet.payload.len() + packet.topic.len();
            if self.messages.len() >= self.max_messages
                && !self.messages.contains_key(&packet.topic)
            {
                tracing::warn!(
                    "Retained store count quota exceeded ({}/{}). Rejecting new topic '{}'",
                    self.messages.len(),
                    self.max_messages,
                    packet.topic
                );
                return false;
            }

            let new_total = self.current_bytes.saturating_sub(old_size) + new_size;
            if new_total > self.max_bytes {
                tracing::warn!(
                    "Retained store byte quota exceeded ({}/{} bytes). Rejecting topic '{}'",
                    new_total,
                    self.max_bytes,
                    packet.topic
                );
                return false;
            }

            self.current_bytes = new_total;
            // Ensure retain flag is true in the stored message
            packet.retain = true;
            self.messages.insert(packet.topic.clone(), packet);
            true
        }
    }

    /// Queries all retained messages that match a newly subscribed topic filter (supports wildcards).
    pub fn get_matches_for_filter(&self, topic_filter: &str) -> Vec<PublishPacket> {
        // Fast-path: O(1) direct lookup if no wildcards are present
        if !topic_filter.contains('+') && !topic_filter.contains('#') {
            return match self.messages.get(topic_filter) {
                Some(pkt) => vec![pkt.clone()],
                None => Vec::new(),
            };
        }

        let mut matching_packets = Vec::new();

        // Create a transient trie node to match the incoming filter against stored concrete topics
        let mut trie = TopicTrie::new();
        if trie.subscribe(topic_filter, 1u32).is_err() {
            return matching_packets;
        }

        for (topic, packet) in &self.messages {
            if trie.matches(topic).contains(&1u32) {
                matching_packets.push(packet.clone());
            }
        }

        matching_packets
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

    #[test]
    fn test_retained_store_and_match() {
        let mut store = RetainedStore::new();

        let p1 = PublishPacket {
            topic: "factory/line1/temp".into(),
            qos: QoS::AtLeastOnce,
            retain: true,
            dup: false,
            packet_id: Some(1),
            payload: Bytes::from_static(b"25.0"),
        };
        store.update(p1);

        let p2 = PublishPacket {
            topic: "factory/line2/temp".into(),
            qos: QoS::AtMostOnce,
            retain: true,
            dup: false,
            packet_id: None,
            payload: Bytes::from_static(b"30.0"),
        };
        store.update(p2);

        assert_eq!(store.count(), 2);

        // Match wildcard 'factory/+/temp'
        let matches = store.get_matches_for_filter("factory/+/temp");
        assert_eq!(matches.len(), 2);

        // Match single exact
        let single = store.get_matches_for_filter("factory/line1/temp");
        assert_eq!(single.len(), 1);
        assert_eq!(single[0].payload, Bytes::from_static(b"25.0"));
    }

    #[test]
    fn test_retained_empty_payload_erasure() {
        let mut store = RetainedStore::new();

        let p1 = PublishPacket {
            topic: "device/status".into(),
            qos: QoS::AtMostOnce,
            retain: true,
            dup: false,
            packet_id: None,
            payload: Bytes::from_static(b"ONLINE"),
        };
        store.update(p1);
        assert!(store.contains_topic("device/status"));

        // Sending zero-length payload with retain=true clears the message
        let clear_pkt = PublishPacket {
            topic: "device/status".into(),
            qos: QoS::AtMostOnce,
            retain: true,
            dup: false,
            packet_id: None,
            payload: Bytes::new(), // Empty payload
        };
        let removed = store.update(clear_pkt);
        assert!(removed);
        assert!(!store.contains_topic("device/status"));
        assert_eq!(store.count(), 0);
    }

    #[test]
    fn test_retained_store_capacity_quota() {
        let mut store = RetainedStore::with_max_messages(2);

        let p1 = PublishPacket {
            topic: "topic/1".into(),
            qos: QoS::AtMostOnce,
            retain: true,
            dup: false,
            packet_id: None,
            payload: Bytes::from_static(b"v1"),
        };
        let p2 = PublishPacket {
            topic: "topic/2".into(),
            qos: QoS::AtMostOnce,
            retain: true,
            dup: false,
            packet_id: None,
            payload: Bytes::from_static(b"v2"),
        };
        let p3 = PublishPacket {
            topic: "topic/3".into(),
            qos: QoS::AtMostOnce,
            retain: true,
            dup: false,
            packet_id: None,
            payload: Bytes::from_static(b"v3"),
        };

        assert!(store.update(p1));
        assert!(store.update(p2));
        assert_eq!(store.count(), 2);

        // 3rd topic must be rejected because quota (2) is reached
        assert!(!store.update(p3));
        assert_eq!(store.count(), 2);
        assert!(!store.contains_topic("topic/3"));

        // Updating an existing topic should succeed even if quota is reached
        let p1_updated = PublishPacket {
            topic: "topic/1".into(),
            qos: QoS::AtMostOnce,
            retain: true,
            dup: false,
            packet_id: None,
            payload: Bytes::from_static(b"v1_updated"),
        };
        assert!(store.update(p1_updated));
        assert_eq!(store.count(), 2);
    }
}
