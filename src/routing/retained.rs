use crate::protocol::PublishPacket;
use crate::routing::TopicTrie;
use std::collections::HashMap;

#[derive(Default, Debug, Clone)]
pub struct RetainedStore {
    messages: HashMap<String, PublishPacket>,
}

impl RetainedStore {
    pub fn new() -> Self {
        Self {
            messages: HashMap::new(),
        }
    }

    /// Stores or deletes a retained message according to MQTT specifications.
    /// If payload is empty (zero-length), the retained message for this topic is deleted.
    pub fn update(&mut self, mut packet: PublishPacket) -> bool {
        if packet.payload.is_empty() {
            // OASIS Spec: Empty payload clears the retained message
            self.messages.remove(&packet.topic).is_some()
        } else {
            // Ensure retain flag is true in the stored message
            packet.retain = true;
            self.messages.insert(packet.topic.clone(), packet);
            true
        }
    }

    /// Queries all retained messages that match a newly subscribed topic filter (supports wildcards).
    pub fn get_matches_for_filter(&self, topic_filter: &str) -> Vec<PublishPacket> {
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
}
