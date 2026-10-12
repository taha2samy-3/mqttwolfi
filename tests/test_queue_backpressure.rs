use std::collections::VecDeque;
use wolf_mqtt::config::QueueSettings;

/// A simulated client session message queue to test slow consumer handling
pub struct MockClientQueue {
    settings: QueueSettings,
    messages: VecDeque<String>,
    dropped_count: usize,
}

impl MockClientQueue {
    pub fn new(settings: QueueSettings) -> Self {
        Self {
            settings,
            messages: VecDeque::new(),
            dropped_count: 0,
        }
    }

    pub fn push(&mut self, msg: String) -> bool {
        if self.messages.len() >= self.settings.max_queued_messages {
            match self.settings.queue_full_policy.as_str() {
                "drop_oldest" => {
                    self.messages.pop_front();
                    self.messages.push_back(msg);
                    self.dropped_count += 1;
                    true
                }
                "drop_newest" => {
                    self.dropped_count += 1;
                    false // incoming message rejected/dropped
                }
                _ => false, // "reject_publisher"
            }
        } else {
            self.messages.push_back(msg);
            true
        }
    }

    pub fn len(&self) -> usize {
        self.messages.len()
    }

    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    pub fn dropped(&self) -> usize {
        self.dropped_count
    }
}

#[test]
fn test_slow_consumer_drop_oldest_policy() {
    let settings = QueueSettings {
        max_queued_messages: 5,
        queue_full_policy: "drop_oldest".into(),
        ..Default::default()
    };
    let mut queue = MockClientQueue::new(settings);

    // Push 5 messages (queue fills up)
    for i in 1..=5 {
        assert!(queue.push(format!("msg_{i}")));
    }
    assert_eq!(queue.len(), 5);
    assert_eq!(queue.dropped(), 0);

    // Push 6th message: should drop msg_1 and retain msg_2 through msg_6
    assert!(queue.push("msg_6".into()));
    assert_eq!(queue.len(), 5);
    assert_eq!(queue.dropped(), 1);
    assert_eq!(queue.messages.front().unwrap(), "msg_2");
    assert_eq!(queue.messages.back().unwrap(), "msg_6");
}

#[test]
fn test_slow_consumer_drop_newest_policy() {
    let settings = QueueSettings {
        max_queued_messages: 3,
        queue_full_policy: "drop_newest".into(),
        ..Default::default()
    };
    let mut queue = MockClientQueue::new(settings);

    assert!(queue.push("first".into()));
    assert!(queue.push("second".into()));
    assert!(queue.push("third".into()));

    // 4th message should be dropped, preserving the original 3
    assert!(!queue.push("overflow".into()));
    assert_eq!(queue.len(), 3);
    assert_eq!(queue.dropped(), 1);
    assert_eq!(queue.messages.back().unwrap(), "third");
}
