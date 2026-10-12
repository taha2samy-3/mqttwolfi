use std::collections::{HashMap, HashSet};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TopicError {
    #[error("Topic filter is empty")]
    EmptyTopic,
    #[error("Multi-level wildcard '#' must be the last character in the topic filter")]
    InvalidMultiWildcardPosition,
    #[error("Single-level wildcard '+' must occupy an entire topic level")]
    InvalidSingleWildcardPosition,
}

#[derive(Debug)]
pub struct TopicTrie<T: Clone + Eq + std::hash::Hash> {
    subscribers: HashSet<T>,
    children: HashMap<String, TopicTrie<T>>,
    single_wildcard: Option<Box<TopicTrie<T>>>,
    multi_wildcard_subscribers: HashSet<T>,
}

impl<T: Clone + Eq + std::hash::Hash> Default for TopicTrie<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Clone + Eq + std::hash::Hash> TopicTrie<T> {
    pub fn new() -> Self {
        Self {
            subscribers: HashSet::new(),
            children: HashMap::new(),
            single_wildcard: None,
            multi_wildcard_subscribers: HashSet::new(),
        }
    }

    /// Validates an MQTT topic filter according to OASIS MQTT specification rules.
    pub fn validate_filter(filter: &str) -> Result<(), TopicError> {
        if filter.is_empty() {
            return Err(TopicError::EmptyTopic);
        }

        let parts: Vec<&str> = filter.split('/').collect();
        let total = parts.len();

        for (idx, part) in parts.iter().enumerate() {
            if part.contains('#') && (*part != "#" || idx != total - 1) {
                return Err(TopicError::InvalidMultiWildcardPosition);
            }
            if part.contains('+') && *part != "+" {
                return Err(TopicError::InvalidSingleWildcardPosition);
            }
        }

        Ok(())
    }

    /// Subscribes a subscriber ID to a topic filter with strict validation.
    pub fn subscribe(&mut self, topic_filter: &str, subscriber: T) -> Result<(), TopicError> {
        Self::validate_filter(topic_filter)?;
        let parts: Vec<&str> = topic_filter.split('/').collect();
        self.insert_recursive(&parts, subscriber);
        Ok(())
    }

    fn insert_recursive(&mut self, parts: &[&str], subscriber: T) {
        if parts.is_empty() {
            self.subscribers.insert(subscriber);
            return;
        }

        match parts[0] {
            "#" => {
                self.multi_wildcard_subscribers.insert(subscriber);
            }
            "+" => {
                let node = self
                    .single_wildcard
                    .get_or_insert_with(|| Box::new(TopicTrie::new()));
                node.insert_recursive(&parts[1..], subscriber);
            }
            token => {
                let node = self.children.entry(token.to_string()).or_default();
                node.insert_recursive(&parts[1..], subscriber);
            }
        }
    }

    /// Returns true if this trie node and all its subtrees have no subscribers.
    pub fn is_empty(&self) -> bool {
        self.subscribers.is_empty()
            && self.multi_wildcard_subscribers.is_empty()
            && self.single_wildcard.is_none()
            && self.children.is_empty()
    }

    /// Unsubscribes a subscriber from a specific topic filter.
    pub fn unsubscribe(&mut self, topic_filter: &str, subscriber: &T) -> bool {
        if Self::validate_filter(topic_filter).is_err() {
            return false;
        }
        let parts: Vec<&str> = topic_filter.split('/').collect();
        self.remove_recursive(&parts, subscriber)
    }

    fn remove_recursive(&mut self, parts: &[&str], subscriber: &T) -> bool {
        if parts.is_empty() {
            return self.subscribers.remove(subscriber);
        }

        match parts[0] {
            "#" => self.multi_wildcard_subscribers.remove(subscriber),
            "+" => {
                if let Some(ref mut node) = self.single_wildcard {
                    let removed = node.remove_recursive(&parts[1..], subscriber);
                    if node.is_empty() {
                        self.single_wildcard = None;
                    }
                    removed
                } else {
                    false
                }
            }
            token => {
                let (removed, should_clean) = if let Some(node) = self.children.get_mut(token) {
                    let removed = node.remove_recursive(&parts[1..], subscriber);
                    (removed, node.is_empty())
                } else {
                    (false, false)
                };
                if should_clean {
                    self.children.remove(token);
                }
                removed
            }
        }
    }

    /// Matches and returns all subscribers interested in a concrete published topic.
    pub fn matches(&self, topic_name: &str) -> HashSet<T> {
        let mut result = HashSet::new();
        let parts: Vec<&str> = topic_name.split('/').collect();
        self.match_recursive(&parts, true, &mut result);
        result
    }

    fn match_recursive(&self, parts: &[&str], is_root: bool, result: &mut HashSet<T>) {
        if parts.is_empty() {
            for sub in &self.subscribers {
                result.insert(sub.clone());
            }
            return;
        }

        let token = parts[0];
        let starts_with_dollar = is_root && token.starts_with('$');

        // Multi-level wildcard '#' matches everything from this level onwards,
        // EXCEPT when at the root level and the topic starts with '$' (MQTT-4.7.2-1).
        if !starts_with_dollar {
            for sub in &self.multi_wildcard_subscribers {
                result.insert(sub.clone());
            }
        }

        // Exact match for current path segment (e.g., "$SYS")
        if let Some(child) = self.children.get(token) {
            child.match_recursive(&parts[1..], false, result);
        }

        // Single wildcard '+' matches current path segment,
        // EXCEPT when at the root level and the topic starts with '$' (MQTT-4.7.2-1).
        if !starts_with_dollar {
            if let Some(ref single) = self.single_wildcard {
                single.match_recursive(&parts[1..], false, result);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_topic_match() {
        let mut trie = TopicTrie::new();
        trie.subscribe("home/livingroom/temperature", "sub1")
            .unwrap();
        trie.subscribe("home/bedroom/temperature", "sub2").unwrap();

        let matched = trie.matches("home/livingroom/temperature");
        assert_eq!(matched.len(), 1);
        assert!(matched.contains("sub1"));

        let unmatched = trie.matches("home/kitchen/temperature");
        assert!(unmatched.is_empty());
    }

    #[test]
    fn test_single_wildcard_match() {
        let mut trie = TopicTrie::new();
        trie.subscribe("home/+/temperature", "wild_sub").unwrap();

        let matched1 = trie.matches("home/livingroom/temperature");
        assert!(matched1.contains("wild_sub"));

        let matched2 = trie.matches("home/kitchen/temperature");
        assert!(matched2.contains("wild_sub"));

        let nomatch = trie.matches("home/livingroom/firstfloor/temperature");
        assert!(!nomatch.contains("wild_sub"));
    }

    #[test]
    fn test_multi_wildcard_match() {
        let mut trie = TopicTrie::new();
        trie.subscribe("factory/#", "factory_monitor").unwrap();

        let matched1 = trie.matches("factory/zone1");
        assert!(matched1.contains("factory_monitor"));

        let matched2 = trie.matches("factory/zone1/machine2/temp");
        assert!(matched2.contains("factory_monitor"));

        let outside = trie.matches("office/temperature");
        assert!(!outside.contains("factory_monitor"));
    }

    #[test]
    fn test_unsubscribe_workflow() {
        let mut trie = TopicTrie::new();
        trie.subscribe("sensors/temperature", "nodeA").unwrap();
        assert!(trie.matches("sensors/temperature").contains("nodeA"));

        let removed = trie.unsubscribe("sensors/temperature", &"nodeA");
        assert!(removed);
        assert!(!trie.matches("sensors/temperature").contains("nodeA"));

        // Removing non-existent subscriber returns false
        assert!(!trie.unsubscribe("sensors/temperature", &"nodeA"));
    }

    #[test]
    fn test_invalid_topic_filter_validation() {
        // Empty topic filter
        assert_eq!(
            TopicTrie::<String>::validate_filter(""),
            Err(TopicError::EmptyTopic)
        );

        // Multi-level wildcard '#' in middle is forbidden by MQTT spec
        assert_eq!(
            TopicTrie::<String>::validate_filter("sport/#/football"),
            Err(TopicError::InvalidMultiWildcardPosition)
        );

        // Single-level wildcard '+' combined with characters is forbidden (e.g. "sport+")
        assert_eq!(
            TopicTrie::<String>::validate_filter("sport/tennis+"),
            Err(TopicError::InvalidSingleWildcardPosition)
        );

        // Valid filters
        assert!(TopicTrie::<String>::validate_filter("sport/#").is_ok());
        assert!(TopicTrie::<String>::validate_filter("sport/+/ranking").is_ok());
        assert!(TopicTrie::<String>::validate_filter("#").is_ok());
        assert!(TopicTrie::<String>::validate_filter("+").is_ok());
    }

    #[test]
    fn test_sys_topic_root_wildcard_isolation() {
        let mut trie = TopicTrie::new();
        trie.subscribe("#", "root_multi").unwrap();
        trie.subscribe("+/broker/uptime", "root_single").unwrap();
        trie.subscribe("$SYS/#", "sys_multi").unwrap();
        trie.subscribe("$SYS/broker/uptime", "sys_exact").unwrap();

        // Topic starting with $ must NOT match root '#' or root '+' (MQTT-4.7.2-1)
        let matches = trie.matches("$SYS/broker/uptime");
        assert!(
            !matches.contains("root_multi"),
            "Root # must not match $SYS"
        );
        assert!(
            !matches.contains("root_single"),
            "Root + must not match $SYS"
        );
        assert!(matches.contains("sys_multi"), "Explicit $SYS/# must match");
        assert!(
            matches.contains("sys_exact"),
            "Explicit $SYS/broker/uptime must match"
        );

        // Normal topics must match root '#' and root '+'
        let normal_matches = trie.matches("app/broker/uptime");
        assert!(normal_matches.contains("root_multi"));
        assert!(normal_matches.contains("root_single"));
    }

    #[test]
    fn test_unsubscribe_pruning() {
        let mut trie = TopicTrie::new();
        assert!(trie.is_empty());

        trie.subscribe("a/b/c", "sub1").unwrap();
        trie.subscribe("a/+/d", "sub2").unwrap();
        trie.subscribe("a/#", "sub3").unwrap();
        assert!(!trie.is_empty());

        trie.unsubscribe("a/b/c", &"sub1");
        trie.unsubscribe("a/+/d", &"sub2");
        trie.unsubscribe("a/#", &"sub3");

        // After unsubscribing all, all empty nodes must be pruned
        assert!(
            trie.is_empty(),
            "Trie should be completely pruned and empty"
        );
    }
}
