//! Subscription trie keyed by topic levels, supporting `+` and `#` wildcards.

use crate::routing::topic::validate_topic_filter;
pub use crate::routing::topic::TopicError;
use std::collections::{HashMap, HashSet};

#[derive(Debug)]
pub struct TopicTrie<T: Clone + Eq + std::hash::Hash> {
    /// Subscribers whose filter ends exactly at this node.
    subscribers: HashSet<T>,
    children: HashMap<String, TopicTrie<T>>,
    single_wildcard: Option<Box<TopicTrie<T>>>,
    /// Subscribers whose filter is `<path to this node>/#`.
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

    /// Validates an MQTT topic filter according to the OASIS specification rules.
    pub fn validate_filter(filter: &str) -> Result<(), TopicError> {
        validate_topic_filter(filter)
    }

    /// Adds `subscriber` under `topic_filter`. Returns true if it was not present before.
    pub fn subscribe(&mut self, topic_filter: &str, subscriber: T) -> Result<bool, TopicError> {
        validate_topic_filter(topic_filter)?;
        let parts: Vec<&str> = topic_filter.split('/').collect();
        Ok(self.insert_recursive(&parts, subscriber))
    }

    fn insert_recursive(&mut self, parts: &[&str], subscriber: T) -> bool {
        let Some((&head, rest)) = parts.split_first() else {
            return self.subscribers.insert(subscriber);
        };
        match head {
            "#" => self.multi_wildcard_subscribers.insert(subscriber),
            "+" => self
                .single_wildcard
                .get_or_insert_with(|| Box::new(TopicTrie::new()))
                .insert_recursive(rest, subscriber),
            token => self
                .children
                .entry(token.to_string())
                .or_default()
                .insert_recursive(rest, subscriber),
        }
    }

    /// Returns true if this node and all its subtrees have no subscribers.
    pub fn is_empty(&self) -> bool {
        self.subscribers.is_empty()
            && self.multi_wildcard_subscribers.is_empty()
            && self.single_wildcard.is_none()
            && self.children.is_empty()
    }

    /// Removes a subscriber from a topic filter, pruning empty nodes. Returns true if removed.
    pub fn unsubscribe(&mut self, topic_filter: &str, subscriber: &T) -> bool {
        if validate_topic_filter(topic_filter).is_err() {
            return false;
        }
        let parts: Vec<&str> = topic_filter.split('/').collect();
        self.remove_recursive(&parts, subscriber)
    }

    fn remove_recursive(&mut self, parts: &[&str], subscriber: &T) -> bool {
        let Some((&head, rest)) = parts.split_first() else {
            return self.subscribers.remove(subscriber);
        };
        match head {
            "#" => self.multi_wildcard_subscribers.remove(subscriber),
            "+" => {
                let Some(node) = self.single_wildcard.as_mut() else {
                    return false;
                };
                let removed = node.remove_recursive(rest, subscriber);
                if node.is_empty() {
                    self.single_wildcard = None;
                }
                removed
            }
            token => {
                let Some(node) = self.children.get_mut(token) else {
                    return false;
                };
                let removed = node.remove_recursive(rest, subscriber);
                if node.is_empty() {
                    self.children.remove(token);
                }
                removed
            }
        }
    }

    /// Returns all subscribers whose filter matches the concrete topic name.
    pub fn matches(&self, topic_name: &str) -> HashSet<T> {
        let mut result = HashSet::new();
        let parts: Vec<&str> = topic_name.split('/').collect();
        self.match_recursive(&parts, true, &mut result);
        result
    }

    fn match_recursive(&self, parts: &[&str], is_root: bool, result: &mut HashSet<T>) {
        // Wildcards at the first level never match topics starting with '$' (§4.7.2).
        let dollar_topic = is_root && parts.first().is_some_and(|p| p.starts_with('$'));

        // `x/#` matches `x` itself as well as every level below it (§4.7.1.2).
        if !dollar_topic {
            result.extend(self.multi_wildcard_subscribers.iter().cloned());
        }

        let Some((&head, rest)) = parts.split_first() else {
            result.extend(self.subscribers.iter().cloned());
            return;
        };

        if let Some(child) = self.children.get(head) {
            child.match_recursive(rest, false, result);
        }
        if !dollar_topic {
            if let Some(single) = &self.single_wildcard {
                single.match_recursive(rest, false, result);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::topic::topic_matches_filter;

    #[test]
    fn exact_single_and_multi_level_matching() {
        let mut trie = TopicTrie::new();
        trie.subscribe("home/livingroom/temperature", "exact")
            .unwrap();
        trie.subscribe("home/+/temperature", "single").unwrap();
        trie.subscribe("home/#", "multi").unwrap();

        let m = trie.matches("home/livingroom/temperature");
        assert_eq!(m.len(), 3);
        let m = trie.matches("home/kitchen/temperature");
        assert!(m.contains("single") && m.contains("multi") && !m.contains("exact"));
        let m = trie.matches("home/livingroom/firstfloor/temperature");
        assert!(m.contains("multi") && !m.contains("single"));
        assert!(trie.matches("office/temperature").is_empty());
    }

    #[test]
    fn multi_level_wildcard_matches_parent_level() {
        let mut trie = TopicTrie::new();
        trie.subscribe("sport/#", 1u32).unwrap();
        trie.subscribe("#", 2u32).unwrap();
        let m = trie.matches("sport");
        assert!(m.contains(&1) && m.contains(&2));
    }

    #[test]
    fn dollar_topics_are_isolated_from_root_wildcards() {
        let mut trie = TopicTrie::new();
        trie.subscribe("#", "root_multi").unwrap();
        trie.subscribe("+/broker/uptime", "root_single").unwrap();
        trie.subscribe("$SYS/#", "sys_multi").unwrap();
        trie.subscribe("$SYS/broker/uptime", "sys_exact").unwrap();

        let m = trie.matches("$SYS/broker/uptime");
        assert!(!m.contains("root_multi") && !m.contains("root_single"));
        assert!(m.contains("sys_multi") && m.contains("sys_exact"));

        let m = trie.matches("app/broker/uptime");
        assert!(m.contains("root_multi") && m.contains("root_single"));
    }

    #[test]
    fn unsubscribe_prunes_every_node() {
        let mut trie = TopicTrie::new();
        trie.subscribe("a/b/c", "s1").unwrap();
        trie.subscribe("a/+/d", "s2").unwrap();
        trie.subscribe("a/#", "s3").unwrap();
        assert!(trie.unsubscribe("a/b/c", &"s1"));
        assert!(trie.unsubscribe("a/+/d", &"s2"));
        assert!(trie.unsubscribe("a/#", &"s3"));
        assert!(!trie.unsubscribe("a/#", &"s3"));
        assert!(trie.is_empty());
    }

    #[test]
    fn subscribe_reports_new_entries_and_rejects_invalid_filters() {
        let mut trie = TopicTrie::new();
        assert_eq!(trie.subscribe("a/b", 1u8), Ok(true));
        assert_eq!(trie.subscribe("a/b", 1u8), Ok(false));
        assert_eq!(
            trie.subscribe("a/#/b", 1u8),
            Err(TopicError::InvalidMultiWildcardPosition)
        );
    }

    /// The trie must agree with the reference matcher for every filter/topic combination.
    #[test]
    fn trie_agrees_with_reference_matcher() {
        let filters = [
            "#", "+", "+/+", "a", "a/#", "a/+", "a/+/c", "a/b/#", "+/b/#", "/+", "$SYS/#",
            "$SYS/+", "a//c", "+/#",
        ];
        let topics = [
            "a", "a/b", "a/b/c", "a/b/c/d", "a//c", "/a", "b/b/x", "$SYS", "$SYS/x", "a/", "/",
        ];
        let mut trie = TopicTrie::new();
        for f in filters {
            trie.subscribe(f, f).unwrap();
        }
        for t in topics {
            let got = trie.matches(t);
            for f in filters {
                assert_eq!(
                    got.contains(f),
                    topic_matches_filter(f, t),
                    "filter {f} topic {t}"
                );
            }
        }
    }
}
