use std::collections::{HashMap, HashSet};

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

    /// Subscribe a client/subscriber ID to a topic filter.
    pub fn subscribe(&mut self, topic_filter: &str, subscriber: T) {
        let parts: Vec<&str> = topic_filter.split('/').collect();
        self.insert_recursive(&parts, subscriber);
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

    /// Match subscribers for a concrete topic name.
    pub fn matches(&self, topic_name: &str) -> HashSet<T> {
        let mut result = HashSet::new();
        let parts: Vec<&str> = topic_name.split('/').collect();
        self.match_recursive(&parts, &mut result);
        result
    }

    fn match_recursive(&self, parts: &[&str], result: &mut HashSet<T>) {
        // Collect all multi-wildcard subscribers at current level
        for sub in &self.multi_wildcard_subscribers {
            result.insert(sub.clone());
        }

        if parts.is_empty() {
            for sub in &self.subscribers {
                result.insert(sub.clone());
            }
            return;
        }

        let token = parts[0];

        // Match exact child token
        if let Some(child) = self.children.get(token) {
            child.match_recursive(&parts[1..], result);
        }

        // Match single-level wildcard '+'
        if let Some(ref single) = self.single_wildcard {
            single.match_recursive(&parts[1..], result);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_topic_match() {
        let mut trie = TopicTrie::new();
        trie.subscribe("home/livingroom/temperature", "sub1");
        trie.subscribe("home/bedroom/temperature", "sub2");

        let matched = trie.matches("home/livingroom/temperature");
        assert_eq!(matched.len(), 1);
        assert!(matched.contains("sub1"));

        let unmatched = trie.matches("home/kitchen/temperature");
        assert!(unmatched.is_empty());
    }

    #[test]
    fn test_single_wildcard_match() {
        let mut trie = TopicTrie::new();
        trie.subscribe("home/+/temperature", "wild_sub");

        let matched1 = trie.matches("home/livingroom/temperature");
        assert!(matched1.contains("wild_sub"));

        let matched2 = trie.matches("home/kitchen/temperature");
        assert!(matched2.contains("wild_sub"));

        // Must not match multi-level hierarchy
        let nomatch = trie.matches("home/livingroom/firstfloor/temperature");
        assert!(!nomatch.contains("wild_sub"));
    }

    #[test]
    fn test_multi_wildcard_match() {
        let mut trie = TopicTrie::new();
        trie.subscribe("factory/#", "factory_monitor");

        let matched1 = trie.matches("factory/zone1");
        assert!(matched1.contains("factory_monitor"));

        let matched2 = trie.matches("factory/zone1/machine2/temp");
        assert!(matched2.contains("factory_monitor"));

        let outside = trie.matches("office/temperature");
        assert!(!outside.contains("factory_monitor"));
    }
}
