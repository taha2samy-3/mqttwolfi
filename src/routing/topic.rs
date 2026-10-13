//! Topic name / topic filter rules (OASIS MQTT v5.0 §4.7, §4.8.2).

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TopicError {
    #[error("topic filter is empty")]
    EmptyTopic,
    #[error("multi-level wildcard '#' must be the last level of the topic filter")]
    InvalidMultiWildcardPosition,
    #[error("single-level wildcard '+' must occupy an entire topic level")]
    InvalidSingleWildcardPosition,
    #[error("invalid shared subscription")]
    InvalidSharedSubscription,
    #[error("topic contains U+0000")]
    InvalidCharacter,
}

/// Validates a topic filter (§4.7.1).
pub fn validate_topic_filter(filter: &str) -> Result<(), TopicError> {
    if filter.is_empty() {
        return Err(TopicError::EmptyTopic);
    }
    // U+0000 is never allowed in MQTT strings (§1.5.4).
    if filter.contains('\0') {
        return Err(TopicError::InvalidCharacter);
    }
    let levels: Vec<&str> = filter.split('/').collect();
    let last = levels.len() - 1;
    for (idx, level) in levels.iter().enumerate() {
        if level.contains('#') && (*level != "#" || idx != last) {
            return Err(TopicError::InvalidMultiWildcardPosition);
        }
        if level.contains('+') && *level != "+" {
            return Err(TopicError::InvalidSingleWildcardPosition);
        }
    }
    Ok(())
}

/// A topic name used in PUBLISH must be non-empty and free of wildcards (§4.7.3) and of
/// U+0000 (§1.5.4).
pub fn is_valid_topic_name(topic: &str) -> bool {
    !topic.is_empty() && !topic.contains(['+', '#', '\0'])
}

pub fn has_wildcards(filter: &str) -> bool {
    filter.contains(['+', '#'])
}

/// Splits `$share/{ShareName}/{filter}` into its parts (§4.8.2).
/// Returns `Ok(None)` for an ordinary filter.
pub fn parse_shared_subscription(filter: &str) -> Result<Option<(&str, &str)>, TopicError> {
    let Some(rest) = filter.strip_prefix("$share/") else {
        return Ok(None);
    };
    let (group, inner) = rest
        .split_once('/')
        .ok_or(TopicError::InvalidSharedSubscription)?;
    if group.is_empty() || group.contains(['+', '#']) || inner.is_empty() {
        return Err(TopicError::InvalidSharedSubscription);
    }
    validate_topic_filter(inner)?;
    Ok(Some((group, inner)))
}

/// Returns true when `topic` matches `filter`.
///
/// Implements §4.7.1: `#` also matches the parent level (`sport/#` matches `sport`), `+` matches
/// exactly one level (which may be empty), and wildcards in the first level never match topic
/// names that begin with `$` (§4.7.2).
pub fn topic_matches_filter(filter: &str, topic: &str) -> bool {
    if topic.starts_with('$') && (filter.starts_with('+') || filter.starts_with('#')) {
        return false;
    }
    let mut f = filter.split('/');
    let mut t = topic.split('/');
    loop {
        match (f.next(), t.next()) {
            (Some("#"), _) => return true,
            (Some("+"), Some(_)) => {}
            (Some(fl), Some(tl)) if fl == tl => {}
            (None, None) => return true,
            _ => return false,
        }
    }
}

/// Returns true when every topic matched by `filter` is also matched by `pattern`.
///
/// Used for authorization of SUBSCRIBE: a subscription is only allowed when an ACL rule pattern
/// covers the whole filter, so no message can be delivered that the rule would not allow.
pub fn filter_covered_by(pattern: &str, filter: &str) -> bool {
    // A pattern starting with a wildcard does not cover `$`-topics, so it cannot cover a
    // filter that explicitly addresses them.
    if filter.starts_with('$') && (pattern.starts_with('+') || pattern.starts_with('#')) {
        return false;
    }
    let p: Vec<&str> = pattern.split('/').collect();
    let f: Vec<&str> = filter.split('/').collect();
    for (i, fl) in f.iter().enumerate() {
        let Some(pl) = p.get(i) else {
            return false;
        };
        match *pl {
            "#" => return true,
            "+" if *fl != "#" => {}
            literal if literal == *fl && *fl != "+" && *fl != "#" => {}
            _ => return false,
        }
    }
    // Filter exhausted: covered if the pattern is exhausted too, or only `#` remains
    // (`a/#` covers `a`).
    p.len() == f.len() || (p.len() == f.len() + 1 && p[f.len()] == "#")
}

/// Returns true when at least one topic name exists that matches both filters.
pub fn filters_intersect(a: &str, b: &str) -> bool {
    let a_dollar_literal = a.starts_with('$');
    let b_dollar_literal = b.starts_with('$');
    let a_wild_first = a.starts_with('+') || a.starts_with('#');
    let b_wild_first = b.starts_with('+') || b.starts_with('#');
    // Wildcards in the first level never match `$` topics.
    if (a_dollar_literal && b_wild_first) || (b_dollar_literal && a_wild_first) {
        return false;
    }
    let al: Vec<&str> = a.split('/').collect();
    let bl: Vec<&str> = b.split('/').collect();
    let mut i = 0;
    loop {
        match (al.get(i), bl.get(i)) {
            (Some(&"#"), _) | (_, Some(&"#")) => return true,
            (Some(x), Some(y)) => {
                if *x != "+" && *y != "+" && x != y {
                    return false;
                }
            }
            (None, None) => return true,
            // One side ended while the other continues with literal levels or `+`.
            _ => return false,
        }
        i += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_validation() {
        assert_eq!(validate_topic_filter(""), Err(TopicError::EmptyTopic));
        assert_eq!(
            validate_topic_filter("sport/#/football"),
            Err(TopicError::InvalidMultiWildcardPosition)
        );
        assert_eq!(
            validate_topic_filter("sport/tennis#"),
            Err(TopicError::InvalidMultiWildcardPosition)
        );
        assert_eq!(
            validate_topic_filter("sport/tennis+"),
            Err(TopicError::InvalidSingleWildcardPosition)
        );
        for ok in [
            "#",
            "+",
            "sport/#",
            "sport/+/ranking",
            "+/+",
            "/finance",
            "a//b",
        ] {
            assert!(validate_topic_filter(ok).is_ok(), "{ok}");
        }
    }

    #[test]
    fn nul_is_rejected_in_names_and_filters() {
        assert_eq!(
            validate_topic_filter("a/\0"),
            Err(TopicError::InvalidCharacter)
        );
        assert!(!is_valid_topic_name("\0A"));
        assert!(is_valid_topic_name("AB"));
    }

    #[test]
    fn spec_matching_examples() {
        // §4.7.1.2
        assert!(topic_matches_filter(
            "sport/tennis/player1/#",
            "sport/tennis/player1"
        ));
        assert!(topic_matches_filter(
            "sport/tennis/player1/#",
            "sport/tennis/player1/ranking"
        ));
        assert!(topic_matches_filter(
            "sport/tennis/player1/#",
            "sport/tennis/player1/score/wimbledon"
        ));
        assert!(topic_matches_filter("sport/#", "sport"));
        assert!(topic_matches_filter("#", "sport/tennis"));
        // §4.7.1.3
        assert!(topic_matches_filter(
            "sport/tennis/+",
            "sport/tennis/player1"
        ));
        assert!(!topic_matches_filter(
            "sport/tennis/+",
            "sport/tennis/player1/ranking"
        ));
        assert!(!topic_matches_filter("sport/+", "sport"));
        assert!(topic_matches_filter("sport/+", "sport/"));
        assert!(topic_matches_filter("+/+", "/finance"));
        assert!(topic_matches_filter("/+", "/finance"));
        assert!(!topic_matches_filter("+", "/finance"));
        // §4.7.2
        assert!(!topic_matches_filter("#", "$SYS/broker"));
        assert!(!topic_matches_filter(
            "+/monitor/Clients",
            "$SYS/monitor/Clients"
        ));
        assert!(topic_matches_filter("$SYS/#", "$SYS/monitor/Clients"));
        assert!(topic_matches_filter(
            "$SYS/monitor/+",
            "$SYS/monitor/Clients"
        ));
    }

    #[test]
    fn shared_subscription_parsing() {
        assert_eq!(parse_shared_subscription("a/b"), Ok(None));
        assert_eq!(
            parse_shared_subscription("$share/g1/a/+/c"),
            Ok(Some(("g1", "a/+/c")))
        );
        assert!(parse_shared_subscription("$share/g1").is_err());
        assert!(parse_shared_subscription("$share//a").is_err());
        assert!(parse_shared_subscription("$share/g+/a").is_err());
        assert!(parse_shared_subscription("$share/g/a/#/b").is_err());
    }

    #[test]
    fn coverage_for_acl() {
        assert!(filter_covered_by("#", "a/b/#"));
        assert!(filter_covered_by("a/#", "a"));
        assert!(filter_covered_by("a/#", "a/+/c"));
        assert!(filter_covered_by("a/+/c", "a/b/c"));
        assert!(filter_covered_by("a/+/c", "a/+/c"));
        assert!(!filter_covered_by("a/+/c", "a/#"));
        assert!(!filter_covered_by("a/+", "a/#"));
        assert!(!filter_covered_by("a/b", "a/+"));
        assert!(!filter_covered_by("a/b", "a/b/c"));
        assert!(!filter_covered_by("a/b/c", "a/b"));
        assert!(!filter_covered_by("#", "$SYS/#"));
        assert!(filter_covered_by("$SYS/#", "$SYS/broker/+"));
    }

    #[test]
    fn intersection_for_acl_denies() {
        assert!(filters_intersect("rooms/x/#", "rooms/x/admin/#"));
        assert!(filters_intersect("rooms/x/+", "rooms/x/admin/#"));
        assert!(filters_intersect("a/+", "+/b"));
        assert!(!filters_intersect("a/b", "a/c"));
        assert!(!filters_intersect("a/+", "a/b/c"));
        assert!(filters_intersect("a", "a/#"));
        assert!(!filters_intersect("#", "$SYS/x"));
        assert!(filters_intersect("$SYS/#", "$SYS/x"));
    }
}
