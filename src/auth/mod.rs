use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, warn};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthError {
    #[error("Authentication failed: invalid username or password")]
    BadCredentials,
    #[error("Authentication failed: user '{0}' not found")]
    UserNotFound(String),
    #[error("Authentication failed: anonymous connections are disabled")]
    AnonymousNotAllowed,
    #[error("Access denied: client '{client_id}' is not authorized on topic '{topic}'")]
    AccessDenied { client_id: String, topic: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    Read,
    Write,
    ReadWrite,
    Deny,
}

impl Permission {
    pub fn can_read(&self) -> bool {
        matches!(self, Permission::Read | Permission::ReadWrite)
    }

    pub fn can_write(&self) -> bool {
        matches!(self, Permission::Write | Permission::ReadWrite)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserRole {
    Admin,
    Moderator,
    Member,
    Viewer,
    Device,
    Custom(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AclRule {
    pub pattern: String,
    pub permission: Permission,
}

impl AclRule {
    pub fn new(pattern: impl Into<String>, permission: Permission) -> Self {
        Self {
            pattern: pattern.into(),
            permission,
        }
    }

    /// Evaluates whether the rule pattern matches the candidate topic.
    /// Supports `%u` (username), `%c` (client_id), `%r` (room_id), and MQTT wildcards (`+`, `#`).
    pub fn matches_topic(&self, user: &UserAccount, client_id: &str, topic: &str) -> bool {
        // If pattern contains %r, evaluate against all allowed rooms for this user
        if self.pattern.contains("%r") {
            if user.role == UserRole::Admin || user.allowed_rooms.iter().any(|r| r == "*") {
                // Admin or global room user: replace %r with '+' to match any single room segment
                let expanded = self
                    .pattern
                    .replace("%u", &user.username)
                    .replace("%c", client_id)
                    .replace("%r", "+");
                return mqtt_topic_match(&expanded, topic);
            }

            for room in &user.allowed_rooms {
                let expanded = self
                    .pattern
                    .replace("%u", &user.username)
                    .replace("%c", client_id)
                    .replace("%r", room);
                if mqtt_topic_match(&expanded, topic) {
                    return true;
                }
            }
            return false;
        }

        let expanded = self
            .pattern
            .replace("%u", &user.username)
            .replace("%c", client_id);
        mqtt_topic_match(&expanded, topic)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserAccount {
    pub username: String,
    pub password_hash: String,
    pub role: UserRole,
    pub allowed_rooms: Vec<String>,
    pub custom_rules: Vec<AclRule>,
}

impl UserAccount {
    /// Computes SHA-256 hexadecimal digest of input password.
    pub fn hash_password(password: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(password);
        let result = hasher.finalize();
        result.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Creates a Superuser Administrator account with unrestricted access across all topics.
    pub fn new_admin(username: impl Into<String>, password: &str) -> Self {
        Self {
            username: username.into(),
            password_hash: Self::hash_password(password.as_bytes()),
            role: UserRole::Admin,
            allowed_rooms: vec!["*".into()],
            custom_rules: vec![
                AclRule::new("#", Permission::ReadWrite),
                AclRule::new("$SYS/#", Permission::Read),
            ],
        }
    }

    /// Creates a Room Moderator account with full management over assigned rooms.
    pub fn new_moderator(
        username: impl Into<String>,
        password: &str,
        allowed_rooms: Vec<String>,
    ) -> Self {
        Self {
            username: username.into(),
            password_hash: Self::hash_password(password.as_bytes()),
            role: UserRole::Moderator,
            allowed_rooms,
            custom_rules: vec![
                AclRule::new("rooms/%r/#", Permission::ReadWrite),
                AclRule::new("users/%u/#", Permission::ReadWrite),
            ],
        }
    }

    /// Creates a standard Room Member account (can chat & share presence in assigned rooms).
    pub fn new_member(
        username: impl Into<String>,
        password: &str,
        allowed_rooms: Vec<String>,
    ) -> Self {
        Self {
            username: username.into(),
            password_hash: Self::hash_password(password.as_bytes()),
            role: UserRole::Member,
            allowed_rooms,
            custom_rules: vec![
                AclRule::new("rooms/%r/chat", Permission::ReadWrite),
                AclRule::new("rooms/%r/presence", Permission::ReadWrite),
                AclRule::new("rooms/%r/announcements", Permission::Read), // Read-only
                AclRule::new("rooms/%r/admin/#", Permission::Deny),       // Explicit deny
                AclRule::new("users/%u/private", Permission::ReadWrite),
            ],
        }
    }

    /// Creates a read-only Room Viewer account (can read chat and announcements, cannot publish).
    pub fn new_viewer(
        username: impl Into<String>,
        password: &str,
        allowed_rooms: Vec<String>,
    ) -> Self {
        Self {
            username: username.into(),
            password_hash: Self::hash_password(password.as_bytes()),
            role: UserRole::Viewer,
            allowed_rooms,
            custom_rules: vec![
                AclRule::new("rooms/%r/chat", Permission::Read),
                AclRule::new("rooms/%r/announcements", Permission::Read),
                AclRule::new("rooms/%r/#", Permission::Deny), // Deny everything else in room
            ],
        }
    }

    /// Creates an IoT Device account strictly scoped to its own ClientID topic.
    pub fn new_device(client_id: impl Into<String>, secret_token: &str) -> Self {
        let cid = client_id.into();
        Self {
            username: cid.clone(),
            password_hash: Self::hash_password(secret_token.as_bytes()),
            role: UserRole::Device,
            allowed_rooms: Vec::new(),
            custom_rules: vec![
                AclRule::new("devices/%c/telemetry", Permission::Write),
                AclRule::new("devices/%c/commands", Permission::Read),
                AclRule::new("#", Permission::Deny), // Cannot access rooms or other devices
            ],
        }
    }

    /// Computes Argon2id PHC string of input password using random salt.
    pub fn hash_password_argon2(password: &[u8]) -> Result<String, String> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        argon2
            .hash_password(password, &salt)
            .map(|h| h.to_string())
            .map_err(|e| e.to_string())
    }

    /// Verifies provided candidate password against the stored credential.
    /// Supports Argon2id, SHA-256 hashed, and raw string comparison.
    pub fn verify_password(&self, candidate: &[u8]) -> bool {
        if self.password_hash.starts_with("$argon2") {
            if let Ok(parsed_hash) = PasswordHash::new(&self.password_hash) {
                return Argon2::default().verify_password(candidate, &parsed_hash).is_ok();
            }
        }

        let candidate_hash = Self::hash_password(candidate);
        if candidate_hash == self.password_hash {
            return true;
        }
        if let Ok(raw_str) = std::str::from_utf8(candidate) {
            if raw_str == self.password_hash {
                return true;
            }
        }
        false
    }

    pub fn can_access_room(&self, room_id: &str) -> bool {
        if self.role == UserRole::Admin {
            return true;
        }
        self.allowed_rooms.iter().any(|r| r == "*" || r == room_id)
    }
}

pub struct AclEngine {
    users: Arc<RwLock<HashMap<String, UserAccount>>>,
    allow_anonymous: bool,
    default_rules: Vec<AclRule>,
}

impl Default for AclEngine {
    fn default() -> Self {
        Self::new(true)
    }
}

impl AclEngine {
    pub fn new(allow_anonymous: bool) -> Self {
        Self {
            users: Arc::new(RwLock::new(HashMap::new())),
            allow_anonymous,
            default_rules: if allow_anonymous {
                vec![AclRule::new("#", Permission::ReadWrite)]
            } else {
                Vec::new()
            },
        }
    }

    pub fn new_with_rules(allow_anonymous: bool, default_rules: Vec<AclRule>) -> Self {
        Self {
            users: Arc::new(RwLock::new(HashMap::new())),
            allow_anonymous,
            default_rules,
        }
    }

    pub fn with_default_rules(mut self, rules: Vec<AclRule>) -> Self {
        self.default_rules = rules;
        self
    }

    pub async fn add_user(&self, account: UserAccount) {
        let mut guard = self.users.write().await;
        guard.insert(account.username.clone(), account);
    }

    pub async fn remove_user(&self, username: &str) -> bool {
        let mut guard = self.users.write().await;
        guard.remove(username).is_some()
    }

    pub async fn get_user(&self, username: &str) -> Option<UserAccount> {
        let guard = self.users.read().await;
        guard.get(username).cloned()
    }

    /// Authenticates a client connection.
    pub async fn authenticate(
        &self,
        username: Option<&str>,
        password: Option<&[u8]>,
        client_id: &str,
    ) -> Result<UserAccount, AuthError> {
        match username {
            Some(u) => {
                let guard = self.users.read().await;
                if let Some(user) = guard.get(u) {
                    let pass_bytes = password.unwrap_or(b"");
                    if user.verify_password(pass_bytes) {
                        debug!(
                            "User '{}' authenticated successfully (role: {:?})",
                            u, user.role
                        );
                        Ok(user.clone())
                    } else {
                        warn!("Authentication failed for user '{}': invalid password", u);
                        Err(AuthError::BadCredentials)
                    }
                } else {
                    warn!("Authentication failed: user '{}' does not exist", u);
                    Err(AuthError::UserNotFound(u.to_string()))
                }
            }
            None => {
                if self.allow_anonymous {
                    debug!("Anonymous connection accepted for client '{}'", client_id);
                    Ok(UserAccount {
                        username: "anonymous".into(),
                        password_hash: String::new(),
                        role: UserRole::Custom("anonymous".into()),
                        allowed_rooms: Vec::new(),
                        custom_rules: self.default_rules.clone(),
                    })
                } else {
                    warn!("Anonymous connection rejected for client '{}'", client_id);
                    Err(AuthError::AnonymousNotAllowed)
                }
            }
        }
    }

    /// Validates whether a client is authorized to PUBLISH to a given topic.
    pub fn check_publish(&self, user: &UserAccount, client_id: &str, topic: &str) -> bool {
        if user.role == UserRole::Admin {
            return true;
        }

        // 1. Check custom user rules (first match takes precedence; Deny explicitly overrides)
        for rule in &user.custom_rules {
            if rule.matches_topic(user, client_id, topic) {
                if rule.permission == Permission::Deny {
                    debug!(
                        "Publish denied by explicit Deny rule: '{}' on '{}'",
                        user.username, topic
                    );
                    return false;
                }
                if rule.permission.can_write() {
                    return true;
                }
            }
        }

        // 2. Check fallback default rules
        for rule in &self.default_rules {
            if rule.matches_topic(user, client_id, topic) {
                if rule.permission == Permission::Deny {
                    return false;
                }
                if rule.permission.can_write() {
                    return true;
                }
            }
        }

        debug!(
            "Publish denied (no matching rule): '{}' on '{}'",
            user.username, topic
        );
        false
    }

    /// Validates whether a client is authorized to SUBSCRIBE to a given topic filter.
    pub fn check_subscribe(&self, user: &UserAccount, client_id: &str, topic_filter: &str) -> bool {
        if user.role == UserRole::Admin {
            return true;
        }

        // 1. Check custom user rules
        for rule in &user.custom_rules {
            if rule.matches_topic(user, client_id, topic_filter) {
                if rule.permission == Permission::Deny {
                    debug!(
                        "Subscribe denied by explicit Deny rule: '{}' on '{}'",
                        user.username, topic_filter
                    );
                    return false;
                }
                if rule.permission.can_read() {
                    return true;
                }
            }
        }

        // 2. Check fallback default rules
        for rule in &self.default_rules {
            if rule.matches_topic(user, client_id, topic_filter) {
                if rule.permission == Permission::Deny {
                    return false;
                }
                if rule.permission.can_read() {
                    return true;
                }
            }
        }

        debug!(
            "Subscribe denied (no matching rule): '{}' on '{}'",
            user.username, topic_filter
        );
        false
    }

    /// Parses an ACL file and loads user credentials, roles, room memberships, and pattern rules.
    pub async fn load_from_acl_file<P: AsRef<Path>>(&self, path: P) -> Result<(), std::io::Error> {
        let content = fs::read_to_string(path)?;
        let mut current_user: Option<UserAccount> = None;

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }

            match parts[0] {
                "user" if parts.len() >= 2 => {
                    if let Some(user) = current_user.take() {
                        self.add_user(user).await;
                    }

                    let username = parts[1].to_string();
                    let mut password_hash = String::new();
                    let mut role = UserRole::Member;
                    let mut rooms = Vec::new();

                    for &arg in &parts[2..] {
                        if let Some(pass) = arg.strip_prefix("password:") {
                            password_hash = UserAccount::hash_password(pass.as_bytes());
                        } else if let Some(hash) = arg.strip_prefix("password_hash:") {
                            password_hash = hash.to_string();
                        } else if let Some(r_str) = arg.strip_prefix("role:") {
                            role = match r_str.to_lowercase().as_str() {
                                "admin" => UserRole::Admin,
                                "moderator" => UserRole::Moderator,
                                "member" => UserRole::Member,
                                "viewer" => UserRole::Viewer,
                                "device" => UserRole::Device,
                                custom => UserRole::Custom(custom.to_string()),
                            };
                        } else if let Some(rooms_str) = arg.strip_prefix("rooms:") {
                            rooms = rooms_str.split(',').map(|s| s.trim().to_string()).collect();
                        }
                    }

                    let mut account = match role {
                        UserRole::Admin => UserAccount::new_admin(&username, ""),
                        UserRole::Moderator => UserAccount::new_moderator(&username, "", rooms),
                        UserRole::Member => UserAccount::new_member(&username, "", rooms),
                        UserRole::Viewer => UserAccount::new_viewer(&username, "", rooms),
                        UserRole::Device => UserAccount::new_device(&username, ""),
                        UserRole::Custom(_) => UserAccount {
                            username: username.clone(),
                            password_hash: password_hash.clone(),
                            role,
                            allowed_rooms: rooms,
                            custom_rules: Vec::new(),
                        },
                    };
                    if !password_hash.is_empty() {
                        account.password_hash = password_hash;
                    }
                    current_user = Some(account);
                }
                "topic" | "pattern" if parts.len() >= 3 => {
                    let perm = match parts[1].to_lowercase().as_str() {
                        "read" => Permission::Read,
                        "write" => Permission::Write,
                        "readwrite" => Permission::ReadWrite,
                        "deny" => Permission::Deny,
                        _ => Permission::Read,
                    };
                    let pattern = parts[2].to_string();
                    let rule = AclRule::new(pattern, perm);

                    if let Some(ref mut user) = current_user {
                        user.custom_rules.push(rule);
                    }
                }
                _ => {}
            }
        }

        if let Some(user) = current_user {
            self.add_user(user).await;
        }

        Ok(())
    }
}

/// Helper utilities for room-scoped topic management.
pub struct RoomManager;

impl RoomManager {
    pub fn chat_topic(room: &str) -> String {
        format!("rooms/{room}/chat")
    }

    pub fn presence_topic(room: &str) -> String {
        format!("rooms/{room}/presence")
    }

    pub fn announcements_topic(room: &str) -> String {
        format!("rooms/{room}/announcements")
    }

    pub fn admin_topic(room: &str) -> String {
        format!("rooms/{room}/admin/control")
    }

    pub fn extract_room(topic: &str) -> Option<&str> {
        let parts: Vec<&str> = topic.split('/').collect();
        if parts.len() >= 3 && parts[0] == "rooms" {
            Some(parts[1])
        } else {
            None
        }
    }
}

/// Evaluates standard MQTT topic wildcard matching.
/// `+` matches single topic level. `#` matches all remaining levels.
pub fn mqtt_topic_match(pattern: &str, candidate: &str) -> bool {
    let p_segments: Vec<&str> = pattern.split('/').collect();
    let c_segments: Vec<&str> = candidate.split('/').collect();

    let mut p_idx = 0;
    let mut c_idx = 0;

    while p_idx < p_segments.len() && c_idx < c_segments.len() {
        match p_segments[p_idx] {
            "#" => return true,
            "+" => {
                p_idx += 1;
                c_idx += 1;
            }
            exact => {
                if exact != c_segments[c_idx] {
                    return false;
                }
                p_idx += 1;
                c_idx += 1;
            }
        }
    }

    if p_idx < p_segments.len() && p_segments[p_idx] == "#" {
        return true;
    }

    p_idx == p_segments.len() && c_idx == c_segments.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_topic_matcher() {
        assert!(mqtt_topic_match("rooms/+/chat", "rooms/living_room/chat"));
        assert!(!mqtt_topic_match(
            "rooms/+/chat",
            "rooms/living_room/presence"
        ));
        assert!(mqtt_topic_match("rooms/#", "rooms/a/b/c"));
        assert!(mqtt_topic_match("devices/%c/data", "devices/%c/data"));
    }

    #[tokio::test]
    async fn test_room_based_credentials_and_permissions() {
        let engine = AclEngine::new(false);

        // 1. Admin
        let admin = UserAccount::new_admin("alice_admin", "admin_secret");
        engine.add_user(admin.clone()).await;

        // 2. Moderator for Room A & Room B
        let mod_user = UserAccount::new_moderator(
            "bob_mod",
            "mod_secret",
            vec!["room_alpha".into(), "room_beta".into()],
        );
        engine.add_user(mod_user.clone()).await;

        // 3. Member for Room A only
        let member =
            UserAccount::new_member("charlie_member", "member_secret", vec!["room_alpha".into()]);
        engine.add_user(member.clone()).await;

        // 4. Viewer for Room A only
        let viewer =
            UserAccount::new_viewer("dave_viewer", "viewer_secret", vec!["room_alpha".into()]);
        engine.add_user(viewer.clone()).await;

        // 5. Device
        let device = UserAccount::new_device("sensor_101", "dev_secret");
        engine.add_user(device.clone()).await;

        // --- Authentication Verification ---
        assert!(engine
            .authenticate(Some("alice_admin"), Some(b"admin_secret"), "c1")
            .await
            .is_ok());
        assert!(engine
            .authenticate(Some("alice_admin"), Some(b"wrong_pass"), "c1")
            .await
            .is_err());
        assert!(engine.authenticate(None, None, "c1").await.is_err()); // Anon disabled

        // --- Room A Chat (Member vs Viewer vs Cross-Room) ---
        // Member can publish and subscribe in Room Alpha
        assert!(engine.check_publish(&member, "c_charlie", "rooms/room_alpha/chat"));
        assert!(engine.check_subscribe(&member, "c_charlie", "rooms/room_alpha/chat"));

        // Viewer can SUBSCRIBE to Room Alpha chat, but CANNOT PUBLISH!
        assert!(engine.check_subscribe(&viewer, "c_dave", "rooms/room_alpha/chat"));
        assert!(!engine.check_publish(&viewer, "c_dave", "rooms/room_alpha/chat"));

        // Member cannot publish or subscribe to Room Beta (Room Isolation!)
        assert!(!engine.check_publish(&member, "c_charlie", "rooms/room_beta/chat"));
        assert!(!engine.check_subscribe(&member, "c_charlie", "rooms/room_beta/chat"));

        // Moderator can publish and subscribe to both Room Alpha and Beta
        assert!(engine.check_publish(&mod_user, "c_bob", "rooms/room_alpha/chat"));
        assert!(engine.check_publish(&mod_user, "c_bob", "rooms/room_beta/chat"));

        // Member is DENIED from Room Alpha admin topics
        assert!(!engine.check_publish(&member, "c_charlie", "rooms/room_alpha/admin/secret"));
        assert!(!engine.check_subscribe(&member, "c_charlie", "rooms/room_alpha/admin/secret"));

        // Moderator CAN access Room Alpha admin topics
        assert!(engine.check_publish(&mod_user, "c_bob", "rooms/room_alpha/admin/secret"));

        // --- Device Isolation ---
        // Device can publish its own telemetry
        assert!(engine.check_publish(&device, "sensor_101", "devices/sensor_101/telemetry"));
        // Device cannot publish to another device's telemetry
        assert!(!engine.check_publish(&device, "sensor_101", "devices/sensor_999/telemetry"));
        // Device cannot access human rooms
        assert!(!engine.check_publish(&device, "sensor_101", "rooms/room_alpha/chat"));
        assert!(!engine.check_subscribe(&device, "sensor_101", "rooms/room_alpha/chat"));

        // Admin has universal access
        assert!(engine.check_publish(&admin, "c_alice", "rooms/room_alpha/chat"));
        assert!(engine.check_publish(&admin, "c_alice", "rooms/room_beta/chat"));
        assert!(engine.check_publish(&admin, "c_alice", "$SYS/broker/uptime"));
    }

    #[test]
    fn test_argon2id_password_hashing() {
        let password = b"complex_secret_passphrase_42!";
        let argon2_hash = UserAccount::hash_password_argon2(password).unwrap();
        assert!(argon2_hash.starts_with("$argon2id$"));

        let account = UserAccount {
            username: "sec_user".into(),
            password_hash: argon2_hash,
            role: UserRole::Member,
            allowed_rooms: vec!["lobby".into()],
            custom_rules: Vec::new(),
        };

        // Correct password verifies successfully
        assert!(account.verify_password(password));
        // Wrong password fails
        assert!(!account.verify_password(b"wrong_passphrase"));
    }
}
