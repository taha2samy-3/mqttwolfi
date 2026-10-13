//! Authentication (Argon2id / legacy SHA-256 credentials) and topic authorization (ACL / RBAC).
//!
//! # Rule evaluation
//!
//! Every identity has an ordered rule list: the rules declared for the user in the ACL file come
//! first (in file order), followed by the defaults of the user's role. The **first matching rule
//! wins**, like firewall rules: put specific `deny` rules before broader allow rules.
//!
//! * PUBLISH to a topic is allowed by the first rule whose pattern matches the topic.
//!   A matching `deny` rule stops evaluation; a rule that lacks write permission is skipped.
//! * SUBSCRIBE to a filter is allowed by the first rule whose pattern *covers* the whole filter
//!   (every topic the filter can match is matched by the pattern). Any `deny` rule that merely
//!   *overlaps* the filter, and comes earlier, rejects the subscription. This guarantees that a
//!   granted subscription never delivers a message a rule would deny.
//!
//! Anonymous clients (allowed only with `allow_anonymous = true`) use the `anonymous` account
//! from the ACL file if one is declared, otherwise the engine's default rules.

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::{Arc, OnceLock, RwLock};
use thiserror::Error;
use tokio::sync::Semaphore;
use tracing::{debug, warn};

use crate::routing::topic::{filter_covered_by, filters_intersect, topic_matches_filter};

/// Name of the identity used for clients that connect without a user name.
pub const ANONYMOUS_USER: &str = "anonymous";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthError {
    #[error("authentication failed: invalid username or password")]
    BadCredentials,
    #[error("authentication failed: anonymous connections are disabled")]
    AnonymousNotAllowed,
    #[error("authentication failed: client identifier does not match the device account")]
    ClientIdMismatch,
}

#[derive(Debug, Error)]
pub enum AclFileError {
    #[error("failed to read ACL file: {0}")]
    Io(#[from] std::io::Error),
    #[error("ACL file line {line}: {message}")]
    Syntax { line: usize, message: String },
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

impl UserRole {
    /// Built-in rules applied after the user's own rules.
    fn default_rules(&self) -> &'static [(&'static str, Permission)] {
        match self {
            UserRole::Admin | UserRole::Custom(_) => &[],
            UserRole::Moderator => &[
                ("rooms/%r/#", Permission::ReadWrite),
                ("users/%u/#", Permission::ReadWrite),
            ],
            UserRole::Member => &[
                ("rooms/%r/admin/#", Permission::Deny),
                ("rooms/%r/chat", Permission::ReadWrite),
                ("rooms/%r/presence", Permission::ReadWrite),
                ("rooms/%r/announcements", Permission::Read),
                ("users/%u/private", Permission::ReadWrite),
            ],
            UserRole::Viewer => &[
                ("rooms/%r/chat", Permission::Read),
                ("rooms/%r/announcements", Permission::Read),
                ("rooms/%r/#", Permission::Deny),
            ],
            UserRole::Device => &[
                ("devices/%c/telemetry", Permission::Write),
                ("devices/%c/commands", Permission::Read),
                ("#", Permission::Deny),
            ],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AclRule {
    pub pattern: String,
    pub permission: Permission,
}

/// A substitution value is unusable when it could inject wildcards, extra topic levels or
/// another macro.
fn safe_substitution(value: &str) -> bool {
    !value.is_empty() && !value.contains(['+', '#', '/', '%', '\0'])
}

/// A rule pattern with its macros substituted for one client.
enum Expanded {
    Patterns(Vec<String>),
    /// The user name or ClientID cannot be substituted safely.
    Unsafe,
}

impl AclRule {
    pub fn new(pattern: impl Into<String>, permission: Permission) -> Self {
        Self {
            pattern: pattern.into(),
            permission,
        }
    }

    /// Expands `%u`, `%c` and `%r` into the concrete patterns this rule stands for, in a single
    /// pass over the pattern: substituted text is never scanned for macros again.
    fn expand(&self, user: &UserAccount, client_id: &str) -> Expanded {
        let any_room = user.role == UserRole::Admin || user.allowed_rooms.iter().any(|r| r == "*");
        let mut out = vec![String::new()];
        let mut rest = self.pattern.as_str();
        while let Some(pos) = rest.find('%') {
            let (literal, tail) = rest.split_at(pos);
            out.iter_mut().for_each(|p| p.push_str(literal));
            let value: Option<&str> = match tail.as_bytes().get(1) {
                Some(b'u') => Some(&user.username),
                Some(b'c') => Some(client_id),
                Some(b'r') => {
                    if any_room {
                        out.iter_mut().for_each(|p| p.push('+'));
                    } else {
                        // Room names come from the ACL file; unusable ones are skipped.
                        let rooms: Vec<&String> = user
                            .allowed_rooms
                            .iter()
                            .filter(|r| safe_substitution(r))
                            .collect();
                        out = out
                            .iter()
                            .flat_map(|p| rooms.iter().map(move |r| format!("{p}{r}")))
                            .collect();
                    }
                    rest = &tail[2..];
                    continue;
                }
                _ => {
                    out.iter_mut().for_each(|p| p.push('%'));
                    rest = &tail[1..];
                    continue;
                }
            };
            let value = value.unwrap_or_default();
            if !safe_substitution(value) {
                return Expanded::Unsafe;
            }
            out.iter_mut().for_each(|p| p.push_str(value));
            rest = &tail[2..];
        }
        out.iter_mut().for_each(|p| p.push_str(rest));
        Expanded::Patterns(out)
    }

    /// Applies `test` to the expanded patterns. A user name or ClientID that cannot be
    /// substituted safely makes a deny rule apply (fail closed) and an allow rule not apply.
    fn applies(&self, user: &UserAccount, client_id: &str, test: impl Fn(&str) -> bool) -> bool {
        match self.expand(user, client_id) {
            Expanded::Patterns(patterns) => patterns.iter().any(|p| test(p)),
            Expanded::Unsafe => self.permission == Permission::Deny,
        }
    }

    /// Returns true when the (expanded) rule pattern matches a concrete topic name.
    pub fn matches_topic(&self, user: &UserAccount, client_id: &str, topic: &str) -> bool {
        self.applies(user, client_id, |p| topic_matches_filter(p, topic))
    }

    fn covers_filter(&self, user: &UserAccount, client_id: &str, filter: &str) -> bool {
        self.applies(user, client_id, |p| filter_covered_by(p, filter))
    }

    fn overlaps_filter(&self, user: &UserAccount, client_id: &str, filter: &str) -> bool {
        self.applies(user, client_id, |p| filters_intersect(p, filter))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserAccount {
    pub username: String,
    /// `$argon2id$...` PHC string or a 64-character lowercase SHA-256 hex digest.
    pub password_hash: String,
    pub role: UserRole,
    pub allowed_rooms: Vec<String>,
    /// Rules declared for this user; evaluated before the role defaults.
    pub custom_rules: Vec<AclRule>,
}

/// Constant-time comparison so the legacy SHA-256 path does not leak matching prefixes.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

impl UserAccount {
    fn with_role(
        username: impl Into<String>,
        password: &str,
        role: UserRole,
        rooms: Vec<String>,
    ) -> Self {
        Self {
            username: username.into(),
            password_hash: Self::hash_password_secure(password.as_bytes()),
            role,
            allowed_rooms: rooms,
            custom_rules: Vec::new(),
        }
    }

    /// Computes the legacy unsalted SHA-256 hexadecimal digest. Prefer Argon2id.
    pub fn hash_password(password: &[u8]) -> String {
        Sha256::digest(password)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// Computes an Argon2id PHC string with a random salt. Empty passwords yield an empty hash
    /// (an account that can never authenticate).
    pub fn hash_password_secure(password: &[u8]) -> String {
        if password.is_empty() {
            return String::new();
        }
        Self::hash_password_argon2(password).unwrap_or_default()
    }

    /// Computes an Argon2id PHC string of the password using a random salt.
    pub fn hash_password_argon2(password: &[u8]) -> Result<String, String> {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(password, &salt)
            .map(|h| h.to_string())
            .map_err(|e| e.to_string())
    }

    /// Superuser with unrestricted access (ACL checks are bypassed).
    pub fn new_admin(username: impl Into<String>, password: &str) -> Self {
        Self::with_role(username, password, UserRole::Admin, vec!["*".into()])
    }

    /// Room moderator: full access to `rooms/%r/#` and `users/%u/#`.
    pub fn new_moderator(username: impl Into<String>, password: &str, rooms: Vec<String>) -> Self {
        Self::with_role(username, password, UserRole::Moderator, rooms)
    }

    /// Room member: chat and presence, read-only announcements, no `rooms/%r/admin/#`.
    pub fn new_member(username: impl Into<String>, password: &str, rooms: Vec<String>) -> Self {
        Self::with_role(username, password, UserRole::Member, rooms)
    }

    /// Read-only room observer.
    pub fn new_viewer(username: impl Into<String>, password: &str, rooms: Vec<String>) -> Self {
        Self::with_role(username, password, UserRole::Viewer, rooms)
    }

    /// IoT device; its user name must equal the MQTT client identifier.
    pub fn new_device(client_id: impl Into<String>, secret_token: &str) -> Self {
        Self::with_role(client_id, secret_token, UserRole::Device, Vec::new())
    }

    /// Account with only explicit rules.
    pub fn new_custom(username: impl Into<String>, password: &str, rules: Vec<AclRule>) -> Self {
        let mut account = Self::with_role(
            username,
            password,
            UserRole::Custom("custom".into()),
            Vec::new(),
        );
        account.custom_rules = rules;
        account
    }

    /// Verifies a candidate password against the stored Argon2id or SHA-256 credential.
    pub fn verify_password(&self, candidate: &[u8]) -> bool {
        if self.password_hash.is_empty() || candidate.is_empty() {
            return false;
        }
        if self.password_hash.starts_with("$argon2") {
            return PasswordHash::new(&self.password_hash)
                .map(|parsed| {
                    Argon2::default()
                        .verify_password(candidate, &parsed)
                        .is_ok()
                })
                .unwrap_or(false);
        }
        constant_time_eq(
            Self::hash_password(candidate).as_bytes(),
            self.password_hash.as_bytes(),
        )
    }

    pub fn can_access_room(&self, room_id: &str) -> bool {
        self.role == UserRole::Admin || self.allowed_rooms.iter().any(|r| r == "*" || r == room_id)
    }

    /// The full ordered rule list: explicit rules, then role defaults.
    fn effective_rules(&self) -> impl Iterator<Item = AclRule> + '_ {
        self.custom_rules.iter().cloned().chain(
            self.role
                .default_rules()
                .iter()
                .map(|(p, perm)| AclRule::new(*p, *perm)),
        )
    }
}

/// A real Argon2id hash (default parameters) used to equalize the cost of rejecting unknown users.
fn dummy_hash() -> &'static str {
    static DUMMY: OnceLock<String> = OnceLock::new();
    DUMMY.get_or_init(|| {
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        UserAccount::hash_password_argon2(&secret).unwrap_or_default()
    })
}

/// Runs one Argon2 verification against [`dummy_hash`] (only for its cost).
fn verify_dummy(candidate: &[u8]) -> bool {
    PasswordHash::new(dummy_hash())
        .map(|parsed| {
            Argon2::default()
                .verify_password(candidate, &parsed)
                .is_ok()
        })
        .unwrap_or(false)
}

pub struct AclEngine {
    users: RwLock<Arc<HashMap<String, Arc<UserAccount>>>>,
    allow_anonymous: bool,
    default_rules: Vec<AclRule>,
    /// Bounds concurrent password verifications (Argon2 is CPU and memory heavy).
    verify_permits: Arc<Semaphore>,
}

impl Default for AclEngine {
    fn default() -> Self {
        Self::new(true)
    }
}

impl AclEngine {
    /// Creates an engine. With `allow_anonymous`, anonymous clients get full read/write access
    /// unless the ACL file declares an `anonymous` user with narrower rules.
    pub fn new(allow_anonymous: bool) -> Self {
        let default_rules = if allow_anonymous {
            vec![AclRule::new("#", Permission::ReadWrite)]
        } else {
            Vec::new()
        };
        Self::new_with_rules(allow_anonymous, default_rules)
    }

    pub fn new_with_rules(allow_anonymous: bool, default_rules: Vec<AclRule>) -> Self {
        let permits = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);
        Self {
            users: RwLock::new(Arc::new(HashMap::new())),
            allow_anonymous,
            default_rules,
            verify_permits: Arc::new(Semaphore::new(permits)),
        }
    }

    pub fn with_default_rules(mut self, rules: Vec<AclRule>) -> Self {
        self.default_rules = rules;
        self
    }

    /// Limits how many password verifications may run at the same time.
    pub fn with_max_concurrent_verifications(mut self, n: usize) -> Self {
        self.verify_permits = Arc::new(Semaphore::new(n.max(1)));
        self
    }

    pub fn allow_anonymous(&self) -> bool {
        self.allow_anonymous
    }

    fn snapshot(&self) -> Arc<HashMap<String, Arc<UserAccount>>> {
        self.users.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub async fn add_user(&self, account: UserAccount) {
        let mut guard = self.users.write().unwrap_or_else(|e| e.into_inner());
        let mut map = (**guard).clone();
        map.insert(account.username.clone(), Arc::new(account));
        *guard = Arc::new(map);
    }

    pub async fn remove_user(&self, username: &str) -> bool {
        let mut guard = self.users.write().unwrap_or_else(|e| e.into_inner());
        let mut map = (**guard).clone();
        let removed = map.remove(username).is_some();
        *guard = Arc::new(map);
        removed
    }

    pub async fn get_user(&self, username: &str) -> Option<Arc<UserAccount>> {
        self.snapshot().get(username).cloned()
    }

    pub fn user_count(&self) -> usize {
        self.snapshot().len()
    }

    /// The current account for `username`, reflecting ACL reloads. The anonymous identity is
    /// resolved as for new connections; an account that no longer exists yields `None`.
    pub fn current_account(&self, username: &str) -> Option<Arc<UserAccount>> {
        if let Some(account) = self.snapshot().get(username) {
            return Some(Arc::clone(account));
        }
        if username == ANONYMOUS_USER {
            return self.anonymous_identity();
        }
        None
    }

    /// The identity used for anonymous clients, if anonymous access is enabled.
    pub fn anonymous_identity(&self) -> Option<Arc<UserAccount>> {
        if !self.allow_anonymous {
            return None;
        }
        if let Some(declared) = self.snapshot().get(ANONYMOUS_USER) {
            return Some(Arc::clone(declared));
        }
        Some(Arc::new(UserAccount {
            username: ANONYMOUS_USER.into(),
            password_hash: String::new(),
            role: UserRole::Custom(ANONYMOUS_USER.into()),
            allowed_rooms: Vec::new(),
            custom_rules: self.default_rules.clone(),
        }))
    }

    /// Authenticates a client connection.
    pub async fn authenticate(
        &self,
        username: Option<&str>,
        password: Option<&[u8]>,
        client_id: &str,
    ) -> Result<Arc<UserAccount>, AuthError> {
        let Some(name) = username else {
            return self.anonymous_identity().ok_or_else(|| {
                warn!("Anonymous connection rejected for client '{}'", client_id);
                AuthError::AnonymousNotAllowed
            });
        };

        let candidate = password.filter(|p| !p.is_empty()).map(<[u8]>::to_vec);
        let user = self.snapshot().get(name).cloned();

        // Always run one full verification, even for unknown users or missing passwords, so the
        // response time does not reveal which user names exist.
        let hash_owner = user.clone().unwrap_or_else(|| {
            Arc::new(UserAccount {
                username: String::new(),
                password_hash: dummy_hash().to_owned(),
                role: UserRole::Custom(String::new()),
                allowed_rooms: Vec::new(),
                custom_rules: Vec::new(),
            })
        });
        let probe = candidate.clone().unwrap_or_else(|| b"\0".to_vec());
        let permit = Arc::clone(&self.verify_permits)
            .acquire_owned()
            .await
            .map_err(|_| AuthError::BadCredentials)?;
        let verified = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let ok = hash_owner.verify_password(&probe);
            if !hash_owner.password_hash.starts_with("$argon2") {
                // Password-less and legacy SHA-256 accounts would answer much faster than
                // Argon2 ones, revealing that the user name exists.
                let _ = verify_dummy(&probe);
            }
            ok
        })
        .await
        .unwrap_or(false);

        let (Some(user), true, Some(_)) = (user, verified, candidate) else {
            warn!(
                "Authentication failed for user '{}' (client '{}')",
                name, client_id
            );
            return Err(AuthError::BadCredentials);
        };

        if user.role == UserRole::Device && user.username != client_id {
            warn!(
                "Device '{}' attempted to connect with mismatched client ID '{}'",
                user.username, client_id
            );
            return Err(AuthError::ClientIdMismatch);
        }

        debug!("User '{}' authenticated (role: {:?})", name, user.role);
        Ok(user)
    }

    /// Returns true when `user` may PUBLISH to the concrete topic name.
    pub fn check_publish(&self, user: &UserAccount, client_id: &str, topic: &str) -> bool {
        if user.role == UserRole::Admin {
            return true;
        }
        for rule in user.effective_rules() {
            if !rule.matches_topic(user, client_id, topic) {
                continue;
            }
            if rule.permission == Permission::Deny {
                debug!(
                    "Publish denied by deny rule '{}' for '{}' on '{}'",
                    rule.pattern, user.username, topic
                );
                return false;
            }
            if rule.permission.can_write() {
                return true;
            }
        }
        debug!(
            "Publish denied (no matching rule) for '{}' on '{}'",
            user.username, topic
        );
        false
    }

    /// Returns true when `user` may receive messages for the concrete topic name.
    pub fn check_read(&self, user: &UserAccount, client_id: &str, topic: &str) -> bool {
        if user.role == UserRole::Admin {
            return true;
        }
        for rule in user.effective_rules() {
            if !rule.matches_topic(user, client_id, topic) {
                continue;
            }
            if rule.permission == Permission::Deny {
                return false;
            }
            if rule.permission.can_read() {
                return true;
            }
        }
        false
    }

    /// Returns true when `user` may SUBSCRIBE to `topic_filter` (see module docs).
    pub fn check_subscribe(&self, user: &UserAccount, client_id: &str, topic_filter: &str) -> bool {
        if user.role == UserRole::Admin {
            return true;
        }
        for rule in user.effective_rules() {
            if rule.permission == Permission::Deny {
                if rule.overlaps_filter(user, client_id, topic_filter) {
                    debug!(
                        "Subscribe denied by deny rule '{}' for '{}' on '{}'",
                        rule.pattern, user.username, topic_filter
                    );
                    return false;
                }
            } else if rule.permission.can_read()
                && rule.covers_filter(user, client_id, topic_filter)
            {
                return true;
            }
        }
        debug!(
            "Subscribe denied (no covering rule) for '{}' on '{}'",
            user.username, topic_filter
        );
        false
    }

    /// Parses ACL file content into accounts without touching the engine.
    pub fn parse_acl(content: &str) -> Result<Vec<UserAccount>, AclFileError> {
        let mut accounts: Vec<UserAccount> = Vec::new();
        for (idx, raw_line) in content.lines().enumerate() {
            let line_no = idx + 1;
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            let syntax = |message: String| AclFileError::Syntax {
                line: line_no,
                message,
            };
            match parts[0] {
                "user" => {
                    let username = parts
                        .get(1)
                        .ok_or_else(|| syntax("'user' requires a user name".into()))?;
                    if accounts.iter().any(|a| a.username == *username) {
                        return Err(syntax(format!("user '{username}' declared twice")));
                    }
                    let mut password_hash = String::new();
                    let mut role = UserRole::Custom("custom".into());
                    let mut rooms = Vec::new();
                    for arg in &parts[2..] {
                        if let Some(pass) = arg.strip_prefix("password:") {
                            warn!(
                                "ACL file line {}: plaintext 'password:' for user '{}'; prefer 'password_hash:' (see --hash-password)",
                                line_no, username
                            );
                            password_hash = UserAccount::hash_password_secure(pass.as_bytes());
                        } else if let Some(hash) = arg.strip_prefix("password_hash:") {
                            let is_argon2 =
                                hash.starts_with("$argon2") && PasswordHash::new(hash).is_ok();
                            let is_sha256 =
                                hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit());
                            password_hash = if is_argon2 {
                                hash.to_string()
                            } else if is_sha256 {
                                hash.to_ascii_lowercase()
                            } else {
                                return Err(syntax(format!(
                                    "invalid password_hash for user '{username}'"
                                )));
                            };
                        } else if let Some(r) = arg.strip_prefix("role:") {
                            role = match r.to_ascii_lowercase().as_str() {
                                "admin" => UserRole::Admin,
                                "moderator" => UserRole::Moderator,
                                "member" => UserRole::Member,
                                "viewer" => UserRole::Viewer,
                                "device" => UserRole::Device,
                                "custom" => UserRole::Custom("custom".into()),
                                other => {
                                    return Err(syntax(format!(
                                        "unknown role '{other}' (expected admin, moderator, member, viewer, device or custom)"
                                    )))
                                }
                            };
                        } else if let Some(list) = arg.strip_prefix("rooms:") {
                            rooms = list
                                .split(',')
                                .map(str::trim)
                                .filter(|s| !s.is_empty())
                                .map(String::from)
                                .collect();
                        } else if arg.starts_with('#') {
                            return Err(syntax(
                                "comments must be on their own line (a '#' after a rule is not a comment)".into(),
                            ));
                        } else {
                            return Err(syntax(format!("unknown user attribute '{arg}'")));
                        }
                    }
                    accounts.push(UserAccount {
                        username: (*username).to_string(),
                        password_hash,
                        role,
                        allowed_rooms: rooms,
                        custom_rules: Vec::new(),
                    });
                }
                "topic" | "pattern" => {
                    if parts.len() > 3 && parts[3].starts_with('#') {
                        return Err(syntax(
                            "comments must be on their own line (a '#' after a rule is not a comment)".into(),
                        ));
                    }
                    if parts.len() != 3 {
                        return Err(syntax(
                            "expected: topic <read|write|readwrite|deny> <pattern>".into(),
                        ));
                    }
                    let permission = match parts[1].to_ascii_lowercase().as_str() {
                        "read" => Permission::Read,
                        "write" => Permission::Write,
                        "readwrite" => Permission::ReadWrite,
                        "deny" => Permission::Deny,
                        other => return Err(syntax(format!("unknown permission '{other}'"))),
                    };
                    let pattern = parts[2];
                    let probe = pattern
                        .replace("%u", "u")
                        .replace("%c", "c")
                        .replace("%r", "r");
                    if crate::routing::topic::validate_topic_filter(&probe).is_err() {
                        return Err(syntax(format!("invalid topic pattern '{pattern}'")));
                    }
                    let account = accounts
                        .last_mut()
                        .ok_or_else(|| syntax("rule appears before any 'user' line".into()))?;
                    account.custom_rules.push(AclRule::new(pattern, permission));
                }
                other => return Err(syntax(format!("unknown directive '{other}'"))),
            }
        }
        Ok(accounts)
    }

    /// Loads an ACL file, atomically replacing all previously loaded accounts.
    pub async fn load_from_acl_file<P: AsRef<Path>>(&self, path: P) -> Result<usize, AclFileError> {
        let content = fs::read_to_string(path)?;
        let accounts = Self::parse_acl(&content)?;
        let count = accounts.len();
        let map: HashMap<String, Arc<UserAccount>> = accounts
            .into_iter()
            .map(|a| (a.username.clone(), Arc::new(a)))
            .collect();
        *self.users.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(map);
        Ok(count)
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
        let mut parts = topic.split('/');
        match (parts.next(), parts.next(), parts.next()) {
            (Some("rooms"), Some(room), Some(_)) => Some(room),
            _ => None,
        }
    }
}

/// Standard MQTT topic matching (kept for API compatibility; see [`topic_matches_filter`]).
pub fn mqtt_topic_match(pattern: &str, candidate: &str) -> bool {
    topic_matches_filter(pattern, candidate)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rooms(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[tokio::test]
    async fn authentication_paths() {
        let engine = AclEngine::new(false);
        engine
            .add_user(UserAccount::new_admin("alice", "admin_secret"))
            .await;
        engine
            .add_user(UserAccount::new_device("sensor_101", "dev_secret"))
            .await;

        assert!(engine
            .authenticate(Some("alice"), Some(b"admin_secret"), "c1")
            .await
            .is_ok());
        assert_eq!(
            engine
                .authenticate(Some("alice"), Some(b"wrong"), "c1")
                .await,
            Err(AuthError::BadCredentials)
        );
        assert_eq!(
            engine.authenticate(Some("alice"), None, "c1").await,
            Err(AuthError::BadCredentials)
        );
        assert_eq!(
            engine.authenticate(Some("nobody"), Some(b"x"), "c1").await,
            Err(AuthError::BadCredentials)
        );
        assert_eq!(
            engine.authenticate(None, None, "c1").await,
            Err(AuthError::AnonymousNotAllowed)
        );
        assert_eq!(
            engine
                .authenticate(Some("sensor_101"), Some(b"dev_secret"), "other")
                .await,
            Err(AuthError::ClientIdMismatch)
        );
        assert!(engine
            .authenticate(Some("sensor_101"), Some(b"dev_secret"), "sensor_101")
            .await
            .is_ok());
    }

    #[test]
    fn dummy_hash_is_a_valid_argon2_hash() {
        assert!(PasswordHash::new(dummy_hash()).is_ok());
    }

    #[test]
    fn password_hashing() {
        let hash = UserAccount::hash_password_argon2(b"complex_secret_passphrase_42!").unwrap();
        assert!(hash.starts_with("$argon2id$"));
        let mut account = UserAccount::new_custom("u", "x", vec![]);
        account.password_hash = hash;
        assert!(account.verify_password(b"complex_secret_passphrase_42!"));
        assert!(!account.verify_password(b"wrong_passphrase"));
        account.password_hash = UserAccount::hash_password(b"legacy");
        assert!(account.verify_password(b"legacy"));
        assert!(!account.verify_password(b"legacx"));
        assert!(!account.verify_password(b""));
    }

    #[test]
    fn room_roles_and_isolation() {
        let engine = AclEngine::new(false);
        let moderator = UserAccount::new_moderator("bob", "p", rooms(&["alpha", "beta"]));
        let member = UserAccount::new_member("charlie", "p", rooms(&["alpha"]));
        let viewer = UserAccount::new_viewer("dave", "p", rooms(&["alpha"]));
        let device = UserAccount::new_device("sensor_101", "p");
        let admin = UserAccount::new_admin("alice", "p");

        assert!(engine.check_publish(&member, "c", "rooms/alpha/chat"));
        assert!(engine.check_subscribe(&member, "c", "rooms/alpha/chat"));
        assert!(!engine.check_publish(&member, "c", "rooms/alpha/announcements"));
        assert!(engine.check_subscribe(&member, "c", "rooms/alpha/announcements"));
        assert!(!engine.check_publish(&member, "c", "rooms/beta/chat"));
        assert!(!engine.check_subscribe(&member, "c", "rooms/beta/chat"));
        assert!(!engine.check_publish(&member, "c", "rooms/alpha/admin/secret"));
        assert!(!engine.check_subscribe(&member, "c", "rooms/alpha/admin/secret"));
        // A wildcard that would reach the admin subtree is refused as a whole.
        assert!(!engine.check_subscribe(&member, "c", "rooms/alpha/#"));
        assert!(engine.check_publish(&member, "c", "users/charlie/private"));
        assert!(!engine.check_publish(&member, "c", "users/bob/private"));

        assert!(engine.check_subscribe(&viewer, "c", "rooms/alpha/chat"));
        assert!(!engine.check_publish(&viewer, "c", "rooms/alpha/chat"));
        assert!(!engine.check_subscribe(&viewer, "c", "rooms/alpha/#"));

        assert!(engine.check_publish(&moderator, "c", "rooms/alpha/admin/secret"));
        assert!(engine.check_subscribe(&moderator, "c", "rooms/beta/#"));
        assert!(!engine.check_subscribe(&moderator, "c", "rooms/gamma/#"));
        assert!(!engine.check_subscribe(&moderator, "c", "rooms/#"));

        assert!(engine.check_publish(&device, "sensor_101", "devices/sensor_101/telemetry"));
        assert!(!engine.check_publish(&device, "sensor_101", "devices/sensor_999/telemetry"));
        assert!(engine.check_subscribe(&device, "sensor_101", "devices/sensor_101/commands"));
        assert!(!engine.check_subscribe(&device, "sensor_101", "devices/+/commands"));
        assert!(!engine.check_subscribe(&device, "sensor_101", "#"));

        assert!(engine.check_publish(&admin, "c", "anything/at/all"));
    }

    #[test]
    fn wildcard_rule_does_not_grant_broader_wildcard_subscription() {
        let engine = AclEngine::new(false);
        let user = UserAccount::new_custom("u", "p", vec![AclRule::new("a/+", Permission::Read)]);
        assert!(engine.check_subscribe(&user, "c", "a/b"));
        assert!(engine.check_subscribe(&user, "c", "a/+"));
        // Previously '+' in the rule matched the '#' level of the filter.
        assert!(!engine.check_subscribe(&user, "c", "a/#"));
    }

    #[test]
    fn substitution_values_cannot_inject_wildcards() {
        let engine = AclEngine::new(false);
        let rules = vec![
            AclRule::new("users/%u/#", Permission::ReadWrite),
            AclRule::new("clients/%c/data", Permission::ReadWrite),
        ];
        let evil = UserAccount::new_custom("+", "p", rules.clone());
        assert!(!engine.check_subscribe(&evil, "c", "users/+/#"));
        assert!(!engine.check_publish(&evil, "c", "users/bob/x"));
        let user = UserAccount::new_custom("bob", "p", rules);
        assert!(!engine.check_publish(&user, "a/b", "clients/a/b/data"));
        assert!(!engine.check_subscribe(&user, "#", "clients/#/data"));
        assert!(engine.check_publish(&user, "dev1", "clients/dev1/data"));
    }

    #[test]
    fn substituted_values_are_not_expanded_again() {
        let engine = AclEngine::new(false);
        let mut user = UserAccount::new_custom(
            "eve",
            "p",
            vec![AclRule::new("clients/%c/#", Permission::ReadWrite)],
        );
        user.allowed_rooms = rooms(&["*"]);
        // ClientID "%r" must not turn the rule into clients/+/# (every client's namespace).
        assert!(!engine.check_publish(&user, "%r", "clients/victim/cmd"));
        assert!(!engine.check_subscribe(&user, "%r", "clients/+/#"));
        assert!(!engine.check_publish(&user, "%r", "clients/%r/x"));
        assert!(engine.check_publish(&user, "eve-1", "clients/eve-1/x"));
        // A literal '%' not followed by a macro letter stays as it is.
        let pct = UserAccount::new_custom(
            "p",
            "p",
            vec![AclRule::new("rate/100%/%u", Permission::ReadWrite)],
        );
        assert!(engine.check_publish(&pct, "c", "rate/100%/p"));
    }

    #[test]
    fn deny_rules_fail_closed_on_unsafe_substitutions() {
        let engine = AclEngine::new(false);
        let user = UserAccount::new_custom(
            "bob",
            "p",
            vec![
                AclRule::new("plant/%c/secrets/#", Permission::Deny),
                AclRule::new("plant/#", Permission::ReadWrite),
            ],
        );
        assert!(engine.check_publish(&user, "line1", "plant/line2/secrets/x"));
        assert!(!engine.check_publish(&user, "line1", "plant/line1/secrets/x"));
        // A ClientID with '/' cannot be substituted: the deny rule applies instead of vanishing.
        assert!(!engine.check_publish(&user, "plant/line1", "plant/line1/secrets/x"));
        assert!(!engine.check_read(&user, "a/b", "plant/x"));
        assert!(!engine.check_subscribe(&user, "a/b", "plant/#"));
    }

    #[tokio::test]
    async fn anonymous_fallback_only_applies_to_anonymous_clients() {
        let engine = AclEngine::new(true);
        let anon = engine.authenticate(None, None, "c").await.unwrap();
        assert!(engine.check_publish(&anon, "c", "any/topic"));
        // An authenticated user without rules gets nothing from the anonymous defaults.
        let user = UserAccount::new_custom("u", "p", vec![]);
        assert!(!engine.check_publish(&user, "c", "any/topic"));
        assert!(!engine.check_subscribe(&user, "c", "#"));
    }

    #[tokio::test]
    async fn declared_anonymous_account_replaces_default_rules() {
        let engine = AclEngine::new(true);
        let accounts = AclEngine::parse_acl("user anonymous\ntopic read public/#\n").unwrap();
        for a in accounts {
            engine.add_user(a).await;
        }
        let anon = engine.authenticate(None, None, "c").await.unwrap();
        assert!(engine.check_subscribe(&anon, "c", "public/news"));
        assert!(!engine.check_publish(&anon, "c", "public/news"));
        assert!(!engine.check_publish(&anon, "c", "private/x"));
    }

    #[test]
    fn file_rules_precede_role_defaults() {
        let content = "user v password:pw role:viewer rooms:ops\ntopic readwrite rooms/%r/notes\n";
        let accounts = AclEngine::parse_acl(content).unwrap();
        let engine = AclEngine::new(false);
        let viewer = &accounts[0];
        // The viewer role denies rooms/%r/# by default, but the explicit rule comes first.
        assert!(engine.check_publish(viewer, "c", "rooms/ops/notes"));
        assert!(!engine.check_publish(viewer, "c", "rooms/ops/chat"));
        assert!(engine.check_subscribe(viewer, "c", "rooms/ops/chat"));
    }

    #[test]
    fn acl_parser_reports_errors_with_line_numbers() {
        let err = AclEngine::parse_acl("topic read a/b\n").unwrap_err();
        assert!(matches!(err, AclFileError::Syntax { line: 1, .. }));
        let err = AclEngine::parse_acl("user a\ntopic maybe a/b\n").unwrap_err();
        assert!(matches!(err, AclFileError::Syntax { line: 2, .. }));
        let err = AclEngine::parse_acl("user a colour:blue\n").unwrap_err();
        assert!(matches!(err, AclFileError::Syntax { line: 1, .. }));
        let err = AclEngine::parse_acl("user a\ntopic read a/#/b\n").unwrap_err();
        assert!(matches!(err, AclFileError::Syntax { line: 2, .. }));
        let err = AclEngine::parse_acl("user a password_hash:nothex\n").unwrap_err();
        assert!(matches!(err, AclFileError::Syntax { line: 1, .. }));
        let err = AclEngine::parse_acl("user a role:admn\n").unwrap_err();
        assert!(err.to_string().contains("unknown role"));
        let err = AclEngine::parse_acl("user a  # trailing comment\n").unwrap_err();
        assert!(err.to_string().contains("own line"));
        let err = AclEngine::parse_acl("user a\ntopic read a/b # why\n").unwrap_err();
        assert!(err.to_string().contains("own line"));
        // `#` as the pattern itself is not a comment.
        assert!(AclEngine::parse_acl("user a role:custom\ntopic deny #\n").is_ok());
    }

    #[test]
    fn shipped_acl_file_parses() {
        let content = std::fs::read_to_string("config/acl.conf").unwrap();
        let accounts = AclEngine::parse_acl(&content).unwrap();
        assert!(accounts.iter().any(|a| a.username == ANONYMOUS_USER));
    }
}
