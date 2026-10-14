//! Broker configuration: TOML file + `WOLFIMQ_*` environment overrides + compiled defaults.
//!
//! Precedence (highest first): environment variables, configuration file, compiled defaults.
//!
//! Any key can be overridden from the environment with `WOLFIMQ_<PATH>`, where `<PATH>` is the
//! TOML key path in upper case with `__` between levels, for example:
//!
//! ```text
//! WOLFIMQ_LISTENERS__TCP__PORT=1884
//! WOLFIMQ_SECURITY__AUTH__ALLOW_ANONYMOUS=true
//! WOLFIMQ_SECURITY__TLS__ALPN_PROTOCOLS='["mqtt", "x-amzn-mqtt-ca"]'
//! ```
//!
//! Values are parsed as TOML literals (booleans, integers, arrays, quoted strings); anything
//! that does not parse is used as a plain string.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use thiserror::Error;

/// Prefix of configuration override environment variables.
pub const ENV_PREFIX: &str = "WOLFIMQ_";
/// Environment variable naming the configuration file (not treated as a key override).
pub const ENV_CONFIG_PATH: &str = "WOLFIMQ_CONFIG";

/// Largest packet size representable on the wire (remaining length limit + 5-byte header).
const MQTT_MAX_PACKET_SIZE: u32 = 268_435_455 + 5;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read configuration file: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse TOML configuration: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("invalid environment override {var}: {message}")]
    Env { var: String, message: String },
    #[error("invalid configuration: {0}")]
    Validation(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct AppConfig {
    pub broker: BrokerSettings,
    pub logging: LoggingConfig,
    pub listeners: ListenersConfig,
    pub security: SecurityConfig,
    pub mqtt: MqttSettings,
    pub monitoring: MonitoringConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct BrokerSettings {
    pub node_id: String,
    /// Maximum simultaneous TCP + TLS connections (0 = unlimited).
    pub max_connections: usize,
    /// Sessions kept by the broker, connected or persisted offline, over all protocols
    /// (0 = unlimited). New sessions beyond it are refused; existing ones can always resume.
    pub max_sessions: usize,
    /// Tokio worker threads (0 = one per CPU core).
    pub worker_threads: usize,
    /// Seconds a new connection may take to complete its CONNECT packet.
    pub connect_timeout_sec: u64,
    /// Seconds to wait for connections to drain on SIGINT / SIGTERM.
    pub shutdown_grace_sec: u64,
}

impl Default for BrokerSettings {
    fn default() -> Self {
        Self {
            node_id: "wolf-broker-node-01".into(),
            max_connections: 100_000,
            max_sessions: 200_000,
            worker_threads: 0,
            connect_timeout_sec: 10,
            shutdown_grace_sec: 5,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct LoggingConfig {
    pub level: String,
    pub format: String,
    pub target: bool,
    pub thread_ids: bool,
    pub line_numbers: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".into(),
            format: "pretty".into(),
            target: true,
            thread_ids: false,
            line_numbers: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct ListenersConfig {
    pub tcp: TcpListenerConfig,
    pub tls: TlsListenerConfig,
    pub ws: WsListenerConfig,
    pub wss: WssListenerConfig,
    pub mqtt_sn: MqttSnListenerConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct TcpListenerConfig {
    pub enabled: bool,
    pub bind_address: String,
    pub port: u16,
}

impl Default for TcpListenerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            bind_address: "127.0.0.1".into(),
            port: 1883,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct TlsListenerConfig {
    pub enabled: bool,
    pub bind_address: String,
    pub port: u16,
}

impl Default for TlsListenerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_address: "0.0.0.0".into(),
            port: 8883,
        }
    }
}

/// MQTT over plain WebSockets. Meant for loopback behind a TLS-terminating reverse proxy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct WsListenerConfig {
    pub enabled: bool,
    pub bind_address: String,
    pub port: u16,
    /// HTTP path accepting MQTT connections.
    pub path: String,
    /// Browser origins allowed to connect (`"*"` = any). Clients that send no Origin header
    /// and same-origin requests are always accepted.
    pub allowed_origins: Vec<String>,
    /// Reverse proxy addresses whose `X-Forwarded-For` header gives the client address.
    pub trusted_proxies: Vec<String>,
    /// Largest HTTP upgrade request (request line and headers) in bytes.
    pub max_header_bytes: usize,
}

impl Default for WsListenerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_address: "127.0.0.1".into(),
            port: 8083,
            path: "/mqtt".into(),
            allowed_origins: Vec::new(),
            trusted_proxies: Vec::new(),
            max_header_bytes: 8192,
        }
    }
}

/// MQTT over WebSockets with wolfSSL TLS. Certificates and TLS settings come from
/// `[security.tls]`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct WssListenerConfig {
    pub enabled: bool,
    pub bind_address: String,
    pub port: u16,
    pub path: String,
    pub allowed_origins: Vec<String>,
    pub trusted_proxies: Vec<String>,
    pub max_header_bytes: usize,
    /// Require client certificates on this listener (browsers usually have none).
    pub require_client_cert: bool,
}

impl Default for WssListenerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_address: "0.0.0.0".into(),
            port: 8084,
            path: "/mqtt".into(),
            allowed_origins: Vec::new(),
            trusted_proxies: Vec::new(),
            max_header_bytes: 8192,
            require_client_cert: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct MqttSnListenerConfig {
    pub enabled: bool,
    pub bind_address: String,
    pub port: u16,
    pub gateway_id: u8,
    /// Seconds between ADVERTISE broadcasts (0 disables them).
    pub advertise_interval_sec: u16,
    /// Destination of ADVERTISE broadcasts (`<address>:<listener port>`).
    pub advertise_address: String,
    /// ACL identity used for MQTT-SN clients (MQTT-SN v1.2 has no credentials). The user must
    /// exist in the ACL file. Empty = the anonymous identity (requires `allow_anonymous`).
    pub acl_user: String,
    /// Maximum MQTT-SN sessions (connected or persisted).
    pub max_sessions: usize,
    /// Accept QoS -1 publishes from clients without a session (§6.8). Such datagrams are
    /// unauthenticated and their source address can be spoofed.
    pub allow_qos_minus1: bool,
    /// Seconds before an unacknowledged QoS 1/2 message is retransmitted (Tretry, §6.13).
    pub retry_interval_sec: u64,
    /// Idle time after which a client that connected with keep-alive 0 is dropped.
    pub max_idle_sec: u64,
    /// Retransmissions before the client is considered lost (Nretry, §6.13).
    pub max_retries: u8,
    pub predefined_topics: HashMap<String, String>,
}

impl Default for MqttSnListenerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_address: "0.0.0.0".into(),
            port: 1884,
            gateway_id: 1,
            advertise_interval_sec: 900,
            advertise_address: "255.255.255.255".into(),
            acl_user: String::new(),
            max_sessions: 10_000,
            allow_qos_minus1: false,
            retry_interval_sec: 10,
            max_idle_sec: 3600,
            max_retries: 3,
            predefined_topics: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct SecurityConfig {
    pub tls: WolfTlsConfig,
    pub auth: AuthConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct WolfTlsConfig {
    pub ca_cert_file: String,
    pub server_cert_file: String,
    pub server_key_file: String,
    /// Mutual TLS: reject clients without a certificate signed by `ca_cert_file`.
    pub require_client_cert: bool,
    /// Require the MQTT ClientID to equal the client certificate's CN or one of its SANs.
    pub verify_client_identity: bool,
    /// PEM certificate revocation list checked against client certificates (mutual TLS only;
    /// empty = no revocation checks). Read at startup.
    pub crl_file: String,
    pub min_tls_version: String,
    /// wolfSSL cipher list (colon or comma separated). Empty = wolfSSL defaults.
    pub ciphers: String,
    pub alpn_protocols: Vec<String>,
    pub handshake_timeout_sec: u64,
}

impl Default for WolfTlsConfig {
    fn default() -> Self {
        Self {
            ca_cert_file: "certs/ca-cert.pem".into(),
            server_cert_file: "certs/server-cert.pem".into(),
            server_key_file: "certs/server-key.pem".into(),
            require_client_cert: true,
            verify_client_identity: false,
            crl_file: String::new(),
            min_tls_version: "TLSv1.3".into(),
            ciphers: String::new(),
            alpn_protocols: vec!["mqtt".into()],
            handshake_timeout_sec: 10,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct AuthConfig {
    pub allow_anonymous: bool,
    /// Algorithm used by `--hash-password`: "argon2id" (recommended) or "sha256" (legacy).
    pub password_hash_algorithm: String,
    pub acl_file: String,
    /// Maximum concurrent password verifications (0 = number of CPU cores).
    pub max_concurrent_auth: usize,
    /// Who may take over a ClientID that is already connected: "same_user" or "any".
    pub client_id_takeover: String,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            allow_anonymous: false,
            password_hash_algorithm: "argon2id".into(),
            acl_file: "config/acl.conf".into(),
            max_concurrent_auth: 0,
            client_id_takeover: "same_user".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct MqttSettings {
    pub protocol: ProtocolSettings,
    pub queues: QueueSettings,
    pub retained: RetainedSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct ProtocolSettings {
    pub allow_v311: bool,
    pub allow_v500: bool,
    /// Largest accepted packet in bytes, fixed header included.
    pub max_packet_size: u32,
    /// Unacknowledged inbound QoS 2 messages allowed per client (MQTT v5.0 Receive Maximum).
    pub receive_maximum: u16,
    /// Topic aliases a v5.0 client may use towards the broker (0 disables them).
    pub topic_alias_maximum: u16,
    /// Upper bound for client keep-alive; v5.0 clients are told via Server Keep Alive (0 = none).
    pub max_keep_alive_sec: u16,
    /// Highest QoS the broker grants (0, 1 or 2).
    pub maximum_qos: u8,
    /// Subscriptions one session may hold (0 = unlimited).
    pub max_subscriptions_per_session: usize,
    pub allow_wildcard_subscriptions: bool,
    pub allow_retained_messages: bool,
    pub allow_shared_subscriptions: bool,
}

impl Default for ProtocolSettings {
    fn default() -> Self {
        Self {
            allow_v311: true,
            allow_v500: true,
            max_packet_size: 4_194_304,
            receive_maximum: 65_535,
            topic_alias_maximum: 20,
            max_keep_alive_sec: 3600,
            maximum_qos: 2,
            max_subscriptions_per_session: 10_000,
            allow_wildcard_subscriptions: true,
            allow_retained_messages: true,
            allow_shared_subscriptions: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueFullPolicy {
    DropOldest,
    DropNewest,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct QueueSettings {
    /// Messages buffered per session (connected-but-slow or offline persistent sessions).
    pub max_queued_messages: usize,
    pub max_queued_bytes: usize,
    /// "drop_oldest" or "drop_newest".
    pub queue_full_policy: String,
    /// Unacknowledged outbound QoS 1/2 messages per session (also capped by the client's
    /// Receive Maximum and, in bytes, by `max_queued_bytes`).
    pub max_inflight_messages: u16,
    /// Messages without a Message Expiry Interval are dropped after waiting this long in a
    /// session queue (0 = never).
    pub default_message_expiry_sec: u32,
    /// Upper bound for the Session Expiry Interval; also the lifetime of MQTT v3.1.1
    /// `CleanSession = 0` sessions after disconnect (0 = sessions end at disconnect).
    pub max_session_expiry_sec: u32,
}

impl Default for QueueSettings {
    fn default() -> Self {
        Self {
            max_queued_messages: 5000,
            max_queued_bytes: 8_388_608,
            queue_full_policy: "drop_oldest".into(),
            max_inflight_messages: 32,
            default_message_expiry_sec: 0,
            max_session_expiry_sec: 86_400,
        }
    }
}

impl QueueSettings {
    pub fn policy(&self) -> QueueFullPolicy {
        match self.queue_full_policy.as_str() {
            "drop_newest" => QueueFullPolicy::DropNewest,
            _ => QueueFullPolicy::DropOldest,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct RetainedSettings {
    pub max_messages: usize,
    pub max_bytes: usize,
}

impl Default for RetainedSettings {
    fn default() -> Self {
        Self {
            max_messages: 100_000,
            max_bytes: 64 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct MonitoringConfig {
    pub sys_topics_enabled: bool,
    pub sys_update_interval_sec: u32,
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            sys_topics_enabled: true,
            sys_update_interval_sec: 30,
        }
    }
}

/// Parses an environment value as a TOML literal, falling back to a plain string.
fn parse_env_value(raw: &str) -> toml::Value {
    let wrapped = format!("v = {raw}");
    match toml::from_str::<toml::Table>(&wrapped) {
        Ok(mut t) => t
            .remove("v")
            .unwrap_or_else(|| toml::Value::String(raw.to_owned())),
        Err(_) => toml::Value::String(raw.to_owned()),
    }
}

/// Collects dotted key paths of every leaf in a TOML table.
fn collect_paths(prefix: &str, value: &toml::Value, out: &mut BTreeSet<String>) {
    if let toml::Value::Table(t) = value {
        for (k, v) in t {
            let path = if prefix.is_empty() {
                k.clone()
            } else {
                format!("{prefix}.{k}")
            };
            out.insert(path.clone());
            // Free-form maps: do not descend.
            if path != "listeners.mqtt_sn.predefined_topics" {
                collect_paths(&path, v, out);
            }
        }
    }
}

impl AppConfig {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let content = fs::read_to_string(path)?;
        Self::load_from_str(&content)
    }

    pub fn load_from_str(content: &str) -> Result<Self, ConfigError> {
        let (config, _) = Self::load_layered(Some(content), std::iter::empty())?;
        Ok(config)
    }

    /// Builds the configuration from optional file content plus environment overrides.
    /// Returns the configuration and human-readable warnings (unknown keys, etc.).
    pub fn load_layered(
        file_content: Option<&str>,
        env: impl IntoIterator<Item = (String, String)>,
    ) -> Result<(Self, Vec<String>), ConfigError> {
        let mut root: toml::Table = match file_content {
            Some(content) => toml::from_str(content)?,
            None => toml::Table::new(),
        };
        let mut warnings = Vec::new();

        let mut overrides: Vec<(String, String)> = env
            .into_iter()
            .filter(|(k, _)| k.starts_with(ENV_PREFIX) && k != ENV_CONFIG_PATH)
            .collect();
        overrides.sort();
        for (var, raw) in overrides {
            let path: Vec<String> = var[ENV_PREFIX.len()..]
                .split("__")
                .map(|s| s.to_ascii_lowercase())
                .collect();
            if path.iter().any(String::is_empty) {
                return Err(ConfigError::Env {
                    var,
                    message: "empty key segment".into(),
                });
            }
            let mut table = &mut root;
            for segment in &path[..path.len() - 1] {
                let entry = table
                    .entry(segment.clone())
                    .or_insert_with(|| toml::Value::Table(toml::Table::new()));
                table = match entry {
                    toml::Value::Table(t) => t,
                    _ => {
                        return Err(ConfigError::Env {
                            var,
                            message: format!("'{segment}' is not a table"),
                        })
                    }
                };
            }
            table.insert(path[path.len() - 1].clone(), parse_env_value(&raw));
        }

        // Warn about keys this version does not understand (typos, removed options).
        let mut known = BTreeSet::new();
        collect_paths(
            "",
            &toml::Value::try_from(AppConfig::default()).expect("serializable"),
            &mut known,
        );
        let mut present = BTreeSet::new();
        collect_paths("", &toml::Value::Table(root.clone()), &mut present);
        for key in present.difference(&known) {
            if !key.starts_with("listeners.mqtt_sn.predefined_topics.") {
                warnings.push(format!("unknown configuration key '{key}' is ignored"));
            }
        }

        let config: AppConfig = toml::Value::Table(root).try_into()?;
        config.validate()?;
        Ok((config, warnings))
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        let invalid = |msg: String| Err(ConfigError::Validation(msg));

        match self.logging.level.to_lowercase().as_str() {
            "trace" | "debug" | "info" | "warn" | "error" => {}
            other => {
                return invalid(format!(
                    "invalid log level '{other}'; expected trace, debug, info, warn or error"
                ))
            }
        }
        match self.logging.format.to_lowercase().as_str() {
            "pretty" | "compact" | "json" => {}
            other => {
                return invalid(format!(
                    "invalid log format '{other}'; expected pretty, compact or json"
                ))
            }
        }

        let p = &self.mqtt.protocol;
        if !p.allow_v311 && !p.allow_v500 {
            return invalid(
                "at least one MQTT protocol version (v3.1.1 or v5.0) must be enabled".into(),
            );
        }
        if !(64..=MQTT_MAX_PACKET_SIZE).contains(&p.max_packet_size) {
            return invalid(format!(
                "max_packet_size must be between 64 and {MQTT_MAX_PACKET_SIZE} bytes"
            ));
        }
        if p.receive_maximum == 0 {
            return invalid("receive_maximum must be at least 1".into());
        }
        if p.maximum_qos > 2 {
            return invalid("maximum_qos must be 0, 1 or 2".into());
        }

        let q = &self.mqtt.queues;
        match q.queue_full_policy.as_str() {
            "drop_oldest" | "drop_newest" => {}
            other => {
                return invalid(format!(
                    "unsupported queue_full_policy '{other}'; expected drop_oldest or drop_newest"
                ))
            }
        }
        if q.max_queued_messages == 0 {
            return invalid("max_queued_messages must be at least 1".into());
        }
        if q.max_inflight_messages == 0 {
            return invalid("max_inflight_messages must be at least 1".into());
        }
        if (p.max_packet_size as usize) > q.max_queued_bytes {
            return invalid(format!(
                "max_packet_size ({} bytes) cannot exceed per-session max_queued_bytes ({} bytes)",
                p.max_packet_size, q.max_queued_bytes
            ));
        }

        let tls = &self.security.tls;
        match tls.min_tls_version.as_str() {
            "TLSv1.2" | "TLSv1.3" => {}
            other => {
                return invalid(format!(
                    "unsupported min_tls_version '{other}'; expected TLSv1.2 or TLSv1.3"
                ))
            }
        }
        if self.listeners.tls.enabled {
            if tls.server_cert_file.is_empty() || tls.server_key_file.is_empty() {
                return invalid(
                    "TLS listener is enabled but server_cert_file / server_key_file is empty"
                        .into(),
                );
            }
            if tls.require_client_cert && tls.ca_cert_file.is_empty() {
                return invalid("require_client_cert is enabled but ca_cert_file is empty".into());
            }
            if tls.verify_client_identity && !tls.require_client_cert {
                return invalid(
                    "verify_client_identity requires require_client_cert = true".into(),
                );
            }
            if !tls.crl_file.is_empty() && !tls.require_client_cert {
                return invalid("crl_file requires require_client_cert = true".into());
            }
            if tls
                .alpn_protocols
                .iter()
                .any(|p| p.is_empty() || p.len() > 255)
            {
                return invalid("ALPN protocol names must be 1..255 bytes".into());
            }
        }

        let (ws, wss) = (&self.listeners.ws, &self.listeners.wss);
        for (name, enabled, path, origins, proxies, max_header_bytes) in [
            (
                "ws",
                ws.enabled,
                &ws.path,
                &ws.allowed_origins,
                &ws.trusted_proxies,
                ws.max_header_bytes,
            ),
            (
                "wss",
                wss.enabled,
                &wss.path,
                &wss.allowed_origins,
                &wss.trusted_proxies,
                wss.max_header_bytes,
            ),
        ] {
            if !enabled {
                continue;
            }
            if !path.starts_with('/') || path.contains(|c: char| c.is_whitespace() || c == '?') {
                return invalid(format!(
                    "listeners.{name}.path must start with '/' and contain no spaces or '?'"
                ));
            }
            if origins.iter().any(|o| o.trim().is_empty()) {
                return invalid(format!(
                    "listeners.{name}.allowed_origins has an empty entry"
                ));
            }
            if let Some(bad) = proxies.iter().find(|p| p.parse::<IpAddr>().is_err()) {
                return invalid(format!(
                    "listeners.{name}.trusted_proxies: '{bad}' is not an IP address"
                ));
            }
            if !(1024..=65_536).contains(&max_header_bytes) {
                return invalid(format!(
                    "listeners.{name}.max_header_bytes must be between 1024 and 65536"
                ));
            }
        }
        if wss.enabled {
            if tls.server_cert_file.is_empty() || tls.server_key_file.is_empty() {
                return invalid(
                    "WSS listener is enabled but server_cert_file / server_key_file is empty"
                        .into(),
                );
            }
            if wss.require_client_cert && tls.ca_cert_file.is_empty() {
                return invalid(
                    "listeners.wss.require_client_cert is enabled but ca_cert_file is empty".into(),
                );
            }
        }

        let auth = &self.security.auth;
        match auth.password_hash_algorithm.to_lowercase().as_str() {
            "argon2" | "argon2id" | "sha256" => {}
            other => {
                return invalid(format!(
                    "unsupported password_hash_algorithm '{other}'; expected argon2id or sha256"
                ))
            }
        }
        match auth.client_id_takeover.as_str() {
            "same_user" | "any" => {}
            other => {
                return invalid(format!(
                    "unsupported client_id_takeover '{other}'; expected same_user or any"
                ))
            }
        }

        let sn = &self.listeners.mqtt_sn;
        if sn.enabled {
            if sn.max_sessions == 0 {
                return invalid("listeners.mqtt_sn.max_sessions must be at least 1".into());
            }
            for (id, topic) in &sn.predefined_topics {
                // 0x0000 and 0xFFFF are reserved topic ids (MQTT-SN v1.2 §5.3.11).
                match id.parse::<u16>() {
                    Ok(n) if n > 0 && n < u16::MAX => {}
                    _ => {
                        return invalid(format!(
                            "predefined topic id '{id}' must be an integer 1..65534"
                        ))
                    }
                }
                if !crate::routing::is_valid_topic_name(topic) {
                    return invalid(format!(
                        "predefined topic '{topic}' is not a valid topic name"
                    ));
                }
            }
        }

        if !self.listeners.tcp.enabled
            && !self.listeners.tls.enabled
            && !ws.enabled
            && !wss.enabled
            && !sn.enabled
        {
            return invalid("no listener is enabled (tcp, tls, ws, wss or mqtt_sn)".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn default_config_is_valid() {
        assert!(AppConfig::default().validate().is_ok());
    }

    #[test]
    fn shipped_sample_file_loads_without_warnings() {
        let content = std::fs::read_to_string("config/broker.toml").unwrap();
        let (config, warnings) = AppConfig::load_layered(Some(&content), Vec::new()).unwrap();
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(config.listeners.tls.port, 8883);
        assert_eq!(config.mqtt.queues.queue_full_policy, "drop_oldest");
    }

    #[test]
    fn environment_overrides_file_values() {
        let file = "[listeners.tcp]\nport = 1883\nenabled = true\n";
        let vars = env(&[
            ("WOLFIMQ_LISTENERS__TCP__PORT", "2883"),
            ("WOLFIMQ_SECURITY__AUTH__ALLOW_ANONYMOUS", "true"),
            ("WOLFIMQ_BROKER__NODE_ID", "edge-7"),
            (
                "WOLFIMQ_SECURITY__TLS__ALPN_PROTOCOLS",
                r#"["mqtt", "x-amzn-mqtt-ca"]"#,
            ),
            ("WOLFIMQ_LISTENERS__MQTT_SN__PREDEFINED_TOPICS__5", "uav/x"),
            ("WOLFIMQ_CONFIG", "/ignored/path.toml"),
            ("OTHER_VAR", "1"),
        ]);
        let (config, warnings) = AppConfig::load_layered(Some(file), vars).unwrap();
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(config.listeners.tcp.port, 2883);
        assert!(config.security.auth.allow_anonymous);
        assert_eq!(config.broker.node_id, "edge-7");
        assert_eq!(
            config.security.tls.alpn_protocols,
            vec!["mqtt", "x-amzn-mqtt-ca"]
        );
        assert_eq!(config.listeners.mqtt_sn.predefined_topics["5"], "uav/x");
    }

    #[test]
    fn invalid_environment_values_are_reported() {
        let vars = env(&[("WOLFIMQ_LISTENERS__TCP__PORT", "not-a-port")]);
        assert!(AppConfig::load_layered(None, vars).is_err());
        // `broker.node_id` is a string, so it cannot be extended into a table.
        let vars = env(&[("WOLFIMQ_BROKER__NODE_ID__X", "1")]);
        let file = "[broker]\nnode_id = \"n1\"\n";
        assert!(matches!(
            AppConfig::load_layered(Some(file), vars),
            Err(ConfigError::Env { .. })
        ));
    }

    #[test]
    fn unknown_keys_produce_warnings() {
        let file = "[security.tls]\npsk_enabled = true\n[broker]\nnode_idd = \"x\"\n";
        let (_, warnings) = AppConfig::load_layered(Some(file), Vec::new()).unwrap();
        assert_eq!(warnings.len(), 2, "{warnings:?}");
    }

    #[test]
    fn validation_rejects_bad_values() {
        let cases: Vec<fn(&mut AppConfig)> = vec![
            |c| c.logging.level = "verbose".into(),
            |c| c.logging.format = "xml".into(),
            |c| {
                c.mqtt.protocol.allow_v311 = false;
                c.mqtt.protocol.allow_v500 = false;
            },
            |c| c.security.tls.min_tls_version = "SSLv3".into(),
            |c| c.mqtt.queues.queue_full_policy = "reject_publisher".into(),
            |c| c.mqtt.protocol.max_packet_size = 10,
            |c| c.mqtt.protocol.maximum_qos = 3,
            |c| c.mqtt.protocol.receive_maximum = 0,
            |c| c.mqtt.queues.max_inflight_messages = 0,
            |c| c.mqtt.queues.max_queued_bytes = 1024,
            |c| c.security.auth.client_id_takeover = "nobody".into(),
            |c| c.security.auth.password_hash_algorithm = "bcrypt".into(),
            |c| {
                c.listeners.tcp.enabled = false;
                c.listeners.tls.enabled = false;
                c.listeners.mqtt_sn.enabled = false;
            },
            |c| {
                c.listeners.mqtt_sn.enabled = true;
                c.listeners
                    .mqtt_sn
                    .predefined_topics
                    .insert("0".into(), "a".into());
            },
            |c| {
                c.listeners.tls.enabled = true;
                c.security.tls.verify_client_identity = true;
                c.security.tls.require_client_cert = false;
            },
        ];
        for (i, mutate) in cases.into_iter().enumerate() {
            let mut config = AppConfig::default();
            mutate(&mut config);
            assert!(config.validate().is_err(), "case {i} should be rejected");
        }
    }
}
