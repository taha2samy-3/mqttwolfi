use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Failed to read configuration file: {0}")]
    Io(#[from] std::io::Error),
    #[error("Failed to parse TOML configuration: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("Invalid configuration: {0}")]
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
    pub max_connections: usize,
    pub worker_threads: usize,
}

impl Default for BrokerSettings {
    fn default() -> Self {
        Self {
            node_id: "wolf-broker-node-01".into(),
            max_connections: 100_000,
            worker_threads: 0,
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
            bind_address: "0.0.0.0".into(),
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
            enabled: true,
            bind_address: "0.0.0.0".into(),
            port: 8883,
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
    pub require_client_cert: bool,
    pub verify_client_identity: bool,
    pub min_tls_version: String,
    pub ciphers: String,
    pub alpn_protocols: Vec<String>,
    pub psk_enabled: bool,
    pub psk_identity_hint: String,
    pub session_tickets_enabled: bool,
    pub session_ticket_lifetime_sec: u32,
    pub hardware_crypto_engine: String,
}

impl Default for WolfTlsConfig {
    fn default() -> Self {
        Self {
            ca_cert_file: "certs/ca-cert.pem".into(),
            server_cert_file: "certs/server-cert.pem".into(),
            server_key_file: "certs/server-key.pem".into(),
            require_client_cert: true,
            verify_client_identity: false,
            min_tls_version: "TLSv1.3".into(),
            ciphers:
                "TLS13-AES128-GCM-SHA256,TLS13-AES256-GCM-SHA384,TLS13-CHACHA20-POLY1305-SHA256"
                    .into(),
            alpn_protocols: vec!["mqtt".into()],
            psk_enabled: false,
            psk_identity_hint: "wolf-broker-psk".into(),
            session_tickets_enabled: true,
            session_ticket_lifetime_sec: 7200,
            hardware_crypto_engine: "none".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct AuthConfig {
    pub allow_anonymous: bool,
    pub password_hash_algorithm: String,
    pub acl_file: String,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            allow_anonymous: false,
            password_hash_algorithm: "sha256".into(),
            acl_file: "config/acl.conf".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct MqttSettings {
    pub protocol: ProtocolSettings,
    pub queues: QueueSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct ProtocolSettings {
    pub allow_v311: bool,
    pub allow_v500: bool,
    pub max_packet_size: u32,
    pub receive_maximum: u16,
    pub topic_alias_maximum: u16,
    pub max_keep_alive_sec: u16,
    pub allow_wildcard_subscriptions: bool,
    pub allow_retained_messages: bool,
    pub allow_shared_subscriptions: bool,
}

impl Default for ProtocolSettings {
    fn default() -> Self {
        Self {
            allow_v311: true,
            allow_v500: true,
            max_packet_size: 4_194_304, // 4 MB
            receive_maximum: 65_535,
            topic_alias_maximum: 20,
            max_keep_alive_sec: 3600,
            allow_wildcard_subscriptions: true,
            allow_retained_messages: true,
            allow_shared_subscriptions: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct QueueSettings {
    pub max_queued_messages: usize,
    pub max_queued_bytes: usize,
    pub queue_full_policy: String,
    pub default_message_expiry_sec: u32,
    pub max_session_expiry_sec: u32,
}

impl Default for QueueSettings {
    fn default() -> Self {
        Self {
            max_queued_messages: 5000,
            max_queued_bytes: 8_388_608, // 8 MB
            queue_full_policy: "drop_oldest".into(),
            default_message_expiry_sec: 86400,
            max_session_expiry_sec: 604800,
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

impl AppConfig {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let content = fs::read_to_string(path)?;
        Self::load_from_str(&content)
    }

    pub fn load_from_str(content: &str) -> Result<Self, ConfigError> {
        let config: AppConfig = toml::from_str(content)?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        // Validate log level
        match self.logging.level.to_lowercase().as_str() {
            "trace" | "debug" | "info" | "warn" | "error" => {}
            other => {
                return Err(ConfigError::Validation(format!(
                    "Invalid log level: '{other}'. Expected one of: trace, debug, info, warn, error"
                )));
            }
        }

        // Validate log format
        match self.logging.format.to_lowercase().as_str() {
            "pretty" | "compact" | "json" => {}
            other => {
                return Err(ConfigError::Validation(format!(
                    "Invalid log format: '{other}'. Expected one of: pretty, compact, json"
                )));
            }
        }

        if !self.mqtt.protocol.allow_v311 && !self.mqtt.protocol.allow_v500 {
            return Err(ConfigError::Validation(
                "At least one MQTT protocol version (v3.1.1 or v5.0) must be enabled".into(),
            ));
        }

        if self.listeners.tls.enabled && !self.security.tls.psk_enabled {
            if self.security.tls.server_cert_file.is_empty() {
                return Err(ConfigError::Validation(
                    "TLS listener is enabled, but server_cert_file is empty".into(),
                ));
            }
            if self.security.tls.server_key_file.is_empty() {
                return Err(ConfigError::Validation(
                    "TLS listener is enabled, but server_key_file is empty".into(),
                ));
            }
            if self.security.tls.require_client_cert && self.security.tls.ca_cert_file.is_empty() {
                return Err(ConfigError::Validation(
                    "Mutual TLS (require_client_cert) is enabled, but ca_cert_file is empty".into(),
                ));
            }
        }

        match self.security.tls.min_tls_version.as_str() {
            "TLSv1.2" | "TLSv1.3" => {}
            other => {
                return Err(ConfigError::Validation(format!(
                    "Unsupported min_tls_version: {other}. Expected TLSv1.2 or TLSv1.3"
                )));
            }
        }

        match self.mqtt.queues.queue_full_policy.as_str() {
            "drop_oldest" | "drop_newest" | "reject_publisher" => {}
            other => {
                return Err(ConfigError::Validation(format!(
                    "Unsupported queue_full_policy: {other}. Expected drop_oldest, drop_newest, or reject_publisher"
                )));
            }
        }

        if (self.mqtt.protocol.max_packet_size as usize) > self.mqtt.queues.max_queued_bytes {
            return Err(ConfigError::Validation(format!(
                "Configuration conflict: max_packet_size ({} bytes) cannot exceed per-client max_queued_bytes ({} bytes)",
                self.mqtt.protocol.max_packet_size, self.mqtt.queues.max_queued_bytes
            )));
        }

        match self
            .security
            .auth
            .password_hash_algorithm
            .to_lowercase()
            .as_str()
        {
            "sha256" | "argon2" | "argon2id" => {}
            other => {
                return Err(ConfigError::Validation(format!(
                    "Unsupported password_hash_algorithm: {other}. Expected sha256, argon2, or argon2id"
                )));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_is_valid() {
        let config = AppConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_load_sample_file() {
        let path = "config/broker.toml";
        let config = AppConfig::load_from_file(path).expect("Failed to load broker.toml");
        assert_eq!(config.broker.node_id, "wolf-broker-node-01");
        assert_eq!(config.logging.level, "info");
        assert!(config.listeners.tls.enabled);
        assert_eq!(config.listeners.tls.port, 8883);
        assert!(config.security.tls.require_client_cert);
        assert_eq!(config.security.tls.min_tls_version, "TLSv1.3");
        assert_eq!(config.mqtt.queues.queue_full_policy, "drop_oldest");
    }

    #[test]
    fn test_validation_rejects_invalid_log_level() {
        let mut config = AppConfig::default();
        config.logging.level = "invalid_level".into();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validation_rejects_invalid_log_format() {
        let mut config = AppConfig::default();
        config.logging.format = "xml".into();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validation_rejects_missing_protocol_versions() {
        let mut config = AppConfig::default();
        config.mqtt.protocol.allow_v311 = false;
        config.mqtt.protocol.allow_v500 = false;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validation_rejects_invalid_tls_version() {
        let mut config = AppConfig::default();
        config.security.tls.min_tls_version = "SSLv3".into();
        assert!(config.validate().is_err());
    }
}
