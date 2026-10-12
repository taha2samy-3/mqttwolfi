use std::path::Path;
use tracing::{info, warn};
use wolf_mqtt::config::AppConfig;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    info!("Starting wolf-mqtt-broker...");

    let config_path = Path::new("config/broker.toml");
    let config = if config_path.exists() {
        info!("Loading configuration from {:?}", config_path);
        AppConfig::load_from_file(config_path)?
    } else {
        warn!(
            "Config file {:?} not found, using compiled defaults",
            config_path
        );
        AppConfig::default()
    };

    info!("Broker Node ID: {}", config.broker.node_id);
    info!(
        "MQTT Protocols: v3.1.1={}, v5.0={}",
        config.mqtt.protocol.allow_v311, config.mqtt.protocol.allow_v500
    );
    if config.listeners.tls.enabled {
        info!(
            "wolfSSL TLS Listener active on {}:{} (Min TLS: {}, mTLS: {})",
            config.listeners.tls.bind_address,
            config.listeners.tls.port,
            config.security.tls.min_tls_version,
            config.security.tls.require_client_cert
        );
    }
    if config.listeners.tcp.enabled {
        info!(
            "Plain TCP Listener active on {}:{}",
            config.listeners.tcp.bind_address, config.listeners.tcp.port
        );
    }

    info!("Initialization complete. Ready for secure connections.");

    Ok(())
}
