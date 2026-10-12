use std::path::Path;
use tracing::{debug, error, info, trace, warn};
use wolf_mqtt::config::AppConfig;
use wolf_mqtt::logging;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config_path = Path::new("config/broker.toml");
    let (config, config_loaded_from_disk) = if config_path.exists() {
        (AppConfig::load_from_file(config_path)?, true)
    } else {
        (AppConfig::default(), false)
    };

    // Initialize structured logging based on configuration file settings
    if let Err(e) = logging::init(&config.logging) {
        error!("Failed to initialize logging subsystem: {e}");
    }

    if !config_loaded_from_disk {
        warn!(
            "Config file {:?} not found, running with compiled defaults",
            config_path
        );
    }

    info!("Starting wolf-mqtt-broker v0.1.0...");
    debug!("Log level initialized to: '{}'", config.logging.level);
    trace!("Verbose trace diagnostics enabled.");

    info!("Broker Node ID: {}", config.broker.node_id);
    info!(
        "MQTT Protocols: v3.1.1={}, v5.0={}",
        config.mqtt.protocol.allow_v311, config.mqtt.protocol.allow_v500
    );

    if config.listeners.tls.enabled {
        info!(
            "wolfSSL TLS Listener active on {}:{} (Min TLS: {}, mTLS: {}, ALPN: {:?})",
            config.listeners.tls.bind_address,
            config.listeners.tls.port,
            config.security.tls.min_tls_version,
            config.security.tls.require_client_cert,
            config.security.tls.alpn_protocols
        );
        if config.security.tls.psk_enabled {
            info!("wolfSSL PSK (Pre-Shared Key) mode enabled.");
        }
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
