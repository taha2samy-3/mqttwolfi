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

    if config.listeners.tls.enabled {
        let tls_addr = format!(
            "{}:{}",
            config.listeners.tls.bind_address, config.listeners.tls.port
        );
        let ca_path = if config.security.tls.require_client_cert {
            Some(config.security.tls.ca_cert_file.as_str())
        } else {
            None
        };

        match wolf_mqtt::tls::create_tls_acceptor(
            &config.security.tls.server_cert_file,
            &config.security.tls.server_key_file,
            ca_path,
        ) {
            Ok(acceptor) => match wolf_mqtt::server::BrokerServer::bind(&tls_addr).await {
                Ok(tls_server) => {
                    info!("WolfiMQ TLS listener active on {}", tls_addr);
                    tokio::spawn(async move {
                        let _ = tls_server.run_tls(acceptor).await;
                    });
                }
                Err(e) => error!("Failed to bind TLS listener on {}: {}", tls_addr, e),
            },
            Err(e) => error!("Failed to initialize TLS acceptor: {}", e),
        }
    }

    if config.listeners.tcp.enabled {
        let tcp_addr = format!(
            "{}:{}",
            config.listeners.tcp.bind_address, config.listeners.tcp.port
        );
        match wolf_mqtt::server::BrokerServer::bind(&tcp_addr).await {
            Ok(tcp_server) => {
                info!("WolfiMQ TCP listener active on {}", tcp_addr);
                tcp_server.run().await?;
            }
            Err(e) => error!("Failed to bind TCP listener on {}: {}", tcp_addr, e),
        }
    } else {
        // Wait indefinitely if only TLS was spawned
        tokio::signal::ctrl_c().await?;
        info!("Shutdown signal received. Exiting.");
    }

    Ok(())
}
