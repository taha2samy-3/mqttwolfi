use std::path::Path;
use std::sync::Arc;
use tracing::{debug, error, info, trace, warn};
use wolf_mqtt::config::AppConfig;
use wolf_mqtt::logging;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let mut config_file = "config/broker.toml".to_string();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-c" | "--config" if i + 1 < args.len() => {
                config_file = args[i + 1].clone();
                i += 1;
            }
            "-h" | "--help" => {
                println!("WolfiMQ - High-Performance MQTT 3.1.1 / 5.0 Broker with Native wolfSSL TLS 1.3\n");
                println!("Usage: wolf-mqtt-broker [OPTIONS]\n");
                println!("Options:");
                println!("  -c, --config <FILE>    Path to TOML configuration file [default: config/broker.toml]");
                println!("  -h, --help             Print help information and exit");
                println!("  -v, --version          Print version information and exit");
                return Ok(());
            }
            "-v" | "--version" => {
                // "FIPS-Ready" = FIPS-approved algorithms only. This build does NOT
                // carry a formal CMVP certificate. For a formally validated build
                // (CMVP #4718), use the wolfSSL commercial FIPS bundle.
                // See: https://www.wolfssl.com/products/wolfcrypt-fips/
                println!("wolf-mqtt-broker v{} (wolfSSL FIPS-Ready build - FIPS-approved algorithms, TLS 1.3 / mTLS)", env!("CARGO_PKG_VERSION"));
                #[cfg(not(feature = "wolfssl-fips"))]
                println!(
                    "wolf-mqtt-broker v{} (wolfSSL TLS 1.3 / mTLS)",
                    env!("CARGO_PKG_VERSION")
                );
                return Ok(());
            }
            _ => {}
        }
        i += 1;
    }

    let config_path = Path::new(&config_file);
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

    info!(
        "Starting wolf-mqtt-broker v{}...",
        env!("CARGO_PKG_VERSION")
    );
    #[cfg(feature = "wolfssl-fips")]
    // NOTE: "FIPS-Ready" = FIPS-approved algorithms only; not a formal CMVP certificate.
    info!("Cryptographic Engine: wolfSSL FIPS-Ready (FIPS-approved algorithms; no CMVP certificate — see wolfssl.com/products/wolfcrypt-fips/ for formally validated builds)");
    #[cfg(not(feature = "wolfssl-fips"))]
    info!("Cryptographic Engine: wolfSSL TLS 1.3 Standard Module");
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

    let acl = Arc::new(wolf_mqtt::auth::AclEngine::new(
        config.security.auth.allow_anonymous,
    ));
    if !config.security.auth.acl_file.is_empty() {
        let acl_path = Path::new(&config.security.auth.acl_file);
        if acl_path.exists() {
            info!("Loading ACL rules and credentials from {:?}", acl_path);
            if let Err(e) = acl.load_from_acl_file(acl_path).await {
                error!("Failed to parse ACL file {:?}: {}", acl_path, e);
            } else {
                info!("ACL rules and credentials loaded successfully.");
            }
        } else {
            warn!("Configured ACL file {:?} does not exist.", acl_path);
        }
    }

    let shared_context = wolf_mqtt::server::BrokerContext::new(Arc::clone(&acl));
    if config.monitoring.sys_topics_enabled {
        shared_context.start_sys_publisher(config.monitoring.sys_update_interval_sec as u64);
        info!(
            "$SYS metric topics active (update interval: {}s)",
            config.monitoring.sys_update_interval_sec
        );
    }
    let mut listeners_active = 0;

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
                    let tls_server = tls_server.with_context(shared_context.clone());
                    info!("WolfiMQ TLS listener active on {}", tls_addr);
                    listeners_active += 1;
                    tokio::spawn(async move {
                        let _ = tls_server.run_tls(acceptor).await;
                    });
                }
                Err(e) => {
                    error!("Failed to bind TLS listener on {}: {}", tls_addr, e);
                    return Err(
                        format!("Failed to bind TLS listener on {}: {}", tls_addr, e).into(),
                    );
                }
            },
            Err(e) => {
                error!("Failed to initialize TLS acceptor: {}", e);
                return Err(format!("Failed to initialize TLS acceptor: {}", e).into());
            }
        }
    }

    if config.listeners.mqtt_sn.enabled {
        match wolf_mqtt::server_sn::MqttSnServer::bind(
            config.listeners.mqtt_sn.clone(),
            shared_context.clone(),
        )
        .await
        {
            Ok(sn_server) => {
                let local_addr = sn_server.local_addr()?;
                listeners_active += 1;
                info!(
                    "WolfiMQ MQTT-SN (UDP) listener active on {} (Gateway ID: {})",
                    local_addr, config.listeners.mqtt_sn.gateway_id
                );
                tokio::spawn(async move {
                    if let Err(e) = sn_server.run().await {
                        error!("MQTT-SN UDP server failure: {}", e);
                    }
                });
            }
            Err(e) => {
                error!("Failed to bind MQTT-SN UDP listener: {}", e);
                return Err(format!("Failed to bind MQTT-SN UDP listener: {}", e).into());
            }
        }
    }

    if config.listeners.tcp.enabled {
        let tcp_addr = format!(
            "{}:{}",
            config.listeners.tcp.bind_address, config.listeners.tcp.port
        );
        match wolf_mqtt::server::BrokerServer::bind(&tcp_addr).await {
            Ok(tcp_server) => {
                let tcp_server = tcp_server.with_context(shared_context.clone());
                listeners_active += 1;
                info!(
                    "WolfiMQ TCP listener active on {} (active listeners: {})",
                    tcp_addr, listeners_active
                );
                tcp_server.run().await?;
            }
            Err(e) => {
                error!("Failed to bind TCP listener on {}: {}", tcp_addr, e);
                return Err(e.into());
            }
        }
    } else {
        if listeners_active == 0 {
            return Err(
                "No network listeners (TCP or TLS) were successfully initialized. Exiting.".into(),
            );
        }
        // Wait indefinitely if only TLS was spawned
        tokio::signal::ctrl_c().await?;
        info!("Shutdown signal received. Exiting.");
    }

    Ok(())
}
