use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};
use wolf_mqtt::auth::{AclEngine, UserAccount, ANONYMOUS_USER};
use wolf_mqtt::broker::BrokerContext;
use wolf_mqtt::config::{AppConfig, ENV_CONFIG_PATH};
use wolf_mqtt::logging;
use wolf_mqtt::server::BrokerServer;
use wolf_mqtt::server_sn::MqttSnServer;
use wolf_mqtt::tls::{create_tls_acceptor, TlsServerConfig};
use wolf_mqtt::ws::WsSettings;

const DEFAULT_CONFIG: &str = "config/broker.toml";

const USAGE: &str = "\
WolfiMQ - MQTT v3.1.1 / v5.0 and MQTT-SN v1.2 broker with wolfSSL TLS

Usage: wolf-broker [OPTIONS]

Options:
  -c, --config <FILE>          Configuration file [env: WOLFIMQ_CONFIG] [default: config/broker.toml]
      --check-config           Validate the configuration, ACL file and TLS files (certificates,
                               key, CRL), then exit
      --print-config           Print the effective configuration (file + environment) as TOML
      --hash-password [PASS]   Print a password hash for acl.conf (reads stdin when PASS is omitted)
  -h, --help                   Print this help
  -V, --version                Print version information

Any configuration key can be overridden with WOLFIMQ_<SECTION>__<KEY>=<value>,
for example WOLFIMQ_LISTENERS__TCP__PORT=1884.";

enum Command {
    Run,
    CheckConfig,
    PrintConfig,
    HashPassword(Option<String>),
}

struct Cli {
    config: Option<PathBuf>,
    command: Command,
}

fn version_line() -> String {
    #[cfg(feature = "wolfssl-fips")]
    let engine =
        "wolfSSL FIPS-Ready build (FIPS-approved algorithms only; not a CMVP-validated module)";
    #[cfg(not(feature = "wolfssl-fips"))]
    let engine = "wolfSSL";
    format!("wolf-broker {} ({engine})", env!("CARGO_PKG_VERSION"))
}

fn parse_args() -> Result<Option<Cli>, String> {
    let mut args = std::env::args().skip(1).peekable();
    let mut cli = Cli {
        config: None,
        command: Command::Run,
    };
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-c" | "--config" => {
                let path = args.next().ok_or("--config requires a file path")?;
                cli.config = Some(PathBuf::from(path));
            }
            "--check-config" => cli.command = Command::CheckConfig,
            "--print-config" => cli.command = Command::PrintConfig,
            "--hash-password" => {
                let inline = args.next_if(|a| !a.starts_with('-'));
                cli.command = Command::HashPassword(inline);
            }
            "-h" | "--help" => {
                println!("{USAGE}");
                return Ok(None);
            }
            "-V" | "-v" | "--version" => {
                println!("{}", version_line());
                return Ok(None);
            }
            other => return Err(format!("unknown argument '{other}' (see --help)")),
        }
    }
    Ok(Some(cli))
}

/// Loads the configuration: explicit path > WOLFIMQ_CONFIG > default path (optional).
fn load_config(
    explicit: Option<&Path>,
) -> Result<(AppConfig, Vec<String>, Option<PathBuf>), String> {
    let (path, required) = match explicit {
        Some(p) => (p.to_path_buf(), true),
        None => match std::env::var_os(ENV_CONFIG_PATH) {
            Some(p) => (PathBuf::from(p), true),
            None => (PathBuf::from(DEFAULT_CONFIG), false),
        },
    };
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => Some(c),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && !required => None,
        Err(e) => {
            return Err(format!(
                "cannot read configuration file {}: {e}",
                path.display()
            ))
        }
    };
    let used = content.as_ref().map(|_| path.clone());
    let (config, warnings) = AppConfig::load_layered(content.as_deref(), std::env::vars())
        .map_err(|e| format!("configuration error ({}): {e}", path.display()))?;
    Ok((config, warnings, used))
}

fn hash_password(config: &AppConfig, inline: Option<String>) -> Result<(), String> {
    let password = match inline {
        Some(p) => p,
        None => {
            let mut line = String::new();
            std::io::stdin()
                .read_line(&mut line)
                .map_err(|e| format!("cannot read password from stdin: {e}"))?;
            line.trim_end_matches(['\r', '\n']).to_string()
        }
    };
    if password.is_empty() {
        return Err("password must not be empty".into());
    }
    let hash = match config
        .security
        .auth
        .password_hash_algorithm
        .to_lowercase()
        .as_str()
    {
        "sha256" => UserAccount::hash_password(password.as_bytes()),
        _ => UserAccount::hash_password_argon2(password.as_bytes())?,
    };
    println!("password_hash:{hash}");
    Ok(())
}

async fn build_acl(config: &AppConfig) -> Result<Arc<AclEngine>, String> {
    let auth = &config.security.auth;
    let mut acl = AclEngine::new(auth.allow_anonymous);
    if auth.max_concurrent_auth > 0 {
        acl = acl.with_max_concurrent_verifications(auth.max_concurrent_auth);
    }
    let acl = Arc::new(acl);
    if !auth.acl_file.is_empty() {
        let count = acl
            .load_from_acl_file(&auth.acl_file)
            .await
            .map_err(|e| format!("ACL file {}: {e}", auth.acl_file))?;
        info!("Loaded {} accounts from {}", count, auth.acl_file);
    }
    if auth.allow_anonymous && acl.get_user(ANONYMOUS_USER).await.is_none() {
        warn!("allow_anonymous = true and no 'anonymous' user in the ACL file: anonymous clients get full read/write access");
    }
    let sn_user = &config.listeners.mqtt_sn.acl_user;
    if config.listeners.mqtt_sn.enabled {
        if !sn_user.is_empty() && acl.get_user(sn_user).await.is_none() {
            return Err(format!(
                "listeners.mqtt_sn.acl_user '{sn_user}' is not defined in the ACL file"
            ));
        }
        if sn_user.is_empty() && !auth.allow_anonymous {
            warn!("MQTT-SN listener has no acl_user and anonymous access is disabled: SN clients will be rejected");
        }
    }
    Ok(acl)
}

/// TLS settings of the WSS listener: the shared `[security.tls]` material, with client
/// certificates required only when `listeners.wss.require_client_cert` says so.
fn wss_tls_config(config: &AppConfig) -> TlsServerConfig {
    let tls = &config.security.tls;
    let wss = &config.listeners.wss;
    let mut cfg = TlsServerConfig::from_config(tls);
    cfg.client_ca_file = wss.require_client_cert.then(|| tls.ca_cert_file.clone());
    cfg.crl_file =
        (wss.require_client_cert && !tls.crl_file.is_empty()).then(|| tls.crl_file.clone());
    cfg
}

fn ws_settings(
    path: &str,
    allowed_origins: &[String],
    trusted_proxies: &[String],
    max_header_bytes: usize,
    config: &AppConfig,
) -> WsSettings {
    WsSettings {
        path: path.to_owned(),
        allowed_origins: allowed_origins.to_vec(),
        // Validated by AppConfig::validate.
        trusted_proxies: trusted_proxies
            .iter()
            .filter_map(|p| p.parse().ok())
            .collect(),
        max_header_bytes,
        max_frame_size: config.mqtt.protocol.max_packet_size as usize,
    }
}

async fn run_broker(config: AppConfig) -> Result<(), String> {
    let acl = build_acl(&config).await?;
    let ctx = BrokerContext::from_config(&config, Arc::clone(&acl));
    ctx.start_background_tasks();

    let mut tasks = Vec::new();
    if config.listeners.tcp.enabled {
        let addr = format!(
            "{}:{}",
            config.listeners.tcp.bind_address, config.listeners.tcp.port
        );
        let server = BrokerServer::bind(&addr, ctx.clone())
            .await
            .map_err(|e| format!("cannot bind TCP listener on {addr}: {e}"))?;
        if config.listeners.tcp.bind_address != "127.0.0.1"
            && config.listeners.tcp.bind_address != "::1"
        {
            warn!("Plain-text MQTT listener exposed on {addr}: credentials travel unencrypted");
        }
        tasks.push(tokio::spawn(async move {
            if let Err(e) = server.run().await {
                error!("TCP listener failed: {e}");
            }
        }));
    }
    if config.listeners.tls.enabled {
        let addr = format!(
            "{}:{}",
            config.listeners.tls.bind_address, config.listeners.tls.port
        );
        let tls_cfg = TlsServerConfig::from_config(&config.security.tls);
        let acceptor =
            create_tls_acceptor(&tls_cfg).map_err(|e| format!("TLS setup failed: {e}"))?;
        let server = BrokerServer::bind(&addr, ctx.clone())
            .await
            .map_err(|e| format!("cannot bind TLS listener on {addr}: {e}"))?
            .with_tls(acceptor);
        info!(
            "TLS listener on {addr} (minimum {}, mutual TLS: {}, ALPN: {:?})",
            config.security.tls.min_tls_version,
            config.security.tls.require_client_cert,
            config.security.tls.alpn_protocols
        );
        tasks.push(tokio::spawn(async move {
            if let Err(e) = server.run().await {
                error!("TLS listener failed: {e}");
            }
        }));
    }
    if config.listeners.ws.enabled {
        let ws = &config.listeners.ws;
        let addr = format!("{}:{}", ws.bind_address, ws.port);
        let server = BrokerServer::bind(&addr, ctx.clone())
            .await
            .map_err(|e| format!("cannot bind WebSocket listener on {addr}: {e}"))?
            .with_websocket(ws_settings(
                &ws.path,
                &ws.allowed_origins,
                &ws.trusted_proxies,
                ws.max_header_bytes,
                &config,
            ));
        if ws.bind_address != "127.0.0.1" && ws.bind_address != "::1" {
            warn!(
                "Plain WebSocket listener exposed on {addr}: credentials travel unencrypted \
                 (use listeners.wss, or a TLS-terminating proxy on loopback)"
            );
        }
        tasks.push(tokio::spawn(async move {
            if let Err(e) = server.run().await {
                error!("WebSocket listener failed: {e}");
            }
        }));
    }
    if config.listeners.wss.enabled {
        let wss = &config.listeners.wss;
        let addr = format!("{}:{}", wss.bind_address, wss.port);
        let acceptor = create_tls_acceptor(&wss_tls_config(&config))
            .map_err(|e| format!("WSS TLS setup failed: {e}"))?;
        let server = BrokerServer::bind(&addr, ctx.clone())
            .await
            .map_err(|e| format!("cannot bind WSS listener on {addr}: {e}"))?
            .with_tls(acceptor)
            .with_websocket(ws_settings(
                &wss.path,
                &wss.allowed_origins,
                &wss.trusted_proxies,
                wss.max_header_bytes,
                &config,
            ));
        if config.security.tls.verify_client_identity && !wss.require_client_cert {
            warn!(
                "verify_client_identity is on but listeners.wss.require_client_cert is off: \
                 WSS clients without a certificate will be refused"
            );
        }
        info!(
            "WSS listener on {addr} (path {}, client certificates: {}, allowed origins: {:?})",
            wss.path, wss.require_client_cert, wss.allowed_origins
        );
        tasks.push(tokio::spawn(async move {
            if let Err(e) = server.run().await {
                error!("WSS listener failed: {e}");
            }
        }));
    }
    if config.listeners.mqtt_sn.enabled {
        let sn = MqttSnServer::bind(config.listeners.mqtt_sn.clone(), ctx.clone())
            .await
            .map_err(|e| format!("cannot bind MQTT-SN listener: {e}"))?;
        tasks.push(tokio::spawn(async move {
            if let Err(e) = sn.run().await {
                error!("MQTT-SN gateway failed: {e}");
            }
        }));
    }

    info!(
        "{} started (node '{}')",
        version_line(),
        config.broker.node_id
    );
    wait_for_signals(&acl, &config).await;

    info!("Shutting down: closing listeners and connections");
    ctx.shutdown();
    let grace = Duration::from_secs(config.broker.shutdown_grace_sec);
    let deadline = tokio::time::Instant::now() + grace;
    while ctx
        .metrics
        .connections_active
        .load(std::sync::atomic::Ordering::Acquire)
        > 0
        && tokio::time::Instant::now() < deadline
    {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    for t in tasks {
        t.abort();
    }
    info!("Shutdown complete");
    Ok(())
}

#[cfg(unix)]
async fn wait_for_signals(acl: &AclEngine, config: &AppConfig) {
    use tokio::signal::unix::{signal, SignalKind};
    let (Ok(mut term), Ok(mut hup)) = (
        signal(SignalKind::terminate()),
        signal(SignalKind::hangup()),
    ) else {
        let _ = tokio::signal::ctrl_c().await;
        return;
    };
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => return,
            _ = term.recv() => return,
            _ = hup.recv() => {
                let path = &config.security.auth.acl_file;
                if path.is_empty() {
                    continue;
                }
                match acl.load_from_acl_file(path).await {
                    Ok(n) => info!("SIGHUP: reloaded {} accounts from {}", n, path),
                    Err(e) => error!("SIGHUP: ACL reload failed, keeping previous rules: {}", e),
                }
            }
        }
    }
}

#[cfg(not(unix))]
async fn wait_for_signals(_acl: &AclEngine, _config: &AppConfig) {
    let _ = tokio::signal::ctrl_c().await;
}

fn main() -> ExitCode {
    let cli = match parse_args() {
        Ok(Some(cli)) => cli,
        Ok(None) => return ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    let (config, warnings, path) = match load_config(cli.config.as_deref()) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    match cli.command {
        Command::HashPassword(inline) => {
            return match hash_password(&config, inline) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::FAILURE
                }
            };
        }
        Command::PrintConfig => {
            for w in &warnings {
                eprintln!("warning: {w}");
            }
            match toml::to_string_pretty(&config) {
                Ok(s) => {
                    print!("{s}");
                    return ExitCode::SUCCESS;
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::FAILURE;
                }
            }
        }
        Command::CheckConfig | Command::Run => {}
    }

    if let Err(e) = logging::init(&config.logging) {
        eprintln!("error: cannot initialize logging: {e}");
        return ExitCode::FAILURE;
    }
    for w in &warnings {
        warn!("{w}");
    }
    match &path {
        Some(p) => info!("Configuration loaded from {}", p.display()),
        None => warn!("No configuration file found; using compiled defaults"),
    }

    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.enable_all();
    if config.broker.worker_threads > 0 {
        builder.worker_threads(config.broker.worker_threads);
    }
    let runtime = match builder.build() {
        Ok(rt) => rt,
        Err(e) => {
            error!("cannot start the Tokio runtime: {e}");
            return ExitCode::FAILURE;
        }
    };

    let check_only = matches!(cli.command, Command::CheckConfig);
    let result = runtime.block_on(async {
        if check_only {
            build_acl(&config).await?;
            if config.listeners.tls.enabled {
                create_tls_acceptor(&TlsServerConfig::from_config(&config.security.tls))
                    .map_err(|e| format!("TLS setup failed: {e}"))?;
            }
            if config.listeners.wss.enabled {
                create_tls_acceptor(&wss_tls_config(&config))
                    .map_err(|e| format!("WSS TLS setup failed: {e}"))?;
            }
            println!("Configuration OK");
            Ok(())
        } else {
            run_broker(config).await
        }
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!("{e}");
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
