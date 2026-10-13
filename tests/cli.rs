//! Command-line interface of the `wolf-broker` binary.

mod common;

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

fn broker() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_wolf-broker"));
    cmd.current_dir(env!("CARGO_MANIFEST_DIR"));
    // Keep the tests independent of the developer's environment.
    for (k, _) in std::env::vars() {
        if k.starts_with("WOLFIMQ_") {
            cmd.env_remove(k);
        }
    }
    cmd
}

#[test]
fn version_and_help() {
    let out = broker().arg("--version").output().unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains(env!("CARGO_PKG_VERSION")));
    let out = broker().arg("--help").output().unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).contains("WOLFIMQ_"));
}

#[test]
fn unknown_arguments_are_errors() {
    let out = broker().arg("--bogus").output().unwrap();
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn print_config_applies_environment_overrides() {
    let out = broker()
        .args(["--config", "config/broker.toml", "--print-config"])
        .env("WOLFIMQ_LISTENERS__TCP__PORT", "2999")
        .env("WOLFIMQ_BROKER__NODE_ID", "edge-42")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("port = 2999"), "{text}");
    assert!(text.contains("node_id = \"edge-42\""));
}

#[test]
fn check_config_validates_config_and_acl() {
    let pki = common::test_pki();
    let out = broker()
        .args(["--config", "config/broker.toml", "--check-config"])
        .env(
            "WOLFIMQ_SECURITY__TLS__CA_CERT_FILE",
            pki.join("ca-cert.pem"),
        )
        .env(
            "WOLFIMQ_SECURITY__TLS__SERVER_CERT_FILE",
            pki.join("server-cert.pem"),
        )
        .env(
            "WOLFIMQ_SECURITY__TLS__SERVER_KEY_FILE",
            pki.join("server-key.pem"),
        )
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("Configuration OK"));

    // Invalid values are reported with a non-zero exit code.
    let out = broker()
        .args(["--config", "config/broker.toml", "--check-config"])
        .env(
            "WOLFIMQ_MQTT__QUEUES__QUEUE_FULL_POLICY",
            "\"reject_publisher\"",
        )
        .output()
        .unwrap();
    assert!(!out.status.success());

    // A missing explicit configuration file is an error.
    let out = broker()
        .args(["--config", "does/not/exist.toml", "--check-config"])
        .output()
        .unwrap();
    assert!(!out.status.success());
}

#[test]
fn hash_password_reads_stdin_and_produces_acl_syntax() {
    let mut child = broker()
        .args(["--config", "config/broker.toml", "--hash-password"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"s3cret\n").unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    let line = String::from_utf8_lossy(&out.stdout).trim().to_string();
    assert!(line.starts_with("password_hash:$argon2id$"), "{line}");

    // The produced line is accepted by the ACL parser and verifies the password.
    let acl = format!("user alice {line}\n");
    let accounts = wolf_mqtt::auth::AclEngine::parse_acl(&acl).unwrap();
    assert!(accounts[0].verify_password(b"s3cret"));
}

#[test]
fn unknown_configuration_keys_are_reported() {
    let dir = std::env::temp_dir().join(format!("wolfimq-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("broker.toml");
    std::fs::write(
        &path,
        "[listeners.tcp]\nenabled = true\nprot = 1\n[security.auth]\nacl_file = \"\"\n",
    )
    .unwrap();
    let out = broker()
        .arg("--config")
        .arg(&path)
        .arg("--print-config")
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("listeners.tcp.prot"));
    let _ = std::fs::remove_dir_all(dir);
}

#[cfg(unix)]
#[test]
fn broker_starts_serves_and_stops_on_sigterm() {
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let mut child = broker()
        .args(["--config", "config/broker.toml"])
        .env("WOLFIMQ_LISTENERS__TLS__ENABLED", "false")
        .env("WOLFIMQ_LISTENERS__MQTT_SN__ENABLED", "false")
        .env("WOLFIMQ_LISTENERS__TCP__ENABLED", "true")
        .env("WOLFIMQ_LISTENERS__TCP__PORT", port.to_string())
        .env("WOLFIMQ_LOGGING__FORMAT", "compact")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let mut ready = false;
        for _ in 0..100 {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                ready = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(ready, "broker did not start");
        let conn = common::v5("cli-admin").with_credentials("superadmin", "admin_secret_pass");
        let mut c = common::connect(addr, conn).await;
        c.ping().await.unwrap();
    });

    // SAFETY-free signal delivery through the `kill` utility.
    let status = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(code) = child.try_wait().unwrap() {
            assert!(code.success(), "broker exited with {code}");
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "broker did not stop on SIGTERM"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}
