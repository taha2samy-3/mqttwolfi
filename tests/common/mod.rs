//! Shared helpers for the integration tests.
#![allow(dead_code)]

use bytes::Bytes;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use wolf_mqtt::auth::AclEngine;
use wolf_mqtt::broker::{BrokerContext, BrokerOptions};
use wolf_mqtt::client::RawClient;
use wolf_mqtt::protocol::{ConnectPacket, MqttPacket, ProtocolVersion, PublishPacket, QoS};
use wolf_mqtt::server::BrokerServer;

/// Short wait used to assert that something does NOT happen.
pub const QUIET: Duration = Duration::from_millis(300);

pub struct TestBroker {
    pub addr: SocketAddr,
    pub ctx: BrokerContext,
}

/// Starts a TCP broker with the given options and ACL on an ephemeral port.
pub async fn start_broker(options: BrokerOptions, acl: AclEngine) -> TestBroker {
    let ctx = BrokerContext::with_options(Arc::new(acl), options);
    ctx.start_background_tasks();
    let server = BrokerServer::bind("127.0.0.1:0", ctx.clone())
        .await
        .expect("bind");
    let addr = server.local_addr().expect("local addr");
    tokio::spawn(server.run());
    TestBroker { addr, ctx }
}

/// Broker allowing anonymous clients full access.
pub async fn open_broker() -> TestBroker {
    start_broker(BrokerOptions::permissive(), AclEngine::new(true)).await
}

pub fn v5(client_id: &str) -> ConnectPacket {
    ConnectPacket::new(client_id).with_version(ProtocolVersion::V500)
}

pub fn v3(client_id: &str) -> ConnectPacket {
    ConnectPacket::new(client_id).with_version(ProtocolVersion::V311)
}

/// Connects and asserts that the broker accepted the connection.
pub async fn connect(addr: SocketAddr, connect: ConnectPacket) -> RawClient {
    let (client, ack) = RawClient::connect(addr, connect).await.expect("connect");
    assert_eq!(ack.reason_code, 0, "CONNACK refused: {ack:?}");
    client
}

pub fn msg(topic: &str, payload: &'static [u8], qos: QoS) -> PublishPacket {
    PublishPacket::new(topic, Bytes::from_static(payload)).with_qos(qos, None)
}

/// Returns the next PUBLISH, failing the test on timeout.
pub async fn next_publish(c: &mut RawClient) -> PublishPacket {
    c.recv_publish().await.expect("expected a PUBLISH")
}

/// Asserts that no PUBLISH arrives within [`QUIET`].
pub async fn assert_no_publish(c: &mut RawClient) {
    loop {
        match c.recv_timeout(QUIET).await {
            Ok(Some(MqttPacket::Publish(p))) => panic!("unexpected PUBLISH: {p:?}"),
            Ok(Some(_)) => continue,
            Ok(None) | Err(_) => return,
        }
    }
}

/// Generates a test PKI once per test binary (requires `openssl`).
pub fn test_pki() -> &'static Path {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("pki-{}", env!("CARGO_CRATE_NAME")));
        let status = std::process::Command::new("bash")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/scripts/generate_certs.sh"
            ))
            .arg(&dir)
            .stdout(std::process::Stdio::null())
            .status()
            .expect("run generate_certs.sh");
        assert!(status.success(), "certificate generation failed");
        dir
    })
}

pub fn pki_file(name: &str) -> String {
    test_pki().join(name).to_string_lossy().into_owned()
}
