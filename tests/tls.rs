//! wolfSSL TLS listener: TLS 1.3 / mutual TLS, client identity binding, handshake hardening.

mod common;

use common::*;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use wolf_mqtt::auth::AclEngine;
use wolf_mqtt::broker::{BrokerContext, BrokerOptions};
use wolf_mqtt::client::RawClient;
use wolf_mqtt::protocol::{reason, QoS};
use wolf_mqtt::server::BrokerServer;
use wolf_mqtt::tls::{
    create_tls12_connector, create_tls_acceptor, create_tls_connector, TlsServerConfig, TlsVersion,
};

fn server_config(mutual: bool) -> TlsServerConfig {
    let mut cfg = TlsServerConfig::new(pki_file("server-cert.pem"), pki_file("server-key.pem"));
    if mutual {
        cfg.client_ca_file = Some(pki_file("ca-cert.pem"));
    }
    cfg
}

/// Starts TLS and TCP listeners sharing one broker; returns (tls addr, tcp addr).
async fn start_tls(
    cfg: TlsServerConfig,
    options: BrokerOptions,
) -> (SocketAddr, SocketAddr, BrokerContext) {
    let ctx = BrokerContext::with_options(Arc::new(AclEngine::new(true)), options);
    let acceptor = create_tls_acceptor(&cfg).expect("TLS acceptor");
    let tls = BrokerServer::bind("127.0.0.1:0", ctx.clone())
        .await
        .unwrap()
        .with_tls(acceptor);
    let tcp = BrokerServer::bind("127.0.0.1:0", ctx.clone())
        .await
        .unwrap();
    let (tls_addr, tcp_addr) = (tls.local_addr().unwrap(), tcp.local_addr().unwrap());
    tokio::spawn(tls.run());
    tokio::spawn(tcp.run());
    (tls_addr, tcp_addr, ctx)
}

fn mtls_connector() -> wolf_mqtt::tls::WolfTlsConnector {
    create_tls_connector(
        &pki_file("ca-cert.pem"),
        Some((&pki_file("client-cert.pem"), &pki_file("client-key.pem"))),
    )
    .unwrap()
}

#[tokio::test]
async fn mutual_tls_clients_share_routing_with_tcp_clients() {
    let (tls_addr, tcp_addr, _) = start_tls(server_config(true), BrokerOptions::permissive()).await;
    let connector = mtls_connector();
    let (mut secure, ack) =
        RawClient::connect_tls(tls_addr, "localhost", &connector, v5("client01"))
            .await
            .unwrap();
    assert_eq!(ack.reason_code, 0);
    secure
        .subscribe("secure/#", QoS::ExactlyOnce)
        .await
        .unwrap();

    let mut plain = connect(tcp_addr, v3("plain")).await;
    plain.subscribe("secure/#", QoS::AtMostOnce).await.unwrap();
    let mut publ = connect(tcp_addr, v3("plain-pub")).await;
    publ.publish(msg("secure/data", b"\x00encrypted\xFF", QoS::ExactlyOnce))
        .await
        .unwrap();

    let p = next_publish(&mut secure).await;
    assert_eq!(&p.payload[..], b"\x00encrypted\xFF");
    assert_eq!(p.qos, QoS::ExactlyOnce);
    assert_eq!(
        &next_publish(&mut plain).await.payload[..],
        b"\x00encrypted\xFF"
    );

    // Large messages cross many TLS records intact.
    let big = bytes::Bytes::from(vec![0x5Au8; 200_000]);
    secure
        .publish(
            wolf_mqtt::PublishPacket::new("secure/big", big.clone())
                .with_qos(QoS::AtLeastOnce, None),
        )
        .await
        .unwrap();
    assert_eq!(next_publish(&mut plain).await.payload, big);
}

#[tokio::test]
async fn clients_without_a_certificate_are_rejected_under_mutual_tls() {
    let (tls_addr, _, _) = start_tls(server_config(true), BrokerOptions::permissive()).await;
    let no_cert = create_tls_connector(&pki_file("ca-cert.pem"), None).unwrap();
    let result = RawClient::connect_tls(tls_addr, "localhost", &no_cert, v5("anon")).await;
    assert!(
        result.is_err(),
        "handshake (or the first read) must fail without a client certificate"
    );
}

#[tokio::test]
async fn server_certificate_hostname_is_verified_by_the_connector() {
    let (tls_addr, _, _) = start_tls(server_config(false), BrokerOptions::permissive()).await;
    let connector = create_tls_connector(&pki_file("ca-cert.pem"), None).unwrap();
    assert!(
        RawClient::connect_tls(tls_addr, "wrong.example.com", &connector, v5("x"))
            .await
            .is_err()
    );
    assert!(
        RawClient::connect_tls(tls_addr, "localhost", &connector, v5("x"))
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn client_id_must_match_certificate_identity_when_enabled() {
    let mut options = BrokerOptions::permissive();
    options.verify_client_identity = true;
    let (tls_addr, _, _) = start_tls(server_config(true), options).await;
    let connector = mtls_connector();
    let (_, ack) = RawClient::connect_tls(tls_addr, "localhost", &connector, v5("impostor"))
        .await
        .unwrap();
    assert_eq!(ack.reason_code, reason::NOT_AUTHORIZED);
    let (mut ok, ack) = RawClient::connect_tls(tls_addr, "localhost", &connector, v5("client01"))
        .await
        .unwrap();
    assert_eq!(ack.reason_code, 0);
    ok.ping().await.unwrap();
}

#[tokio::test]
async fn stalled_handshakes_time_out_without_affecting_service() {
    let mut cfg = server_config(false);
    cfg.handshake_timeout = Duration::from_millis(500);
    let (tls_addr, _, ctx) = start_tls(cfg, BrokerOptions::permissive()).await;

    // Open sockets that never start a handshake.
    let mut stalled = Vec::new();
    for _ in 0..20 {
        stalled.push(TcpStream::connect(tls_addr).await.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(900)).await;
    for s in stalled.iter_mut() {
        let mut buf = [0u8; 16];
        let n = tokio::time::timeout(Duration::from_secs(2), s.read(&mut buf))
            .await
            .unwrap()
            .unwrap_or(0);
        assert_eq!(n, 0, "server must close stalled handshakes");
    }
    assert_eq!(
        ctx.metrics
            .connections_active
            .load(std::sync::atomic::Ordering::Acquire),
        0
    );

    let connector = create_tls_connector(&pki_file("ca-cert.pem"), None).unwrap();
    let (mut c, _) = RawClient::connect_tls(tls_addr, "localhost", &connector, v5("after"))
        .await
        .unwrap();
    c.ping().await.unwrap();
}

#[tokio::test]
async fn tls12_minimum_version_accepts_modern_clients() {
    let mut cfg = server_config(false);
    cfg.min_version = TlsVersion::Tls12;
    cfg.ciphers = Some("TLS13-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256".into());
    let (tls_addr, _, _) = start_tls(cfg, BrokerOptions::permissive()).await;
    let connector = create_tls12_connector(&pki_file("ca-cert.pem")).unwrap();
    let (mut c, ack) = RawClient::connect_tls(tls_addr, "localhost", &connector, v3("tls12"))
        .await
        .unwrap();
    assert_eq!(ack.reason_code, 0);
    c.ping().await.unwrap();
}

#[test]
fn invalid_cipher_lists_are_rejected_at_startup() {
    let mut cfg = server_config(false);
    cfg.ciphers = Some("NOT-A-CIPHER".into());
    assert!(create_tls_acceptor(&cfg).is_err());
}

#[tokio::test]
async fn revoked_client_certificates_are_rejected() {
    let mut cfg = server_config(true);
    cfg.crl_file = Some(pki_file("crl.pem"));
    let (tls_addr, _, _) = start_tls(cfg, BrokerOptions::permissive()).await;

    let (mut ok, ack) =
        RawClient::connect_tls(tls_addr, "localhost", &mtls_connector(), v5("client01"))
            .await
            .unwrap();
    assert_eq!(ack.reason_code, 0);
    ok.ping().await.unwrap();

    let revoked = create_tls_connector(
        &pki_file("ca-cert.pem"),
        Some((
            &pki_file("revoked-client-cert.pem"),
            &pki_file("revoked-client-key.pem"),
        )),
    )
    .unwrap();
    assert!(
        RawClient::connect_tls(tls_addr, "localhost", &revoked, v5("revoked01"))
            .await
            .is_err(),
        "a revoked certificate must fail the handshake"
    );
    // Control: the same certificate is accepted when no CRL is configured.
    let (plain_addr, _, _) = start_tls(server_config(true), BrokerOptions::permissive()).await;
    assert!(
        RawClient::connect_tls(plain_addr, "localhost", &revoked, v5("revoked01"))
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn certificate_bound_client_ids_cannot_be_used_over_plain_tcp() {
    let mut options = BrokerOptions::permissive();
    options.verify_client_identity = true;
    let (_, tcp_addr, _) = start_tls(server_config(true), options).await;
    // Without a certificate there is no identity to match, whatever the listener.
    let (_, ack) = RawClient::connect(tcp_addr, v5("client01")).await.unwrap();
    assert_eq!(ack.reason_code, reason::NOT_AUTHORIZED);
}
