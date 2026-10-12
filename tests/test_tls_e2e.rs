use bytes::{Buf, Bytes, BytesMut};
use rustls_pki_types::ServerName;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::client::TlsStream;
use wolf_mqtt::protocol::{ConnectPacket, MqttPacket, ProtocolVersion, PublishPacket, QoS};
use wolf_mqtt::server::BrokerServer;
use wolf_mqtt::tls::{create_tls_acceptor, create_tls_connector};

async fn send_packet(stream: &mut TlsStream<TcpStream>, packet: MqttPacket) {
    let mut buf = BytesMut::new();
    packet.encode(&mut buf).expect("Packet encode failed");
    stream.write_all(&buf).await.expect("TLS socket write failed");
}

async fn read_packet(stream: &mut TlsStream<TcpStream>, buf: &mut BytesMut) -> MqttPacket {
    loop {
        if !buf.is_empty() {
            let mut slice = &buf[..];
            if let Ok(pkt) = MqttPacket::decode(&mut slice) {
                let consumed = buf.len() - slice.len();
                buf.advance(consumed);
                return pkt;
            }
        }
        let n = stream.read_buf(buf).await.expect("TLS socket read failed");
        assert!(n > 0, "Unexpected EOF during TLS socket read");
    }
}

#[tokio::test]
async fn test_tls13_mtls_e2e_pub_sub_exchange() {
    // 1. Setup TLS Acceptor with server cert & CA for mTLS
    let acceptor = create_tls_acceptor(
        "certs/server-cert.pem",
        "certs/server-key.pem",
        Some("certs/ca-cert.pem"),
    )
    .expect("Failed to create TLS acceptor");

    let server = BrokerServer::bind("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr().unwrap();

    tokio::spawn(async move {
        let _ = server.run_tls(acceptor).await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // 2. Setup TLS Connector with client cert & key for mTLS
    let connector = create_tls_connector(
        "certs/ca-cert.pem",
        Some(("certs/client-cert.pem", "certs/client-key.pem")),
    )
    .expect("Failed to create TLS connector");

    let server_name = ServerName::try_from("localhost")
        .expect("Invalid server name")
        .to_owned();

    // 3. Connect Subscriber over TLS 1.3
    let tcp_sub = TcpStream::connect(addr).await.unwrap();
    let mut tls_sub = connector
        .connect(server_name.clone(), tcp_sub)
        .await
        .expect("Subscriber TLS handshake failed");

    let mut sub_buf = BytesMut::with_capacity(4096);

    send_packet(
        &mut tls_sub,
        MqttPacket::Connect(ConnectPacket {
            version: ProtocolVersion::V500,
            client_id: "tls_sub_client".into(),
            clean_start: true,
            keep_alive_sec: 60,
            will: None,
        }),
    )
    .await;

    let connack = timeout(Duration::from_secs(3), read_packet(&mut tls_sub, &mut sub_buf))
        .await
        .expect("ConnAck timeout");
    assert_eq!(
        connack,
        MqttPacket::ConnAck {
            session_present: false,
            reason_code: 0x00,
        }
    );

    // Subscribe to "tls/secure/alerts"
    send_packet(
        &mut tls_sub,
        MqttPacket::Subscribe {
            packet_id: 1,
            topics: vec![("tls/secure/alerts".into(), QoS::AtLeastOnce)],
        },
    )
    .await;

    let suback = timeout(Duration::from_secs(3), read_packet(&mut tls_sub, &mut sub_buf))
        .await
        .expect("SubAck timeout");
    assert_eq!(
        suback,
        MqttPacket::SubAck {
            packet_id: 1,
            return_codes: vec![0x01],
        }
    );

    // 4. Connect Publisher over TLS 1.3
    let tcp_pub = TcpStream::connect(addr).await.unwrap();
    let mut tls_pub = connector
        .connect(server_name, tcp_pub)
        .await
        .expect("Publisher TLS handshake failed");

    let mut pub_buf = BytesMut::with_capacity(4096);

    send_packet(
        &mut tls_pub,
        MqttPacket::Connect(ConnectPacket {
            version: ProtocolVersion::V500,
            client_id: "tls_pub_client".into(),
            clean_start: true,
            keep_alive_sec: 60,
            will: None,
        }),
    )
    .await;

    let pub_connack = timeout(Duration::from_secs(3), read_packet(&mut tls_pub, &mut pub_buf))
        .await
        .expect("Publisher ConnAck timeout");
    assert!(matches!(pub_connack, MqttPacket::ConnAck { .. }));

    // Send QoS 1 Publish over TLS
    send_packet(
        &mut tls_pub,
        MqttPacket::Publish(PublishPacket {
            topic: "tls/secure/alerts".into(),
            qos: QoS::AtLeastOnce,
            retain: false,
            dup: false,
            packet_id: Some(777),
            payload: Bytes::from_static(b"MISSION_CRITICAL_ENCRYPTED_TELEMETRY"),
        }),
    )
    .await;

    // Publisher receives PUBACK over TLS
    let puback = timeout(Duration::from_secs(3), read_packet(&mut tls_pub, &mut pub_buf))
        .await
        .expect("PubAck timeout");
    assert_eq!(puback, MqttPacket::PubAck { packet_id: 777 });

    // Subscriber receives the message over TLS
    let delivered = timeout(Duration::from_secs(3), read_packet(&mut tls_sub, &mut sub_buf))
        .await
        .expect("Subscriber delivery timeout");
    if let MqttPacket::Publish(p) = delivered {
        assert_eq!(p.topic, "tls/secure/alerts");
        assert_eq!(p.payload, Bytes::from_static(b"MISSION_CRITICAL_ENCRYPTED_TELEMETRY"));
    } else {
        panic!("Expected Publish, got {:?}", delivered);
    }

    // Ping / Pong over TLS
    send_packet(&mut tls_sub, MqttPacket::PingReq).await;
    let pingresp = timeout(Duration::from_secs(3), read_packet(&mut tls_sub, &mut sub_buf))
        .await
        .unwrap();
    assert_eq!(pingresp, MqttPacket::PingResp);

    // Clean disconnects
    send_packet(&mut tls_pub, MqttPacket::Disconnect).await;
    send_packet(&mut tls_sub, MqttPacket::Disconnect).await;
}
