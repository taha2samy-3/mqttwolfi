//! MQTT over WebSockets (RFC 6455; MQTT v3.1.1 / v5.0 chapter 6), plain and over wolfSSL TLS.
//!
//! The interoperability client is tokio-tungstenite, an independent implementation used only
//! by the tests; the frame-level tests craft frames by hand.

mod common;

use bytes::{BufMut, Bytes, BytesMut};
use common::*;
use futures_util::{SinkExt, StreamExt};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::Message;
use wolf_mqtt::auth::AclEngine;
use wolf_mqtt::broker::{BrokerContext, BrokerOptions};
use wolf_mqtt::client::{ClientStream, RawClient};
use wolf_mqtt::protocol::{ConnectPacket, MqttPacket, ProtocolVersion, QoS};
use wolf_mqtt::server::BrokerServer;
use wolf_mqtt::tls::{create_tls_acceptor, create_tls_connector, TlsServerConfig};
use wolf_mqtt::ws::WsSettings;

struct WsBroker {
    ws: SocketAddr,
    tcp: SocketAddr,
    ctx: BrokerContext,
}

fn ws_settings() -> WsSettings {
    WsSettings {
        allowed_origins: vec!["https://dashboard.example.com".into()],
        max_frame_size: 64 * 1024,
        ..Default::default()
    }
}

/// A WebSocket listener plus a TCP listener sharing one broker.
async fn start(tls: bool) -> WsBroker {
    let ctx =
        BrokerContext::with_options(Arc::new(AclEngine::new(true)), BrokerOptions::permissive());
    let mut ws = BrokerServer::bind("127.0.0.1:0", ctx.clone())
        .await
        .unwrap()
        .with_websocket(ws_settings());
    if tls {
        let cfg = TlsServerConfig::new(pki_file("server-cert.pem"), pki_file("server-key.pem"));
        ws = ws.with_tls(create_tls_acceptor(&cfg).unwrap());
    }
    let tcp = BrokerServer::bind("127.0.0.1:0", ctx.clone())
        .await
        .unwrap();
    let (ws_addr, tcp_addr) = (ws.local_addr().unwrap(), tcp.local_addr().unwrap());
    tokio::spawn(ws.run());
    tokio::spawn(tcp.run());
    WsBroker {
        ws: ws_addr,
        tcp: tcp_addr,
        ctx,
    }
}

/// Bridges a tokio-tungstenite connection to an in-memory pipe for `RawClient`.
fn pipe_for<S>(ws: tokio_tungstenite::WebSocketStream<S>) -> tokio::io::DuplexStream
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (app, pipe) = tokio::io::duplex(64 * 1024);
    let (mut sink, mut stream) = ws.split();
    let (mut pipe_rd, mut pipe_wr) = tokio::io::split(pipe);
    tokio::spawn(async move {
        while let Some(Ok(msg)) = stream.next().await {
            match msg {
                Message::Binary(b) => {
                    if pipe_wr.write_all(&b).await.is_err() {
                        break;
                    }
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
        let _ = pipe_wr.shutdown().await;
    });
    tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match pipe_rd.read(&mut buf).await {
                Ok(0) | Err(_) => {
                    let _ = sink.close().await;
                    break;
                }
                Ok(n) => {
                    let frame = Message::Binary(Bytes::copy_from_slice(&buf[..n]));
                    if sink.send(frame).await.is_err() {
                        break;
                    }
                }
            }
        }
    });
    app
}

fn request(
    addr: SocketAddr,
    scheme: &str,
    path: &str,
) -> tokio_tungstenite::tungstenite::handshake::client::Request {
    let mut req = format!("{scheme}://localhost:{}{path}", addr.port())
        .into_client_request()
        .unwrap();
    req.headers_mut()
        .insert("Sec-WebSocket-Protocol", HeaderValue::from_static("mqtt"));
    req
}

async fn ws_connect(addr: SocketAddr, connect: ConnectPacket) -> RawClient {
    let tcp = TcpStream::connect(addr).await.unwrap();
    let (ws, resp) = tokio_tungstenite::client_async(request(addr, "ws", "/mqtt"), tcp)
        .await
        .unwrap();
    assert_eq!(resp.headers()["Sec-WebSocket-Protocol"], "mqtt");
    let (client, ack) = RawClient::handshake(ClientStream::Pipe(pipe_for(ws)), connect)
        .await
        .unwrap();
    assert_eq!(ack.reason_code, 0);
    client
}

#[tokio::test]
async fn mqtt_v311_and_v5_work_over_websockets_and_share_routing_with_tcp() {
    let b = start(false).await;
    let mut ws5 = ws_connect(b.ws, v5("browser-5")).await;
    let mut ws3 = ws_connect(b.ws, v3("browser-3")).await;
    ws5.subscribe("dash/#", QoS::ExactlyOnce).await.unwrap();
    ws3.subscribe("dash/#", QoS::AtLeastOnce).await.unwrap();

    let mut tcp = connect(b.tcp, v5("sensor")).await;
    let payload = vec![0xA5u8; 40_000]; // spans several WebSocket frames
    tcp.publish(
        wolf_mqtt::PublishPacket::new("dash/big", Bytes::from(payload.clone()))
            .with_qos(QoS::ExactlyOnce, None),
    )
    .await
    .unwrap();
    assert_eq!(next_publish(&mut ws5).await.payload, payload);
    assert_eq!(next_publish(&mut ws3).await.payload, payload);

    // And the other way round.
    tcp.subscribe("cmd/#", QoS::AtLeastOnce).await.unwrap();
    ws5.publish(msg("cmd/light", b"on", QoS::AtLeastOnce))
        .await
        .unwrap();
    assert_eq!(&next_publish(&mut tcp).await.payload[..], b"on");
    ws5.disconnect().await.unwrap();
}

#[tokio::test]
async fn websockets_over_wolfssl_tls() {
    let b = start(true).await;
    let connector = create_tls_connector(&pki_file("ca-cert.pem"), None).unwrap();
    let tcp = TcpStream::connect(b.ws).await.unwrap();
    let tls = connector.connect("localhost", tcp).await.unwrap();
    let (ws, _) = tokio_tungstenite::client_async(request(b.ws, "wss", "/mqtt"), tls)
        .await
        .unwrap();
    let (mut c, ack) = RawClient::handshake(ClientStream::Pipe(pipe_for(ws)), v5("secure-browser"))
        .await
        .unwrap();
    assert_eq!(ack.reason_code, 0);
    c.subscribe("s/#", QoS::AtLeastOnce).await.unwrap();
    let mut tcp_client = connect(b.tcp, v3("s-pub")).await;
    tcp_client
        .publish(msg("s/x", b"tls+ws", QoS::AtLeastOnce))
        .await
        .unwrap();
    assert_eq!(&next_publish(&mut c).await.payload[..], b"tls+ws");
}

#[tokio::test]
async fn bundled_websocket_client_interoperates_with_the_listener() {
    // The client used by wolf-bench-tls: wolfCrypt mask keys, Sec-WebSocket-Accept check.
    let b = start(false).await;
    let tcp = TcpStream::connect(b.ws).await.unwrap();
    let pipe = wolf_mqtt::ws::connect_client(tcp, "localhost", "/mqtt", 1 << 20)
        .await
        .unwrap();
    let (mut c, ack) = RawClient::handshake(ClientStream::Pipe(pipe), v5("own-client"))
        .await
        .unwrap();
    assert_eq!(ack.reason_code, 0);
    c.subscribe("own/#", QoS::AtLeastOnce).await.unwrap();
    c.publish(msg("own/echo", b"masked", QoS::AtLeastOnce))
        .await
        .unwrap();
    assert_eq!(&next_publish(&mut c).await.payload[..], b"masked");

    // A wrong path is refused with an error, not a hang.
    let tcp = TcpStream::connect(b.ws).await.unwrap();
    assert!(
        wolf_mqtt::ws::connect_client(tcp, "localhost", "/nope", 1 << 20)
            .await
            .is_err()
    );
}

// ── Raw protocol checks ──────────────────────────────────────────────────────────────────

async fn raw_upgrade(addr: SocketAddr, extra: &str) -> (TcpStream, String) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let req = format!(
        "GET /mqtt HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n{extra}\r\n"
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match tokio::time::timeout(Duration::from_secs(3), s.read(&mut byte)).await {
            Ok(Ok(1)) => head.push(byte[0]),
            _ => break,
        }
    }
    (s, String::from_utf8_lossy(&head).into_owned())
}

fn masked(first: u8, payload: &[u8]) -> BytesMut {
    let mask = [9u8, 8, 7, 6];
    let mut out = BytesMut::new();
    out.put_u8(first);
    if payload.len() < 126 {
        out.put_u8(0x80 | payload.len() as u8);
    } else {
        out.put_u8(0x80 | 126);
        out.put_u16(payload.len() as u16);
    }
    out.extend_from_slice(&mask);
    out.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i & 3]));
    out
}

/// Reads server frames until a Close frame and returns its status code.
async fn close_code(s: &mut TcpStream) -> Option<u16> {
    let mut buf = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        let mut i = 0;
        while i + 2 <= buf.len() {
            let len = (buf[i + 1] & 0x7F) as usize;
            let (hdr, len) = match len {
                126 if i + 4 <= buf.len() => {
                    (4, u16::from_be_bytes([buf[i + 2], buf[i + 3]]) as usize)
                }
                126 | 127 => break,
                n => (2, n),
            };
            if i + hdr + len > buf.len() {
                break;
            }
            if buf[i] & 0x0F == 0x8 {
                return (len >= 2).then(|| u16::from_be_bytes([buf[i + hdr], buf[i + hdr + 1]]));
            }
            i += hdr + len;
        }
        let mut chunk = [0u8; 4096];
        match tokio::time::timeout_at(deadline, s.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => buf.extend_from_slice(&chunk[..n]),
            _ => return None,
        }
    }
}

#[tokio::test]
async fn upgrade_response_follows_rfc6455_and_mqtt_chapter_6() {
    let b = start(false).await;
    let (_, head) = raw_upgrade(b.ws, "Sec-WebSocket-Protocol: mqtt\r\n").await;
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");
    assert!(head.contains("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));
    assert!(head.contains("Sec-WebSocket-Protocol: mqtt\r\n"));
}

#[tokio::test]
async fn bad_upgrades_are_refused_with_http_errors() {
    let b = start(false).await;
    let (_, head) = raw_upgrade(b.ws, "").await;
    assert!(head.starts_with("HTTP/1.1 400"), "no subprotocol: {head}");
    let (_, head) = raw_upgrade(
        b.ws,
        "Sec-WebSocket-Protocol: mqtt\r\nOrigin: https://evil.example\r\n",
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 403"), "foreign origin: {head}");
    let (_, head) = raw_upgrade(
        b.ws,
        "Sec-WebSocket-Protocol: mqtt\r\nOrigin: https://dashboard.example.com\r\n",
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 101"), "allowed origin: {head}");
    let mut big = String::from("Sec-WebSocket-Protocol: mqtt\r\n");
    for i in 0..400 {
        big.push_str(&format!("X-Filler-{i}: {}\r\n", "y".repeat(20)));
    }
    let (_, head) = raw_upgrade(b.ws, &big).await;
    assert!(
        head.starts_with("HTTP/1.1 431"),
        "oversized headers: {head}"
    );
}

#[tokio::test]
async fn packets_split_across_frames_and_several_per_frame_are_handled() {
    let b = start(false).await;
    let (mut s, head) = raw_upgrade(b.ws, "Sec-WebSocket-Protocol: mqtt\r\n").await;
    assert!(head.starts_with("HTTP/1.1 101"));
    let connect = MqttPacket::Connect(v3("framed"))
        .to_bytes(ProtocolVersion::V311)
        .unwrap();
    let ping = MqttPacket::PingReq.to_bytes(ProtocolVersion::V311).unwrap();
    // CONNECT split over a fragmented message, then CONNECT's tail and PINGREQ in one frame.
    let (a, rest) = connect.split_at(5);
    let mut frames = masked(0x02, a); // binary, not final
    let mut tail = rest.to_vec();
    tail.extend_from_slice(&ping);
    frames.extend_from_slice(&masked(0x80, &tail)); // final continuation
    s.write_all(&frames).await.unwrap();

    let mut got = Vec::new();
    let mut buf = [0u8; 64];
    while got.len() < 2 + 4 + 2 {
        let n = tokio::time::timeout(Duration::from_secs(3), s.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert!(n > 0);
        got.extend_from_slice(&buf[..n]);
    }
    // Server frames: binary CONNACK (0x82 0x04 20 02 00 00) then binary PINGRESP (0x82 0x02 d0 00),
    // possibly in a single frame.
    let payload: Vec<u8> = if got[1] == 6 {
        got[2..8].to_vec()
    } else {
        [&got[2..6], &got[8..10]].concat()
    };
    assert_eq!(payload, vec![0x20, 0x02, 0x00, 0x00, 0xD0, 0x00]);
}

#[tokio::test]
async fn text_and_unmasked_frames_close_the_connection() {
    let b = start(false).await;
    let (mut s, _) = raw_upgrade(b.ws, "Sec-WebSocket-Protocol: mqtt\r\n").await;
    s.write_all(&masked(0x81, b"hello")).await.unwrap();
    assert_eq!(
        close_code(&mut s).await,
        Some(1003),
        "text frame (MQTT-6.0.0-1)"
    );

    let (mut s, _) = raw_upgrade(b.ws, "Sec-WebSocket-Protocol: mqtt\r\n").await;
    s.write_all(&[0x82, 0x02, 0x10, 0x00]).await.unwrap();
    assert_eq!(
        close_code(&mut s).await,
        Some(1002),
        "unmasked client frame"
    );
}

#[tokio::test]
async fn pings_are_answered_and_a_client_close_ends_the_session_with_its_will() {
    let b = start(false).await;
    let mut watcher = connect(b.tcp, v3("ws-watch")).await;
    watcher.subscribe("ws/will", QoS::AtMostOnce).await.unwrap();

    let (mut s, _) = raw_upgrade(b.ws, "Sec-WebSocket-Protocol: mqtt\r\n").await;
    let connect =
        MqttPacket::Connect(v3("ws-will").with_will(msg("ws/will", b"gone", QoS::AtMostOnce)))
            .to_bytes(ProtocolVersion::V311)
            .unwrap();
    s.write_all(&masked(0x82, &connect)).await.unwrap();
    s.write_all(&masked(0x89, b"are-you-there")).await.unwrap();
    let mut got = Vec::new();
    let mut buf = [0u8; 128];
    while !got.windows(15).any(|w| w == b"\x8a\x0dare-you-there") {
        let n = tokio::time::timeout(Duration::from_secs(3), s.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert!(n > 0, "connection closed before PONG");
        got.extend_from_slice(&buf[..n]);
    }
    // Close without MQTT DISCONNECT: an abnormal end, so the Will is published.
    s.write_all(&masked(0x88, &1000u16.to_be_bytes()))
        .await
        .unwrap();
    assert_eq!(close_code(&mut s).await, Some(1000));
    assert_eq!(&next_publish(&mut watcher).await.payload[..], b"gone");
    assert!(b.ctx.session_by_client_id("ws-will").is_none());
}

#[tokio::test]
async fn idle_upgrades_are_dropped_after_the_connect_timeout() {
    let mut options = BrokerOptions::permissive();
    options.connect_timeout = Duration::from_millis(300);
    let ctx = BrokerContext::with_options(Arc::new(AclEngine::new(true)), options);
    let server = BrokerServer::bind("127.0.0.1:0", ctx.clone())
        .await
        .unwrap()
        .with_websocket(WsSettings::default());
    let addr = server.local_addr().unwrap();
    tokio::spawn(server.run());
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(b"GET /mqtt HTTP/1.1\r\nHost: x\r\n")
        .await
        .unwrap();
    let mut buf = [0u8; 16];
    let n = tokio::time::timeout(Duration::from_secs(3), s.read(&mut buf))
        .await
        .expect("the broker must drop a stalled upgrade")
        .unwrap_or(0);
    assert_eq!(n, 0);
}
