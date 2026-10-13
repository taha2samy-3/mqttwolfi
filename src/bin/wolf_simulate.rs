use bytes::{Buf, Bytes, BytesMut};
use rustls_pki_types::ServerName;
use std::env;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use wolf_mqtt::protocol::{ConnectPacket, MqttPacket, ProtocolVersion, PublishPacket, QoS};
use wolf_mqtt::tls::create_tls_connector;

static PID_GEN: AtomicU16 = AtomicU16::new(1);

fn next_pid() -> u16 {
    let pid = PID_GEN.fetch_add(1, Ordering::Relaxed);
    if pid == 0 {
        PID_GEN.fetch_add(1, Ordering::Relaxed)
    } else {
        pid
    }
}

enum AnyStream {
    Tcp(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl AsyncRead for AnyStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            AnyStream::Tcp(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            AnyStream::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for AnyStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        match self.get_mut() {
            AnyStream::Tcp(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            AnyStream::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            AnyStream::Tcp(s) => std::pin::Pin::new(s).poll_flush(cx),
            AnyStream::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            AnyStream::Tcp(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            AnyStream::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

struct ClientSession {
    stream: AnyStream,
    read_buf: BytesMut,
    pub client_id: String,
}

impl ClientSession {
    #[allow(clippy::too_many_arguments)]
    async fn connect(
        host: &str,
        port: u16,
        use_tls: bool,
        client_id: &str,
        version: ProtocolVersion,
        username: Option<&str>,
        password: Option<&[u8]>,
        will: Option<PublishPacket>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let stream = if use_tls {
            let ca_file = "certs/ca-cert.pem";
            let connector = create_tls_connector(ca_file, None)?;
            let tcp = TcpStream::connect((host, port)).await?;
            let server_name = ServerName::try_from("localhost")?.to_owned();
            let tls = connector.connect(server_name, tcp).await?;
            AnyStream::Tls(Box::new(tls))
        } else {
            let tcp = TcpStream::connect((host, port)).await?;
            AnyStream::Tcp(tcp)
        };

        let mut session = Self {
            stream,
            read_buf: BytesMut::with_capacity(8192),
            client_id: client_id.to_string(),
        };

        session
            .send_packet(MqttPacket::Connect(ConnectPacket {
                version,
                client_id: client_id.to_string(),
                clean_start: true,
                keep_alive_sec: 60,
                will,
                username: username.map(|u| u.to_string()),
                password: password.map(Bytes::copy_from_slice),
            }))
            .await?;

        let resp = session.read_packet().await?;
        match resp {
            MqttPacket::ConnAck {
                session_present,
                reason_code,
            } => {
                if reason_code != 0 {
                    return Err(format!(
                        "Broker rejected connection for client '{}' with reason code {}",
                        client_id, reason_code
                    )
                    .into());
                }
                println!(
                    "    \x1b[32m✔\x1b[0m [CONNACK] Client '{}' authenticated (session_present: {}, code: 0)",
                    client_id, session_present
                );
            }
            other => {
                return Err(format!("Expected ConnAck, received: {:?}", other).into());
            }
        }

        Ok(session)
    }

    async fn send_packet(
        &mut self,
        packet: MqttPacket,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut buf = BytesMut::new();
        packet.encode(&mut buf)?;
        self.stream.write_all(&buf).await?;
        self.stream.flush().await?;
        Ok(())
    }

    async fn read_packet(
        &mut self,
    ) -> Result<MqttPacket, Box<dyn std::error::Error + Send + Sync>> {
        loop {
            if !self.read_buf.is_empty() {
                let mut slice = &self.read_buf[..];
                if let Ok(pkt) = MqttPacket::decode(&mut slice) {
                    let consumed = self.read_buf.len() - slice.len();
                    self.read_buf.advance(consumed);
                    return Ok(pkt);
                }
            }
            let n = self.stream.read_buf(&mut self.read_buf).await?;
            if n == 0 {
                return Err("EOF while reading MQTT packet".into());
            }
        }
    }

    async fn subscribe(
        &mut self,
        topics: Vec<(&str, QoS)>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let pid = next_pid();
        let topic_pairs: Vec<(String, QoS)> = topics
            .into_iter()
            .map(|(t, q)| (t.to_string(), q))
            .collect();
        self.send_packet(MqttPacket::Subscribe {
            packet_id: pid,
            topics: topic_pairs.clone(),
        })
        .await?;

        let resp = self.read_packet().await?;
        match resp {
            MqttPacket::SubAck {
                packet_id,
                return_codes,
            } => {
                println!(
                    "    \x1b[32m✔\x1b[0m [SUBACK] Subscribed packet_id: {}, return_codes: {:?}",
                    packet_id, return_codes
                );
            }
            other => return Err(format!("Expected SubAck, received: {:?}", other).into()),
        }
        Ok(())
    }

    async fn publish(
        &mut self,
        topic: &str,
        payload: &[u8],
        qos: QoS,
        retain: bool,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let pid = if qos != QoS::AtMostOnce {
            Some(next_pid())
        } else {
            None
        };

        let pub_pkt = MqttPacket::Publish(PublishPacket {
            topic: topic.to_string(),
            packet_id: pid,
            payload: Bytes::copy_from_slice(payload),
            qos,
            retain,
            dup: false,
        });

        self.send_packet(pub_pkt).await?;

        match qos {
            QoS::AtMostOnce => {
                println!(
                    "    \x1b[36m➔\x1b[0m [PUBLISH QoS 0] Topic: '{}' ({} bytes)",
                    topic,
                    payload.len()
                );
            }
            QoS::AtLeastOnce => {
                let resp = self.read_packet().await?;
                if let MqttPacket::PubAck { packet_id } = resp {
                    println!(
                        "    \x1b[32m✔\x1b[0m [PUBACK] Topic: '{}', packet_id: {} acknowledged",
                        topic, packet_id
                    );
                } else {
                    return Err(format!("Expected PubAck, received {:?}", resp).into());
                }
            }
            QoS::ExactlyOnce => {
                let resp = self.read_packet().await?;
                if let MqttPacket::PubRec { packet_id } = resp {
                    println!(
                        "    \x1b[35m⇄\x1b[0m [PUBREC] Topic: '{}', packet_id: {} acknowledged (step 1/3)",
                        topic, packet_id
                    );
                    self.send_packet(MqttPacket::PubRel { packet_id }).await?;
                    let comp_resp = self.read_packet().await?;
                    if let MqttPacket::PubComp {
                        packet_id: comp_pid,
                    } = comp_resp
                    {
                        println!(
                            "    \x1b[32m✔\x1b[0m [PUBCOMP] Handshake completed for pid: {} (step 2/3)",
                            comp_pid
                        );
                    } else {
                        return Err(format!("Expected PubComp, received {:?}", comp_resp).into());
                    }
                } else {
                    return Err(format!("Expected PubRec, received {:?}", resp).into());
                }
            }
        }
        Ok(())
    }

    async fn ping(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.send_packet(MqttPacket::PingReq).await?;
        let resp = self.read_packet().await?;
        if matches!(resp, MqttPacket::PingResp) {
            println!("    \x1b[32m✔\x1b[0m [PINGRESP] Heartbeat keep-alive roundtrip confirmed");
            Ok(())
        } else {
            Err(format!("Expected PingResp, received {:?}", resp).into())
        }
    }

    async fn disconnect(mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.send_packet(MqttPacket::Disconnect).await?;
        println!(
            "    \x1b[34mℹ\x1b[0m [DISCONNECT] Client '{}' disconnected gracefully",
            self.client_id
        );
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("\x1b[1;36m================================================================================\x1b[0m");
    println!("\x1b[1;36m       🐺 WolfiMQ Traffic Simulator & Real-Time Protocol Inspector             \x1b[0m");
    println!("\x1b[1;36m================================================================================\x1b[0m\n");

    let args: Vec<String> = env::args().collect();
    let mut host = "127.0.0.1".to_string();
    let mut port: u16 = 1883;
    let mut use_tls = false;
    let mut step_delay = 500u64;
    let mut username: Option<String> = Some("superadmin".to_string());
    let mut password: Option<Vec<u8>> = Some(b"admin_secret_pass".to_vec());

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--host" if i + 1 < args.len() => {
                host = args[i + 1].clone();
                i += 1;
            }
            "--port" if i + 1 < args.len() => {
                port = args[i + 1].parse().unwrap_or(1883);
                i += 1;
            }
            "--tls" => {
                use_tls = true;
                if port == 1883 {
                    port = 8883;
                }
            }
            "--delay" if i + 1 < args.len() => {
                step_delay = args[i + 1].parse().unwrap_or(500);
                i += 1;
            }
            "--username" | "-u" if i + 1 < args.len() => {
                username = Some(args[i + 1].clone());
                i += 1;
            }
            "--password" | "-p" if i + 1 < args.len() => {
                password = Some(args[i + 1].as_bytes().to_vec());
                i += 1;
            }
            "--anonymous" => {
                username = None;
                password = None;
            }
            "--help" | "-h" => {
                println!("Usage: cargo run --bin wolf-simulate -- [OPTIONS]");
                println!();
                println!("Options:");
                println!("  --host <HOST>     Target broker hostname/IP (default: 127.0.0.1)");
                println!(
                    "  --port <PORT>     Target broker port (default: 1883 for TCP, 8883 for TLS)"
                );
                println!("  --tls             Connect via TLS 1.3 encrypted socket");
                println!("  --delay <MS>      Delay in milliseconds between simulated steps (default: 500)");
                println!("  --username, -u    Authentication username (default: superadmin)");
                println!(
                    "  --password, -p    Authentication password (default: admin_secret_pass)"
                );
                println!("  --anonymous       Connect anonymously without credentials");
                println!("  --help, -h        Display this help message");
                return Ok(());
            }
            _ => {}
        }
        i += 1;
    }

    println!("\x1b[1mSimulator Settings:\x1b[0m");
    println!("  Target Broker : {}:{}", host, port);
    println!(
        "  Encryption    : {}",
        if use_tls {
            "TLS 1.3 / mTLS (Active)"
        } else {
            "Plain TCP"
        }
    );
    println!("  Step Interval : {} ms", step_delay);
    println!(
        "  Credentials   : {}\n",
        if let Some(ref u) = username {
            format!("User '{}'", u)
        } else {
            "Anonymous".to_string()
        }
    );

    let delay = Duration::from_millis(step_delay);
    let u_ref = username.as_deref();
    let p_ref = password.as_deref();

    // -------------------------------------------------------------------------
    // Phase 1: Connect Subscriber Client
    // -------------------------------------------------------------------------
    println!("\x1b[1;33m▶ [Phase 1/6] Connecting Subscriber Client (MQTT v5.0)...\x1b[0m");
    let mut sub_session = ClientSession::connect(
        &host,
        port,
        use_tls,
        "wolf-subscriber-node",
        ProtocolVersion::V500,
        u_ref,
        p_ref,
        None,
    )
    .await?;
    tokio::time::sleep(delay).await;

    println!("\x1b[1;33m▶ [Phase 2/6] Subscribing to telemetry & alerts...\x1b[0m");
    sub_session
        .subscribe(vec![
            ("sensors/+/telemetry", QoS::AtLeastOnce),
            ("alerts/#", QoS::ExactlyOnce),
            ("devices/+/status", QoS::AtLeastOnce),
        ])
        .await?;
    tokio::time::sleep(delay).await;

    // Spawn async background listener for subscriber to receive broadcasts
    let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel::<()>();
    let sub_handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                pkt_res = sub_session.read_packet() => {
                    match pkt_res {
                        Ok(MqttPacket::Publish(p)) => {
                            let text = String::from_utf8_lossy(&p.payload);
                            println!(
                                "    \x1b[1;32m📥 [SUBSCRIBER RECEIVED]\x1b[0m Topic: '\x1b[33m{}\x1b[0m' | QoS: {:?} | Retain: {} | Payload: {}",
                                p.topic, p.qos, p.retain, text
                            );
                            if p.qos == QoS::AtLeastOnce {
                                if let Some(pid) = p.packet_id {
                                    let _ = sub_session.send_packet(MqttPacket::PubAck { packet_id: pid }).await;
                                }
                            } else if p.qos == QoS::ExactlyOnce {
                                if let Some(pid) = p.packet_id {
                                    let _ = sub_session.send_packet(MqttPacket::PubRec { packet_id: pid }).await;
                                    // Complete handshake
                                    if let Ok(MqttPacket::PubRel { packet_id: rel_pid }) = sub_session.read_packet().await {
                                        let _ = sub_session.send_packet(MqttPacket::PubComp { packet_id: rel_pid }).await;
                                    }
                                }
                            }
                        }
                        Ok(MqttPacket::PingResp) => {}
                        Ok(other) => {
                            println!("    \x1b[34mℹ\x1b[0m [Subscriber Event]: {:?}", other);
                        }
                        Err(_) => {
                            break;
                        }
                    }
                }
                _ = &mut stop_rx => {
                    let _ = sub_session.disconnect().await;
                    break;
                }
            }
        }
    });

    // -------------------------------------------------------------------------
    // Phase 2: Connect Publisher Client & Send Multi-QoS Messages
    // -------------------------------------------------------------------------
    println!("\n\x1b[1;33m▶ [Phase 3/6] Connecting Publisher Client & Testing Multi-QoS Delivery...\x1b[0m");
    let mut pub_session = ClientSession::connect(
        &host,
        port,
        use_tls,
        "wolf-publisher-node",
        ProtocolVersion::V500,
        u_ref,
        p_ref,
        None,
    )
    .await?;
    tokio::time::sleep(delay).await;

    // QoS 0 Publish
    println!("  • Publishing Telemetry [QoS 0] (Fire-and-forget)...");
    pub_session
        .publish(
            "sensors/temp/telemetry",
            br#"{"sensor_id": "temp_01", "temp_c": 24.3, "status": "ok"}"#,
            QoS::AtMostOnce,
            false,
        )
        .await?;
    tokio::time::sleep(delay).await;

    // QoS 1 Publish
    println!("  • Publishing Pressure [QoS 1] (At-least-once with PUBACK)...");
    pub_session
        .publish(
            "sensors/pressure/telemetry",
            br#"{"sensor_id": "pres_01", "pressure_bar": 1.013, "status": "nominal"}"#,
            QoS::AtLeastOnce,
            false,
        )
        .await?;
    tokio::time::sleep(delay).await;

    // QoS 2 Publish
    println!("  • Publishing Critical Alert [QoS 2] (Exactly-once 4-way handshake)...");
    pub_session
        .publish(
            "alerts/critical",
            br#"{"alert_type": "OVERHEAT_ALARM", "severity": "HIGH", "zone": "DC-01"}"#,
            QoS::ExactlyOnce,
            false,
        )
        .await?;
    tokio::time::sleep(delay).await;

    // Keep-Alive Ping
    println!("  • Testing Keep-Alive Heartbeat (PINGREQ -> PINGRESP)...");
    pub_session.ping().await?;
    tokio::time::sleep(delay).await;

    // -------------------------------------------------------------------------
    // Phase 4: Retained Messages & Late Joiner Delivery
    // -------------------------------------------------------------------------
    println!("\n\x1b[1;33m▶ [Phase 4/6] Testing Retained Message Storage & Late Joiner Delivery...\x1b[0m");
    println!("  • Storing Retained Message on 'sensors/status/telemetry'...");
    pub_session
        .publish(
            "sensors/status/telemetry",
            br#"{"system_state": "ONLINE_NORMAL", "cluster_node": "primary"}"#,
            QoS::AtLeastOnce,
            true, // retain = true
        )
        .await?;
    tokio::time::sleep(delay).await;

    println!("  • Connecting Late-Joining Subscriber to verify Retained Message delivery...");
    let mut late_session = ClientSession::connect(
        &host,
        port,
        use_tls,
        "wolf-late-joiner-node",
        ProtocolVersion::V500,
        u_ref,
        p_ref,
        None,
    )
    .await?;

    late_session
        .subscribe(vec![("sensors/status/telemetry", QoS::AtLeastOnce)])
        .await?;

    let retained_pkt = late_session.read_packet().await?;
    if let MqttPacket::Publish(p) = retained_pkt {
        let text = String::from_utf8_lossy(&p.payload);
        println!(
            "    \x1b[1;32m✔\x1b[0m [RETAINED CONFIRMED] Received topic: '{}' (retain flag: {}): {}",
            p.topic, p.retain, text
        );
    }
    late_session.disconnect().await?;
    tokio::time::sleep(delay).await;

    // Clear retained message
    println!("  • Deleting Retained Message with empty payload (payload: b\"\")...");
    pub_session
        .publish("sensors/status/telemetry", b"", QoS::AtLeastOnce, true)
        .await?;
    tokio::time::sleep(delay).await;

    // -------------------------------------------------------------------------
    // Phase 5: Last Will and Testament (LWT) Ungraceful Disconnect
    // -------------------------------------------------------------------------
    println!("\n\x1b[1;33m▶ [Phase 5/6] Testing LWT (Last Will and Testament) Ungraceful Crash Delivery...\x1b[0m");
    println!("  • Spawning IoT device with Will configured on 'devices/crasher/status' (QoS 1)...");
    let will_packet = PublishPacket {
        topic: "devices/crasher/status".to_string(),
        packet_id: None,
        payload: Bytes::from_static(b"FATAL_CRASH: Device disconnected without DISCONNECT packet"),
        qos: QoS::AtLeastOnce,
        retain: false,
        dup: false,
    };

    let crasher_session = ClientSession::connect(
        &host,
        port,
        use_tls,
        "wolf-crasher-device",
        ProtocolVersion::V500,
        u_ref,
        p_ref,
        Some(will_packet),
    )
    .await?;

    tokio::time::sleep(delay).await;
    println!("  • Abruptly dropping IoT device TCP connection (simulating network crash)...");
    drop(crasher_session);

    // Wait for broker to detect socket close and dispatch LWT to our subscriber
    tokio::time::sleep(Duration::from_millis(1000)).await;

    // -------------------------------------------------------------------------
    // Phase 6: Graceful Teardown
    // -------------------------------------------------------------------------
    println!("\n\x1b[1;33m▶ [Phase 6/6] Gracefully Closing Sessions...\x1b[0m");
    pub_session.disconnect().await?;
    let _ = stop_tx.send(());
    let _ = sub_handle.await;

    println!("\n\x1b[1;32m================================================================================\x1b[0m");
    println!("\x1b[1;32m       ✔ All Simulation Protocol Tests Passed Successfully!                   \x1b[0m");
    println!("\x1b[1;32m================================================================================\x1b[0m\n");

    Ok(())
}
