//! Live traffic simulator: exercises a running broker step by step and prints each exchange.

use bytes::Bytes;
use std::time::Duration;
use wolf_mqtt::client::RawClient;
use wolf_mqtt::protocol::{ConnectPacket, MqttPacket, ProtocolVersion, PublishPacket, QoS};
use wolf_mqtt::tls::{create_tls_connector, WolfTlsConnector};

type Error = Box<dyn std::error::Error + Send + Sync>;

const HELP: &str = "\
Usage: wolf-simulate [OPTIONS]

Options:
  --host <HOST>          Broker host (default: 127.0.0.1)
  --port <PORT>          Broker port (default: 1883, or 8883 with --tls)
  --tls                  Connect with TLS (wolfSSL)
  --ca <FILE>            CA certificate for TLS (default: certs/ca-cert.pem)
  --cert <FILE>          Client certificate for mutual TLS (default: certs/client-cert.pem)
  --key <FILE>           Client private key for mutual TLS (default: certs/client-key.pem)
  --no-client-cert       Do not present a client certificate
  --mqtt <3|5>           Protocol version (default: 5)
  -u, --username <USER>  User name (default: superadmin)
  -p, --password <PASS>  Password (default: admin_secret_pass)
  --anonymous            Connect without credentials
  --delay <MS>           Pause between steps (default: 500)
  -h, --help             Show this help";

struct Options {
    host: String,
    port: Option<u16>,
    tls: bool,
    ca: String,
    cert: Option<(String, String)>,
    version: ProtocolVersion,
    credentials: Option<(String, String)>,
    delay: Duration,
}

fn parse() -> Result<Option<Options>, Error> {
    let mut o = Options {
        host: "127.0.0.1".into(),
        port: None,
        tls: false,
        ca: "certs/ca-cert.pem".into(),
        cert: Some((
            "certs/client-cert.pem".into(),
            "certs/client-key.pem".into(),
        )),
        version: ProtocolVersion::V500,
        credentials: Some(("superadmin".into(), "admin_secret_pass".into())),
        delay: Duration::from_millis(500),
    };
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let mut value = || args.next().ok_or_else(|| format!("{a} needs a value"));
        match a.as_str() {
            "--host" => o.host = value()?,
            "--port" => o.port = Some(value()?.parse()?),
            "--tls" => o.tls = true,
            "--ca" => o.ca = value()?,
            "--cert" => {
                let cert = value()?;
                let key = o
                    .cert
                    .take()
                    .map(|(_, k)| k)
                    .unwrap_or_else(|| "certs/client-key.pem".into());
                o.cert = Some((cert, key));
            }
            "--key" => {
                let key = value()?;
                let cert = o
                    .cert
                    .take()
                    .map(|(c, _)| c)
                    .unwrap_or_else(|| "certs/client-cert.pem".into());
                o.cert = Some((cert, key));
            }
            "--no-client-cert" => o.cert = None,
            "--mqtt" => {
                o.version = match value()?.as_str() {
                    "3" | "3.1.1" => ProtocolVersion::V311,
                    "5" | "5.0" => ProtocolVersion::V500,
                    other => return Err(format!("unknown MQTT version '{other}'").into()),
                }
            }
            "-u" | "--username" => {
                let user = value()?;
                let pass = o.credentials.take().map(|(_, p)| p).unwrap_or_default();
                o.credentials = Some((user, pass));
            }
            "-p" | "--password" => {
                let pass = value()?;
                let user = o.credentials.take().map(|(u, _)| u).unwrap_or_default();
                o.credentials = Some((user, pass));
            }
            "--anonymous" => o.credentials = None,
            "--delay" => o.delay = Duration::from_millis(value()?.parse()?),
            "-h" | "--help" => {
                println!("{HELP}");
                return Ok(None);
            }
            other => return Err(format!("unknown argument '{other}' (see --help)").into()),
        }
    }
    Ok(Some(o))
}

struct Sim {
    o: Options,
    tls: Option<WolfTlsConnector>,
}

impl Sim {
    fn connect_packet(&self, client_id: &str) -> ConnectPacket {
        let mut c = ConnectPacket::new(client_id).with_version(self.o.version);
        if let Some((u, p)) = &self.o.credentials {
            c = c.with_credentials(u.clone(), p.clone());
        }
        c
    }

    async fn connect(&self, conn: ConnectPacket) -> Result<RawClient, Error> {
        let id = conn.client_id.clone();
        let port = self.o.port.unwrap_or(if self.o.tls { 8883 } else { 1883 });
        let addr = (self.o.host.as_str(), port);
        let (client, ack) = match &self.tls {
            Some(connector) => RawClient::connect_tls(addr, &self.o.host, connector, conn).await?,
            None => RawClient::connect(addr, conn).await?,
        };
        if ack.reason_code != 0 {
            return Err(format!(
                "broker refused '{id}' with reason code 0x{:02X}",
                ack.reason_code
            )
            .into());
        }
        println!(
            "  [CONNACK] '{id}' connected (session present: {})",
            ack.session_present
        );
        Ok(client)
    }

    async fn pause(&self) {
        tokio::time::sleep(self.o.delay).await;
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let Some(o) = parse()? else {
        return Ok(());
    };
    let tls = if o.tls {
        let cert = o.cert.as_ref().map(|(c, k)| (c.as_str(), k.as_str()));
        Some(create_tls_connector(&o.ca, cert)?)
    } else {
        None
    };
    let sim = Sim { o, tls };
    println!(
        "WolfiMQ traffic simulator ({}, MQTT {:?})",
        if sim.o.tls { "TLS" } else { "TCP" },
        sim.o.version
    );

    println!("\n[1/5] Subscriber connects and subscribes");
    let mut sub = sim.connect(sim.connect_packet("sim-subscriber")).await?;
    for (filter, qos) in [
        ("sim/sensors/+/telemetry", QoS::AtLeastOnce),
        ("sim/alerts/#", QoS::ExactlyOnce),
        ("sim/devices/+/status", QoS::AtLeastOnce),
    ] {
        let code = sub.subscribe(filter, qos).await?;
        println!("  [SUBACK] {filter} -> 0x{code:02X}");
    }
    let listener = tokio::spawn(async move {
        loop {
            match sub.recv_timeout(Duration::from_secs(30)).await {
                Ok(Some(MqttPacket::Publish(p))) => {
                    println!(
                        "  [RECEIVED] {} (QoS {:?}, retain {}): {}",
                        p.topic,
                        p.qos,
                        p.retain,
                        String::from_utf8_lossy(&p.payload)
                    );
                    if sub.ack_publish(&p).await.is_err() {
                        break;
                    }
                }
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => break,
            }
        }
    });
    sim.pause().await;

    println!("\n[2/5] Publisher sends QoS 0, 1 and 2 messages");
    let mut publ = sim.connect(sim.connect_packet("sim-publisher")).await?;
    let samples: [(&str, &str, QoS); 3] = [
        (
            "sim/sensors/temp/telemetry",
            r#"{"temp_c":24.3}"#,
            QoS::AtMostOnce,
        ),
        (
            "sim/sensors/pressure/telemetry",
            r#"{"bar":1.013}"#,
            QoS::AtLeastOnce,
        ),
        (
            "sim/alerts/critical",
            r#"{"alert":"OVERHEAT"}"#,
            QoS::ExactlyOnce,
        ),
    ];
    for (topic, body, qos) in samples {
        let code = publ
            .publish(PublishPacket::new(topic, Bytes::from(body)).with_qos(qos, None))
            .await?;
        println!("  [PUBLISH] {topic} QoS {qos:?} -> 0x{code:02X}");
        sim.pause().await;
    }
    publ.ping().await?;
    println!("  [PINGRESP] keep-alive round trip OK");

    println!("\n[3/5] Retained message and late subscriber");
    publ.publish(
        PublishPacket::new("sim/devices/gw/status", Bytes::from_static(b"ONLINE"))
            .with_qos(QoS::AtLeastOnce, None)
            .with_retain(true),
    )
    .await?;
    let mut late = sim.connect(sim.connect_packet("sim-late")).await?;
    late.subscribe("sim/devices/gw/status", QoS::AtLeastOnce)
        .await?;
    let p = late.recv_publish().await?;
    println!(
        "  [RETAINED] {} (retain {}): {}",
        p.topic,
        p.retain,
        String::from_utf8_lossy(&p.payload)
    );
    late.disconnect().await?;
    publ.publish(PublishPacket::new("sim/devices/gw/status", Bytes::new()).with_retain(true))
        .await?;
    println!("  [CLEARED] retained message removed with an empty payload");
    sim.pause().await;

    println!("\n[4/5] Last Will after an abrupt disconnect");
    let will = PublishPacket::new(
        "sim/devices/crasher/status",
        Bytes::from_static(b"CONNECTION_LOST"),
    )
    .with_qos(QoS::AtLeastOnce, None);
    let crasher = sim
        .connect(sim.connect_packet("sim-crasher").with_will(will))
        .await?;
    drop(crasher.into_stream());
    tokio::time::sleep(Duration::from_secs(1)).await;

    println!("\n[5/5] Clean shutdown");
    publ.disconnect().await?;
    listener.abort();
    println!("\nSimulation finished successfully.");
    Ok(())
}
