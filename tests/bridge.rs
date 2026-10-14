//! Bridges between two live brokers (edge → cloud): topic mapping, loop prevention, buffering
//! through an outage, remote limits, ACL, TLS and MQTT v3.1.1 remotes.

mod common;

use bytes::Bytes;
use common::*;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use wolf_mqtt::auth::{AclEngine, AclRule, Permission, UserAccount};
use wolf_mqtt::bridge;
use wolf_mqtt::broker::{BrokerContext, BrokerOptions};
use wolf_mqtt::config::{BridgeConfig, BridgeDirection, BridgeTopicConfig};
use wolf_mqtt::protocol::{Properties, Property, PublishPacket, QoS};
use wolf_mqtt::server::BrokerServer;
use wolf_mqtt::tls::{create_tls_acceptor, TlsServerConfig};

/// An open broker that also knows the bridge's ACL account (read/write `rules`).
async fn edge_broker(rules: &[&str]) -> TestBroker {
    let acl = AclEngine::new(true);
    acl.add_user(UserAccount::new_custom(
        "bridge",
        "unused",
        rules
            .iter()
            .map(|r| AclRule::new(*r, Permission::ReadWrite))
            .collect(),
    ))
    .await;
    start_broker(BrokerOptions::permissive(), acl).await
}

fn topic(
    pattern: &str,
    direction: BridgeDirection,
    local: &str,
    remote: &str,
) -> BridgeTopicConfig {
    BridgeTopicConfig {
        pattern: pattern.into(),
        direction,
        qos: 1,
        local_prefix: local.into(),
        remote_prefix: remote.into(),
        retain: true,
    }
}

fn bridge_cfg(remote: SocketAddr, topics: Vec<BridgeTopicConfig>) -> BridgeConfig {
    BridgeConfig {
        addresses: vec![remote.to_string()],
        acl_user: "bridge".into(),
        reconnect_min_sec: 1,
        reconnect_max_sec: 1,
        keep_alive_sec: 5,
        topics,
        ..Default::default()
    }
}

/// Waits until the bridge's client is connected at the remote broker.
async fn wait_connected(remote: &BrokerContext, client_id: &str) {
    for _ in 0..100 {
        if remote
            .session_by_client_id(client_id)
            .is_some_and(|s| s.is_connected())
        {
            // Let its SUBSCRIBE reach the remote broker too.
            tokio::time::sleep(Duration::from_millis(150)).await;
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("bridge '{client_id}' did not connect");
}

async fn start_bridge(
    name: &str,
    cfg: BridgeConfig,
    edge: &TestBroker,
    remote: &BrokerContext,
) -> JoinHandle<()> {
    let h = bridge::start(name, cfg, edge.ctx.clone()).await.unwrap();
    wait_connected(remote, &format!("wolfimq-bridge-{name}")).await;
    h
}

#[tokio::test]
async fn out_and_in_topics_are_mapped_with_prefixes() {
    let cloud = open_broker().await;
    let edge = edge_broker(&["site/#"]).await;
    let _b = start_bridge(
        "map",
        bridge_cfg(
            cloud.addr,
            vec![
                topic("telemetry/#", BridgeDirection::Out, "site/", "edge-07/"),
                topic("commands/#", BridgeDirection::In, "site/", "edge-07/"),
            ],
        ),
        &edge,
        &cloud.ctx,
    )
    .await;

    let mut cloud_sub = connect(cloud.addr, v5("cloud-app")).await;
    cloud_sub
        .subscribe("edge-07/telemetry/#", QoS::AtLeastOnce)
        .await
        .unwrap();
    let mut edge_sub = connect(edge.addr, v5("edge-app")).await;
    edge_sub
        .subscribe("site/commands/#", QoS::AtLeastOnce)
        .await
        .unwrap();

    let mut sensor = connect(edge.addr, v5("sensor")).await;
    sensor
        .publish(msg("site/telemetry/temp", b"21.5", QoS::AtLeastOnce))
        .await
        .unwrap();
    let p = next_publish(&mut cloud_sub).await;
    assert_eq!(
        (p.topic.as_str(), &p.payload[..]),
        ("edge-07/telemetry/temp", &b"21.5"[..])
    );

    let mut operator = connect(cloud.addr, v5("operator")).await;
    operator
        .publish(msg("edge-07/commands/reboot", b"now", QoS::AtLeastOnce))
        .await
        .unwrap();
    let p = next_publish(&mut edge_sub).await;
    assert_eq!(
        (p.topic.as_str(), &p.payload[..]),
        ("site/commands/reboot", &b"now"[..])
    );
    // Topics without a rule stay local.
    sensor
        .publish(msg("site/private", b"x", QoS::AtMostOnce))
        .await
        .unwrap();
    assert_no_publish(&mut cloud_sub).await;
}

#[tokio::test]
async fn both_directions_do_not_loop() {
    let cloud = open_broker().await;
    let edge = edge_broker(&["shared/#"]).await;
    let _b = start_bridge(
        "both",
        bridge_cfg(
            cloud.addr,
            vec![topic("shared/#", BridgeDirection::Both, "", "")],
        ),
        &edge,
        &cloud.ctx,
    )
    .await;
    let mut at_edge = connect(edge.addr, v5("edge-watch")).await;
    at_edge
        .subscribe("shared/#", QoS::AtLeastOnce)
        .await
        .unwrap();
    let mut at_cloud = connect(cloud.addr, v5("cloud-watch")).await;
    at_cloud
        .subscribe("shared/#", QoS::AtLeastOnce)
        .await
        .unwrap();

    let mut from_edge = connect(edge.addr, v5("edge-pub")).await;
    from_edge
        .publish(msg("shared/a", b"1", QoS::AtLeastOnce))
        .await
        .unwrap();
    assert_eq!(&next_publish(&mut at_edge).await.payload[..], b"1");
    assert_eq!(&next_publish(&mut at_cloud).await.payload[..], b"1");

    let mut from_cloud = connect(cloud.addr, v5("cloud-pub")).await;
    from_cloud
        .publish(msg("shared/b", b"2", QoS::AtLeastOnce))
        .await
        .unwrap();
    assert_eq!(&next_publish(&mut at_cloud).await.payload[..], b"2");
    assert_eq!(&next_publish(&mut at_edge).await.payload[..], b"2");

    // Exactly one copy each: nothing echoes back across the bridge.
    assert_no_publish(&mut at_edge).await;
    assert_no_publish(&mut at_cloud).await;
}

#[tokio::test]
async fn messages_that_crossed_enough_bridges_are_not_forwarded() {
    let cloud = open_broker().await;
    let edge = edge_broker(&["hop/#"]).await;
    let _b = start_bridge(
        "hops",
        bridge_cfg(
            cloud.addr,
            vec![topic("hop/#", BridgeDirection::Out, "", "")],
        ),
        &edge,
        &cloud.ctx,
    )
    .await;
    let mut at_cloud = connect(cloud.addr, v5("hop-watch")).await;
    at_cloud.subscribe("hop/#", QoS::AtLeastOnce).await.unwrap();
    let mut publ = connect(edge.addr, v5("hop-pub")).await;
    // Already bridged once (max_hops = 1): stays here.
    let bridged = msg("hop/x", b"again", QoS::AtLeastOnce).with_properties(Properties(vec![
        Property::UserProperty(bridge::HOPS_PROPERTY.into(), "1".into()),
    ]));
    publ.publish(bridged).await.unwrap();
    publ.publish(msg("hop/x", b"fresh", QoS::AtLeastOnce))
        .await
        .unwrap();
    let p = next_publish(&mut at_cloud).await;
    assert_eq!(&p.payload[..], b"fresh");
    assert!(p.properties.iter().any(
        |pr| matches!(pr, Property::UserProperty(k, v) if k == bridge::HOPS_PROPERTY && v == "1")
    ));
    assert_no_publish(&mut at_cloud).await;
}

/// TCP proxy that can drop every connection and refuse new ones, to simulate an outage.
struct Proxy {
    addr: SocketAddr,
    down: Arc<AtomicBool>,
    pipes: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl Proxy {
    async fn start(target: SocketAddr) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let down = Arc::new(AtomicBool::new(false));
        let pipes: Arc<Mutex<Vec<JoinHandle<()>>>> = Arc::default();
        let (d, p) = (Arc::clone(&down), Arc::clone(&pipes));
        tokio::spawn(async move {
            while let Ok((mut inbound, _)) = listener.accept().await {
                if d.load(Ordering::SeqCst) {
                    continue; // dropped: connection refused in effect
                }
                let pipe = tokio::spawn(async move {
                    if let Ok(mut outbound) = TcpStream::connect(target).await {
                        let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                    }
                });
                p.lock().unwrap().push(pipe);
            }
        });
        Self { addr, down, pipes }
    }

    fn cut(&self) {
        self.down.store(true, Ordering::SeqCst);
        for p in self.pipes.lock().unwrap().drain(..) {
            p.abort();
        }
    }

    fn restore(&self) {
        self.down.store(false, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn qos1_messages_are_buffered_through_an_outage_in_order() {
    let cloud = open_broker().await;
    let proxy = Proxy::start(cloud.addr).await;
    let edge = edge_broker(&["data/#"]).await;
    let mut cfg = bridge_cfg(
        proxy.addr,
        vec![topic("data/#", BridgeDirection::Out, "", "")],
    );
    cfg.notification_topic = "bridges/outage/state".into();
    let _b = start_bridge("outage", cfg, &edge, &cloud.ctx).await;

    let mut at_cloud = connect(cloud.addr, v5("outage-watch")).await;
    at_cloud
        .subscribe("data/#", QoS::AtLeastOnce)
        .await
        .unwrap();
    at_cloud
        .subscribe("bridges/#", QoS::AtLeastOnce)
        .await
        .unwrap();
    // Retained "1" from when the bridge connected.
    assert_eq!(&next_publish(&mut at_cloud).await.payload[..], b"1");

    proxy.cut();
    // The cloud loses the bridge connection and publishes its Will.
    assert_eq!(&next_publish(&mut at_cloud).await.payload[..], b"0");

    let mut publ = connect(edge.addr, v5("outage-pub")).await;
    for i in 0..20u8 {
        publ.publish(
            PublishPacket::new("data/x", Bytes::from(vec![i])).with_qos(QoS::AtLeastOnce, None),
        )
        .await
        .unwrap();
    }
    proxy.restore();
    let mut got = Vec::new();
    while got.len() < 20 {
        let p = tokio::time::timeout(Duration::from_secs(10), at_cloud.recv_publish())
            .await
            .expect("buffered messages after the outage")
            .unwrap();
        if p.topic == "data/x" {
            got.push(p.payload[0]);
        }
    }
    assert_eq!(got, (0..20).collect::<Vec<u8>>());
}

#[tokio::test]
async fn remote_maximum_qos_and_local_acl_are_respected() {
    let mut options = BrokerOptions::permissive();
    options.maximum_qos = QoS::AtLeastOnce;
    let cloud = start_broker(options, AclEngine::new(true)).await;
    let edge = edge_broker(&["q/#"]).await;
    let _b = start_bridge(
        "limits",
        bridge_cfg(
            cloud.addr,
            vec![
                {
                    let mut t = topic("q/#", BridgeDirection::Out, "", "");
                    t.qos = 2;
                    t
                },
                // The bridge account may not write under forbidden/: these are dropped.
                topic("in/#", BridgeDirection::In, "forbidden/", ""),
            ],
        ),
        &edge,
        &cloud.ctx,
    )
    .await;
    let mut at_cloud = connect(cloud.addr, v5("q-watch")).await;
    at_cloud.subscribe("q/#", QoS::AtLeastOnce).await.unwrap();
    let mut publ = connect(edge.addr, v5("q-pub")).await;
    for payload in [&b"first"[..], &b"second"[..]] {
        publ.publish(
            PublishPacket::new("q/x", Bytes::copy_from_slice(payload))
                .with_qos(QoS::ExactlyOnce, None),
        )
        .await
        .unwrap();
    }
    // QoS 2 is downgraded to the remote's Maximum QoS instead of getting the bridge disconnected.
    for expected in [&b"first"[..], &b"second"[..]] {
        let p = next_publish(&mut at_cloud).await;
        assert_eq!((&p.payload[..], p.qos), (expected, QoS::AtLeastOnce));
    }

    let mut at_edge = connect(edge.addr, v5("acl-watch")).await;
    at_edge.subscribe("#", QoS::AtMostOnce).await.unwrap();
    let mut cloud_pub = connect(cloud.addr, v5("acl-pub")).await;
    cloud_pub
        .publish(msg("in/x", b"blocked", QoS::AtLeastOnce))
        .await
        .unwrap();
    assert_no_publish(&mut at_edge).await;
}

#[tokio::test]
async fn bridge_over_mutual_tls_with_wolfssl() {
    let ctx =
        BrokerContext::with_options(Arc::new(AclEngine::new(true)), BrokerOptions::permissive());
    let mut tls = TlsServerConfig::new(pki_file("server-cert.pem"), pki_file("server-key.pem"));
    tls.client_ca_file = Some(pki_file("ca-cert.pem"));
    let server = BrokerServer::bind("127.0.0.1:0", ctx.clone())
        .await
        .unwrap()
        .with_tls(create_tls_acceptor(&tls).unwrap());
    let tls_addr = server.local_addr().unwrap();
    tokio::spawn(server.run());
    let plain = BrokerServer::bind("127.0.0.1:0", ctx.clone())
        .await
        .unwrap();
    let plain_addr = plain.local_addr().unwrap();
    tokio::spawn(plain.run());

    let edge = edge_broker(&["secure/#"]).await;
    let mut cfg = bridge_cfg(
        tls_addr,
        vec![topic("secure/#", BridgeDirection::Out, "", "")],
    );
    cfg.tls.enabled = true;
    cfg.tls.ca_file = pki_file("ca-cert.pem");
    cfg.tls.cert_file = pki_file("client-cert.pem");
    cfg.tls.key_file = pki_file("client-key.pem");
    cfg.tls.server_name = "localhost".into();
    let _b = start_bridge("mtls", cfg, &edge, &ctx).await;

    let mut at_cloud = connect(plain_addr, v5("tls-watch")).await;
    at_cloud
        .subscribe("secure/#", QoS::AtLeastOnce)
        .await
        .unwrap();
    let mut publ = connect(edge.addr, v5("tls-pub")).await;
    publ.publish(msg("secure/x", b"over wolfSSL", QoS::AtLeastOnce))
        .await
        .unwrap();
    assert_eq!(
        &next_publish(&mut at_cloud).await.payload[..],
        b"over wolfSSL"
    );

    // A wrong server name is refused: the bridge never connects.
    let mut wrong = bridge_cfg(
        tls_addr,
        vec![topic("secure/#", BridgeDirection::Out, "", "")],
    );
    wrong.tls = {
        let mut t = wrong.tls.clone();
        t.enabled = true;
        t.ca_file = pki_file("ca-cert.pem");
        t.cert_file = pki_file("client-cert.pem");
        t.key_file = pki_file("client-key.pem");
        t.server_name = "not-the-broker.example".into();
        t
    };
    let _w = bridge::start("wrong-name", wrong, edge.ctx.clone())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(ctx
        .session_by_client_id("wolfimq-bridge-wrong-name")
        .is_none());
}

#[tokio::test]
async fn mqtt_v311_remote_with_disjoint_topics() {
    let cloud = open_broker().await;
    let edge = edge_broker(&["up/#", "down/#"]).await;
    let mut cfg = bridge_cfg(
        cloud.addr,
        vec![
            topic("up/#", BridgeDirection::Out, "", "edge/"),
            topic("down/#", BridgeDirection::In, "", "edge/"),
        ],
    );
    cfg.protocol_version = 4;
    let _b = start_bridge("v3", cfg, &edge, &cloud.ctx).await;
    let mut at_cloud = connect(cloud.addr, v3("v3-watch")).await;
    at_cloud
        .subscribe("edge/#", QoS::AtLeastOnce)
        .await
        .unwrap();
    let mut at_edge = connect(edge.addr, v3("v3-edge")).await;
    at_edge.subscribe("down/#", QoS::AtLeastOnce).await.unwrap();

    let mut publ = connect(edge.addr, v3("v3-pub")).await;
    publ.publish(msg("up/x", b"u", QoS::AtLeastOnce))
        .await
        .unwrap();
    assert_eq!(next_publish(&mut at_cloud).await.topic, "edge/up/x");
    at_cloud
        .publish(msg("edge/down/y", b"d", QoS::AtLeastOnce))
        .await
        .unwrap();
    assert_eq!(next_publish(&mut at_edge).await.topic, "down/y");
}

#[tokio::test]
async fn bridges_need_an_acl_identity_allowed_to_read_their_topics() {
    let cloud = open_broker().await;
    let edge = edge_broker(&["allowed/#"]).await;
    let err = bridge::start(
        "denied",
        bridge_cfg(
            cloud.addr,
            vec![topic("secret/#", BridgeDirection::Out, "", "")],
        ),
        edge.ctx.clone(),
    )
    .await
    .unwrap_err();
    assert!(err.contains("may not read"), "{err}");
    let mut unknown = bridge_cfg(
        cloud.addr,
        vec![topic("allowed/#", BridgeDirection::Out, "", "")],
    );
    unknown.acl_user = "nobody".into();
    let err = bridge::start("unknown", unknown, edge.ctx.clone())
        .await
        .unwrap_err();
    assert!(err.contains("not defined"), "{err}");
}
