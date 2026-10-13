//! Authentication and topic authorization end to end, using the shipped `config/acl.conf`.

mod common;

use common::*;
use std::net::SocketAddr;
use std::time::Duration;
use wolf_mqtt::auth::AclEngine;
use wolf_mqtt::broker::BrokerOptions;
use wolf_mqtt::client::RawClient;
use wolf_mqtt::protocol::{connack_v3, reason, MqttPacket, QoS};

async fn acl_broker(options: BrokerOptions, allow_anonymous: bool) -> TestBroker {
    let acl = AclEngine::new(allow_anonymous);
    acl.load_from_acl_file("config/acl.conf")
        .await
        .expect("acl.conf");
    start_broker(options, acl).await
}

async fn login(addr: SocketAddr, client_id: &str, user: &str, pass: &str) -> RawClient {
    connect(addr, v5(client_id).with_credentials(user, pass.to_owned())).await
}

#[tokio::test]
async fn credentials_are_verified() {
    let b = acl_broker(BrokerOptions::permissive(), false).await;
    login(b.addr, "admin-1", "superadmin", "admin_secret_pass")
        .await
        .ping()
        .await
        .unwrap();

    let (_, ack) = RawClient::connect(b.addr, v3("x").with_credentials("superadmin", "nope"))
        .await
        .unwrap();
    assert_eq!(ack.reason_code, connack_v3::BAD_USER_NAME_OR_PASSWORD);
    let (_, ack) = RawClient::connect(b.addr, v3("x").with_credentials("ghost", "nope"))
        .await
        .unwrap();
    assert_eq!(ack.reason_code, connack_v3::BAD_USER_NAME_OR_PASSWORD);
    let (_, ack) = RawClient::connect(b.addr, v3("x")).await.unwrap();
    assert_eq!(ack.reason_code, connack_v3::NOT_AUTHORIZED);
    // Accounts without a password (the MQTT-SN identity) cannot log in.
    let (_, ack) = RawClient::connect(b.addr, v5("x").with_credentials("sn_gateway", "anything"))
        .await
        .unwrap();
    assert_eq!(ack.reason_code, reason::BAD_USER_NAME_OR_PASSWORD);
}

#[tokio::test]
async fn room_isolation_between_members_viewers_and_moderators() {
    let b = acl_broker(BrokerOptions::permissive(), false).await;
    let mut sarah = login(b.addr, "sarah", "dev_sarah", "sarah_dev_pass").await;
    let mut alex = login(b.addr, "alex", "ops_alex", "alex_ops_pass").await;
    let mut auditor = login(b.addr, "auditor", "guest_auditor", "auditor_pass").await;
    let mut lead = login(b.addr, "lead", "ops_lead", "moderator_password").await;

    assert_eq!(
        sarah
            .subscribe("rooms/engineering/chat", QoS::AtLeastOnce)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        sarah
            .subscribe("rooms/operations/chat", QoS::AtLeastOnce)
            .await
            .unwrap(),
        reason::NOT_AUTHORIZED
    );
    assert_eq!(
        sarah
            .subscribe("rooms/engineering/#", QoS::AtLeastOnce)
            .await
            .unwrap(),
        reason::NOT_AUTHORIZED
    );
    assert_eq!(
        auditor
            .subscribe("rooms/operations/chat", QoS::AtLeastOnce)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        lead.subscribe("rooms/engineering/#", QoS::AtLeastOnce)
            .await
            .unwrap(),
        1
    );

    // Cross-room publish is refused and never delivered.
    assert_eq!(
        alex.publish(msg(
            "rooms/engineering/chat",
            b"intrusion",
            QoS::AtLeastOnce
        ))
        .await
        .unwrap(),
        reason::NOT_AUTHORIZED
    );
    // Viewers cannot publish; members cannot post announcements or touch admin topics.
    assert_eq!(
        auditor
            .publish(msg("rooms/operations/chat", b"hi", QoS::AtLeastOnce))
            .await
            .unwrap(),
        reason::NOT_AUTHORIZED
    );
    assert_eq!(
        sarah
            .publish(msg(
                "rooms/engineering/announcements",
                b"x",
                QoS::AtLeastOnce
            ))
            .await
            .unwrap(),
        reason::NOT_AUTHORIZED
    );
    assert_eq!(
        sarah
            .publish(msg(
                "rooms/engineering/admin/control",
                b"x",
                QoS::AtLeastOnce
            ))
            .await
            .unwrap(),
        reason::NOT_AUTHORIZED
    );
    assert_no_publish(&mut sarah).await;
    assert_no_publish(&mut lead).await;

    // Allowed traffic flows to everyone entitled to it.
    assert_eq!(
        sarah
            .publish(msg("rooms/engineering/chat", b"hello", QoS::AtLeastOnce))
            .await
            .unwrap(),
        0
    );
    assert_eq!(&next_publish(&mut sarah).await.payload[..], b"hello");
    assert_eq!(&next_publish(&mut lead).await.payload[..], b"hello");
    assert_eq!(
        lead.publish(msg("rooms/operations/chat", b"ops", QoS::AtLeastOnce))
            .await
            .unwrap(),
        0
    );
    assert_eq!(&next_publish(&mut auditor).await.payload[..], b"ops");
}

#[tokio::test]
async fn device_accounts_are_bound_to_their_client_id() {
    let b = acl_broker(BrokerOptions::permissive(), false).await;
    let (_, ack) = RawClient::connect(
        b.addr,
        v5("other-id").with_credentials("sensor_node", "sensor_token_77"),
    )
    .await
    .unwrap();
    assert_eq!(ack.reason_code, reason::CLIENT_IDENTIFIER_NOT_VALID);

    let mut dev = login(b.addr, "sensor_node", "sensor_node", "sensor_token_77").await;
    assert_eq!(
        dev.subscribe("devices/sensor_node/commands", QoS::AtLeastOnce)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        dev.subscribe("devices/+/commands", QoS::AtLeastOnce)
            .await
            .unwrap(),
        reason::NOT_AUTHORIZED
    );
    assert_eq!(
        dev.subscribe("#", QoS::AtLeastOnce).await.unwrap(),
        reason::NOT_AUTHORIZED
    );
    assert_eq!(
        dev.publish(msg(
            "devices/sensor_node/telemetry",
            b"21C",
            QoS::AtLeastOnce
        ))
        .await
        .unwrap(),
        0
    );
    assert_eq!(
        dev.publish(msg("devices/other/telemetry", b"spoof", QoS::AtLeastOnce))
            .await
            .unwrap(),
        reason::NOT_AUTHORIZED
    );

    let mut admin = login(b.addr, "admin-2", "superadmin", "admin_secret_pass").await;
    admin
        .publish(msg(
            "devices/sensor_node/commands",
            b"reboot",
            QoS::AtLeastOnce,
        ))
        .await
        .unwrap();
    assert_eq!(&next_publish(&mut dev).await.payload[..], b"reboot");
}

#[tokio::test]
async fn unauthorized_will_topic_is_refused_at_connect() {
    let b = acl_broker(BrokerOptions::permissive(), false).await;
    let conn = v5("sarah-will")
        .with_credentials("dev_sarah", "sarah_dev_pass")
        .with_will(msg("rooms/operations/chat", b"x", QoS::AtMostOnce));
    let (_, ack) = RawClient::connect(b.addr, conn).await.unwrap();
    assert_eq!(ack.reason_code, reason::NOT_AUTHORIZED);
}

#[tokio::test]
async fn anonymous_clients_use_the_declared_anonymous_account() {
    let b = acl_broker(BrokerOptions::permissive(), true).await;
    let mut anon = connect(b.addr, v5("anon-1")).await;
    assert_eq!(
        anon.subscribe("public/news", QoS::AtMostOnce)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        anon.subscribe("rooms/engineering/chat", QoS::AtMostOnce)
            .await
            .unwrap(),
        reason::NOT_AUTHORIZED
    );
    assert_eq!(
        anon.publish(msg("public/news", b"x", QoS::AtLeastOnce))
            .await
            .unwrap(),
        reason::NOT_AUTHORIZED
    );
}

#[tokio::test]
async fn client_id_takeover_policy() {
    let b = acl_broker(BrokerOptions::permissive(), false).await;
    let mut sarah = login(b.addr, "shared-id", "dev_sarah", "sarah_dev_pass").await;

    // Another user may not steal the ClientID ...
    let (_, ack) = RawClient::connect(
        b.addr,
        v5("shared-id").with_credentials("ops_alex", "alex_ops_pass"),
    )
    .await
    .unwrap();
    assert_eq!(ack.reason_code, reason::CLIENT_IDENTIFIER_NOT_VALID);
    sarah.ping().await.unwrap();

    // ... but the same user reconnecting takes over the session.
    let _again = login(b.addr, "shared-id", "dev_sarah", "sarah_dev_pass").await;
    let got = sarah.wait_closed(Duration::from_secs(2)).await.unwrap();
    assert!(got.contains(&MqttPacket::disconnect(reason::SESSION_TAKEN_OVER)));

    // With client_id_takeover = "any" a different user may take over.
    let mut options = BrokerOptions::permissive();
    options.client_id_takeover_any = true;
    let b = acl_broker(options, false).await;
    let mut first = login(b.addr, "id-x", "dev_sarah", "sarah_dev_pass").await;
    let _second = login(b.addr, "id-x", "ops_alex", "alex_ops_pass").await;
    first.wait_closed(Duration::from_secs(2)).await.unwrap();
}

#[tokio::test]
async fn acl_reload_replaces_rules_atomically() {
    let dir = std::env::temp_dir().join(format!("wolfimq-acl-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("acl.conf");
    std::fs::write(&path, "user u password:p\ntopic readwrite a/#\n").unwrap();
    let acl = AclEngine::new(false);
    acl.load_from_acl_file(&path).await.unwrap();
    let b = start_broker(BrokerOptions::permissive(), acl).await;
    let mut c = login(b.addr, "r1", "u", "p").await;
    assert_eq!(c.subscribe("a/x", QoS::AtMostOnce).await.unwrap(), 0);

    // A broken file is rejected and the old rules stay in force.
    std::fs::write(&path, "user u password:p\ntopic sometimes a/#\n").unwrap();
    assert!(b.ctx.acl.load_from_acl_file(&path).await.is_err());
    assert_eq!(c.subscribe("a/y", QoS::AtMostOnce).await.unwrap(), 0);

    std::fs::write(&path, "user u password:p\ntopic readwrite b/#\n").unwrap();
    b.ctx.acl.load_from_acl_file(&path).await.unwrap();
    let mut c = login(b.addr, "r2", "u", "p").await;
    assert_eq!(
        c.subscribe("a/z", QoS::AtMostOnce).await.unwrap(),
        reason::NOT_AUTHORIZED
    );
    assert_eq!(c.subscribe("b/z", QoS::AtMostOnce).await.unwrap(), 0);
    let _ = std::fs::remove_dir_all(dir);
}
