use bytes::{Bytes, BytesMut};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use wolf_mqtt::auth::{AclEngine, UserAccount};
use wolf_mqtt::protocol::{ConnectPacket, MqttPacket, PublishPacket, QoS};
use wolf_mqtt::server::BrokerServer;

async fn send_packet(stream: &mut TcpStream, packet: MqttPacket) {
    let mut buf = BytesMut::new();
    packet.encode(&mut buf).expect("Failed to encode packet");
    stream
        .write_all(&buf)
        .await
        .expect("Failed to write packet to stream");
    stream.flush().await.expect("Failed to flush stream");
}

async fn read_packet(stream: &mut TcpStream, buf: &mut BytesMut) -> MqttPacket {
    loop {
        if !buf.is_empty() {
            let mut slice = &buf[..];
            if let Ok(pkt) = MqttPacket::decode(&mut slice) {
                let consumed = buf.len() - slice.len();
                let _ = buf.split_to(consumed);
                return pkt;
            }
        }
        let mut temp = [0u8; 1024];
        let n = stream
            .read(&mut temp)
            .await
            .expect("Failed to read from TCP stream");
        assert!(n > 0, "Unexpected EOF while waiting for packet");
        buf.extend_from_slice(&temp[..n]);
    }
}

#[tokio::test]
async fn test_e2e_credential_authentication_and_rejection() {
    let acl = Arc::new(AclEngine::new(false)); // Disallow anonymous
    acl.add_user(UserAccount::new_member(
        "valid_user",
        "secret_123",
        vec!["lobby".into()],
    ))
    .await;

    let server = BrokerServer::bind("127.0.0.1:0")
        .await
        .unwrap()
        .with_acl(acl);
    let addr = server.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = server.run().await;
    });

    // 1. Valid credentials connect successfully
    {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let mut buf = BytesMut::new();
        let conn = ConnectPacket::new("client_ok")
            .with_credentials("valid_user", Bytes::from_static(b"secret_123"));
        send_packet(&mut stream, MqttPacket::Connect(conn)).await;

        let ack = timeout(Duration::from_secs(2), read_packet(&mut stream, &mut buf))
            .await
            .expect("ConnAck timeout");
        assert_eq!(
            ack,
            MqttPacket::ConnAck {
                session_present: false,
                reason_code: 0x00,
            }
        );
    }

    // 2. Invalid password rejected with 0x86
    {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let mut buf = BytesMut::new();
        let conn = ConnectPacket::new("client_bad_pass")
            .with_credentials("valid_user", Bytes::from_static(b"WRONG_PASS"));
        send_packet(&mut stream, MqttPacket::Connect(conn)).await;

        let ack = timeout(Duration::from_secs(2), read_packet(&mut stream, &mut buf))
            .await
            .expect("ConnAck timeout");
        assert_eq!(
            ack,
            MqttPacket::ConnAck {
                session_present: false,
                reason_code: 0x86,
            }
        );
    }

    // 3. Unknown user rejected with 0x86
    {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let mut buf = BytesMut::new();
        let conn = ConnectPacket::new("client_bad_user")
            .with_credentials("ghost_user", Bytes::from_static(b"secret_123"));
        send_packet(&mut stream, MqttPacket::Connect(conn)).await;

        let ack = timeout(Duration::from_secs(2), read_packet(&mut stream, &mut buf))
            .await
            .expect("ConnAck timeout");
        assert_eq!(
            ack,
            MqttPacket::ConnAck {
                session_present: false,
                reason_code: 0x86,
            }
        );
    }

    // 4. Anonymous rejected when allow_anonymous = false
    {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let mut buf = BytesMut::new();
        let conn = ConnectPacket::new("client_anon");
        send_packet(&mut stream, MqttPacket::Connect(conn)).await;

        let ack = timeout(Duration::from_secs(2), read_packet(&mut stream, &mut buf))
            .await
            .expect("ConnAck timeout");
        assert_eq!(
            ack,
            MqttPacket::ConnAck {
                session_present: false,
                reason_code: 0x86,
            }
        );
    }
}

#[tokio::test]
async fn test_e2e_room_isolation_and_cross_room_security() {
    let acl = Arc::new(AclEngine::new(false));
    acl.add_user(UserAccount::new_member(
        "alice_alpha",
        "pass_alpha",
        vec!["room_alpha".into()],
    ))
    .await;
    acl.add_user(UserAccount::new_member(
        "bob_beta",
        "pass_beta",
        vec!["room_beta".into()],
    ))
    .await;

    let server = BrokerServer::bind("127.0.0.1:0")
        .await
        .unwrap()
        .with_acl(acl);
    let addr = server.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = server.run().await;
    });

    let mut stream_alice = TcpStream::connect(addr).await.unwrap();
    let mut buf_alice = BytesMut::new();
    let conn_alice = ConnectPacket::new("client_alice")
        .with_credentials("alice_alpha", Bytes::from_static(b"pass_alpha"));
    send_packet(&mut stream_alice, MqttPacket::Connect(conn_alice)).await;
    let _ = timeout(
        Duration::from_secs(2),
        read_packet(&mut stream_alice, &mut buf_alice),
    )
    .await
    .unwrap();

    let mut stream_bob = TcpStream::connect(addr).await.unwrap();
    let mut buf_bob = BytesMut::new();
    let conn_bob = ConnectPacket::new("client_bob")
        .with_credentials("bob_beta", Bytes::from_static(b"pass_beta"));
    send_packet(&mut stream_bob, MqttPacket::Connect(conn_bob)).await;
    let _ = timeout(
        Duration::from_secs(2),
        read_packet(&mut stream_bob, &mut buf_bob),
    )
    .await
    .unwrap();

    // Alice subscribes to authorized room: "rooms/room_alpha/chat"
    send_packet(
        &mut stream_alice,
        MqttPacket::Subscribe {
            packet_id: 1,
            topics: vec![("rooms/room_alpha/chat".into(), QoS::AtLeastOnce)],
        },
    )
    .await;
    let alice_suback = timeout(
        Duration::from_secs(2),
        read_packet(&mut stream_alice, &mut buf_alice),
    )
    .await
    .unwrap();
    assert_eq!(
        alice_suback,
        MqttPacket::SubAck {
            packet_id: 1,
            return_codes: vec![0x01],
        }
    );

    // Alice attempts to subscribe to unauthorized room: "rooms/room_beta/chat" -> Denied (0x80)
    send_packet(
        &mut stream_alice,
        MqttPacket::Subscribe {
            packet_id: 2,
            topics: vec![("rooms/room_beta/chat".into(), QoS::AtLeastOnce)],
        },
    )
    .await;
    let alice_denied_suback = timeout(
        Duration::from_secs(2),
        read_packet(&mut stream_alice, &mut buf_alice),
    )
    .await
    .unwrap();
    assert_eq!(
        alice_denied_suback,
        MqttPacket::SubAck {
            packet_id: 2,
            return_codes: vec![0x80], // 0x80 = Failure / Denied
        }
    );

    // Bob subscribes to authorized room: "rooms/room_beta/chat"
    send_packet(
        &mut stream_bob,
        MqttPacket::Subscribe {
            packet_id: 10,
            topics: vec![("rooms/room_beta/chat".into(), QoS::AtLeastOnce)],
        },
    )
    .await;
    let bob_suback = timeout(
        Duration::from_secs(2),
        read_packet(&mut stream_bob, &mut buf_bob),
    )
    .await
    .unwrap();
    assert_eq!(
        bob_suback,
        MqttPacket::SubAck {
            packet_id: 10,
            return_codes: vec![0x01],
        }
    );

    // Alice publishes to "rooms/room_alpha/chat" -> Alice receives it, Bob does NOT
    send_packet(
        &mut stream_alice,
        MqttPacket::Publish(PublishPacket {
            topic: "rooms/room_alpha/chat".into(),
            qos: QoS::AtMostOnce,
            retain: false,
            dup: false,
            packet_id: None,
            payload: Bytes::from_static(b"Hello Alpha Room!"),
        }),
    )
    .await;

    let alice_msg = timeout(
        Duration::from_secs(2),
        read_packet(&mut stream_alice, &mut buf_alice),
    )
    .await
    .expect("Alice should receive message in Alpha room");
    if let MqttPacket::Publish(p) = alice_msg {
        assert_eq!(p.topic, "rooms/room_alpha/chat");
        assert_eq!(&p.payload[..], b"Hello Alpha Room!");
    } else {
        panic!("Expected Publish packet");
    }

    // Verify Bob received zero messages (timeout expected)
    let bob_recv = timeout(
        Duration::from_millis(150),
        read_packet(&mut stream_bob, &mut buf_bob),
    )
    .await;
    assert!(bob_recv.is_err(), "Bob must not receive Alpha room traffic");

    // Alice attempts to publish to "rooms/room_beta/chat" -> Dropped by broker!
    send_packet(
        &mut stream_alice,
        MqttPacket::Publish(PublishPacket {
            topic: "rooms/room_beta/chat".into(),
            qos: QoS::AtMostOnce,
            retain: false,
            dup: false,
            packet_id: None,
            payload: Bytes::from_static(b"Malicious intrusion"),
        }),
    )
    .await;

    let bob_recv2 = timeout(
        Duration::from_millis(150),
        read_packet(&mut stream_bob, &mut buf_bob),
    )
    .await;
    assert!(
        bob_recv2.is_err(),
        "Bob must not receive unauthorized messages"
    );
}

#[tokio::test]
async fn test_e2e_roles_moderator_member_viewer() {
    let acl = Arc::new(AclEngine::new(false));
    acl.add_user(UserAccount::new_moderator(
        "mod_ops",
        "mod_pass",
        vec!["general".into()],
    ))
    .await;
    acl.add_user(UserAccount::new_member(
        "member_joe",
        "member_pass",
        vec!["general".into()],
    ))
    .await;
    acl.add_user(UserAccount::new_viewer(
        "viewer_sam",
        "viewer_pass",
        vec!["general".into()],
    ))
    .await;

    let server = BrokerServer::bind("127.0.0.1:0")
        .await
        .unwrap()
        .with_acl(acl);
    let addr = server.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = server.run().await;
    });

    // 1. Connect Member and Viewer
    let mut stream_member = TcpStream::connect(addr).await.unwrap();
    let mut buf_member = BytesMut::new();
    send_packet(
        &mut stream_member,
        MqttPacket::Connect(
            ConnectPacket::new("client_member")
                .with_credentials("member_joe", Bytes::from_static(b"member_pass")),
        ),
    )
    .await;
    let _ = read_packet(&mut stream_member, &mut buf_member).await;

    let mut stream_viewer = TcpStream::connect(addr).await.unwrap();
    let mut buf_viewer = BytesMut::new();
    send_packet(
        &mut stream_viewer,
        MqttPacket::Connect(
            ConnectPacket::new("client_viewer")
                .with_credentials("viewer_sam", Bytes::from_static(b"viewer_pass")),
        ),
    )
    .await;
    let _ = read_packet(&mut stream_viewer, &mut buf_viewer).await;

    // Both subscribe to announcements
    send_packet(
        &mut stream_member,
        MqttPacket::Subscribe {
            packet_id: 1,
            topics: vec![("rooms/general/announcements".into(), QoS::AtMostOnce)],
        },
    )
    .await;
    let _ = read_packet(&mut stream_member, &mut buf_member).await;

    send_packet(
        &mut stream_viewer,
        MqttPacket::Subscribe {
            packet_id: 1,
            topics: vec![("rooms/general/announcements".into(), QoS::AtMostOnce)],
        },
    )
    .await;
    let _ = read_packet(&mut stream_viewer, &mut buf_viewer).await;

    // 2. Member tries to publish announcements -> Denied/dropped!
    send_packet(
        &mut stream_member,
        MqttPacket::Publish(PublishPacket {
            topic: "rooms/general/announcements".into(),
            qos: QoS::AtMostOnce,
            retain: false,
            dup: false,
            packet_id: None,
            payload: Bytes::from_static(b"Member fake broadcast"),
        }),
    )
    .await;

    let viewer_check = timeout(
        Duration::from_millis(150),
        read_packet(&mut stream_viewer, &mut buf_viewer),
    )
    .await;
    assert!(
        viewer_check.is_err(),
        "Viewer must not receive member announcement publish"
    );

    // 3. Connect Moderator and publish announcement -> Delivered to both!
    let mut stream_mod = TcpStream::connect(addr).await.unwrap();
    let mut buf_mod = BytesMut::new();
    send_packet(
        &mut stream_mod,
        MqttPacket::Connect(
            ConnectPacket::new("client_mod")
                .with_credentials("mod_ops", Bytes::from_static(b"mod_pass")),
        ),
    )
    .await;
    let _ = read_packet(&mut stream_mod, &mut buf_mod).await;

    send_packet(
        &mut stream_mod,
        MqttPacket::Publish(PublishPacket {
            topic: "rooms/general/announcements".into(),
            qos: QoS::AtMostOnce,
            retain: false,
            dup: false,
            packet_id: None,
            payload: Bytes::from_static(b"System Maintenance at Midnight"),
        }),
    )
    .await;

    let member_msg = timeout(
        Duration::from_secs(2),
        read_packet(&mut stream_member, &mut buf_member),
    )
    .await
    .expect("Member must receive Moderator announcement");
    if let MqttPacket::Publish(p) = member_msg {
        assert_eq!(&p.payload[..], b"System Maintenance at Midnight");
    }

    let viewer_msg = timeout(
        Duration::from_secs(2),
        read_packet(&mut stream_viewer, &mut buf_viewer),
    )
    .await
    .expect("Viewer must receive Moderator announcement");
    if let MqttPacket::Publish(p) = viewer_msg {
        assert_eq!(&p.payload[..], b"System Maintenance at Midnight");
    }

    // 4. Viewer tries to publish to chat -> Denied!
    send_packet(
        &mut stream_viewer,
        MqttPacket::Publish(PublishPacket {
            topic: "rooms/general/chat".into(),
            qos: QoS::AtMostOnce,
            retain: false,
            dup: false,
            packet_id: None,
            payload: Bytes::from_static(b"Viewer illegal chat"),
        }),
    )
    .await;

    let member_check = timeout(
        Duration::from_millis(150),
        read_packet(&mut stream_member, &mut buf_member),
    )
    .await;
    assert!(
        member_check.is_err(),
        "Member must not receive Viewer chat publish"
    );
}

#[tokio::test]
async fn test_e2e_device_clientid_pattern_scoping() {
    let acl = Arc::new(AclEngine::new(false));
    acl.add_user(UserAccount::new_device("sensor_42", "token_abc123"))
        .await;

    let server = BrokerServer::bind("127.0.0.1:0")
        .await
        .unwrap()
        .with_acl(acl);
    let addr = server.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = server.run().await;
    });

    let mut stream_dev = TcpStream::connect(addr).await.unwrap();
    let mut buf_dev = BytesMut::new();
    send_packet(
        &mut stream_dev,
        MqttPacket::Connect(
            ConnectPacket::new("sensor_42")
                .with_credentials("sensor_42", Bytes::from_static(b"token_abc123")),
        ),
    )
    .await;
    let _ = read_packet(&mut stream_dev, &mut buf_dev).await;

    // Device subscribes to its own commands: "devices/sensor_42/commands" -> Allowed (0x01)
    send_packet(
        &mut stream_dev,
        MqttPacket::Subscribe {
            packet_id: 1,
            topics: vec![("devices/sensor_42/commands".into(), QoS::AtLeastOnce)],
        },
    )
    .await;
    let suback = timeout(
        Duration::from_secs(2),
        read_packet(&mut stream_dev, &mut buf_dev),
    )
    .await
    .unwrap();
    assert_eq!(
        suback,
        MqttPacket::SubAck {
            packet_id: 1,
            return_codes: vec![0x01],
        }
    );

    // Device tries to subscribe to other device's commands: "devices/sensor_99/commands" -> Denied (0x80)
    send_packet(
        &mut stream_dev,
        MqttPacket::Subscribe {
            packet_id: 2,
            topics: vec![("devices/sensor_99/commands".into(), QoS::AtLeastOnce)],
        },
    )
    .await;
    let denied_suback = timeout(
        Duration::from_secs(2),
        read_packet(&mut stream_dev, &mut buf_dev),
    )
    .await
    .unwrap();
    assert_eq!(
        denied_suback,
        MqttPacket::SubAck {
            packet_id: 2,
            return_codes: vec![0x80],
        }
    );

    // Device publishes telemetry to its own topic with QoS 1 -> PUBACK received!
    send_packet(
        &mut stream_dev,
        MqttPacket::Publish(PublishPacket {
            topic: "devices/sensor_42/telemetry".into(),
            qos: QoS::AtLeastOnce,
            retain: false,
            dup: false,
            packet_id: Some(555),
            payload: Bytes::from_static(b"temp: 21.8C"),
        }),
    )
    .await;
    let puback = timeout(
        Duration::from_secs(2),
        read_packet(&mut stream_dev, &mut buf_dev),
    )
    .await
    .unwrap();
    assert_eq!(puback, MqttPacket::PubAck { packet_id: 555 });

    // Device attempts to publish to another device's telemetry with QoS 1 -> Rejected (No PubAck, dropped)
    send_packet(
        &mut stream_dev,
        MqttPacket::Publish(PublishPacket {
            topic: "devices/sensor_99/telemetry".into(),
            qos: QoS::AtLeastOnce,
            retain: false,
            dup: false,
            packet_id: Some(666),
            payload: Bytes::from_static(b"fake data"),
        }),
    )
    .await;
    let dropped_check = timeout(
        Duration::from_millis(150),
        read_packet(&mut stream_dev, &mut buf_dev),
    )
    .await;
    assert!(
        dropped_check.is_err(),
        "Unauthorized publish must not receive PUBACK"
    );
}

#[tokio::test]
async fn test_e2e_load_acl_conf_file_live() {
    let acl = Arc::new(AclEngine::new(false));
    acl.load_from_acl_file("config/acl.conf")
        .await
        .expect("config/acl.conf must load successfully");

    let server = BrokerServer::bind("127.0.0.1:0")
        .await
        .unwrap()
        .with_acl(acl);
    let addr = server.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = server.run().await;
    });

    // 1. Superadmin connects
    {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let mut buf = BytesMut::new();
        send_packet(
            &mut stream,
            MqttPacket::Connect(
                ConnectPacket::new("admin_session")
                    .with_credentials("superadmin", Bytes::from_static(b"admin_secret_pass")),
            ),
        )
        .await;
        let ack = timeout(Duration::from_secs(2), read_packet(&mut stream, &mut buf))
            .await
            .unwrap();
        assert_eq!(
            ack,
            MqttPacket::ConnAck {
                session_present: false,
                reason_code: 0x00,
            }
        );

        // Superadmin subscribes to # and $SYS/# -> both succeed
        send_packet(
            &mut stream,
            MqttPacket::Subscribe {
                packet_id: 1,
                topics: vec![
                    ("#".into(), QoS::AtLeastOnce),
                    ("$SYS/#".into(), QoS::AtMostOnce),
                ],
            },
        )
        .await;
        let suback = timeout(Duration::from_secs(2), read_packet(&mut stream, &mut buf))
            .await
            .unwrap();
        assert_eq!(
            suback,
            MqttPacket::SubAck {
                packet_id: 1,
                return_codes: vec![0x01, 0x00],
            }
        );
    }

    // 2. Sarah (engineering member) connects and tests room boundaries
    {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let mut buf = BytesMut::new();
        send_packet(
            &mut stream,
            MqttPacket::Connect(
                ConnectPacket::new("sarah_laptop")
                    .with_credentials("dev_sarah", Bytes::from_static(b"sarah_dev_pass")),
            ),
        )
        .await;
        let ack = timeout(Duration::from_secs(2), read_packet(&mut stream, &mut buf))
            .await
            .unwrap();
        assert_eq!(
            ack,
            MqttPacket::ConnAck {
                session_present: false,
                reason_code: 0x00,
            }
        );

        // Allowed: rooms/engineering/chat
        send_packet(
            &mut stream,
            MqttPacket::Subscribe {
                packet_id: 2,
                topics: vec![("rooms/engineering/chat".into(), QoS::AtLeastOnce)],
            },
        )
        .await;
        let suback = timeout(Duration::from_secs(2), read_packet(&mut stream, &mut buf))
            .await
            .unwrap();
        assert_eq!(
            suback,
            MqttPacket::SubAck {
                packet_id: 2,
                return_codes: vec![0x01],
            }
        );

        // Explicit Deny: rooms/engineering/admin/control -> Denied (0x80)
        send_packet(
            &mut stream,
            MqttPacket::Subscribe {
                packet_id: 3,
                topics: vec![("rooms/engineering/admin/control".into(), QoS::AtLeastOnce)],
            },
        )
        .await;
        let denied_suback = timeout(Duration::from_secs(2), read_packet(&mut stream, &mut buf))
            .await
            .unwrap();
        assert_eq!(
            denied_suback,
            MqttPacket::SubAck {
                packet_id: 3,
                return_codes: vec![0x80],
            }
        );

        // Cross-room: rooms/operations/chat -> Not allowed (0x80)
        send_packet(
            &mut stream,
            MqttPacket::Subscribe {
                packet_id: 4,
                topics: vec![("rooms/operations/chat".into(), QoS::AtLeastOnce)],
            },
        )
        .await;
        let cross_suback = timeout(Duration::from_secs(2), read_packet(&mut stream, &mut buf))
            .await
            .unwrap();
        assert_eq!(
            cross_suback,
            MqttPacket::SubAck {
                packet_id: 4,
                return_codes: vec![0x80],
            }
        );
    }
}

/// Regression test for F2: ACL rule ordering bug.
///
/// `guest_auditor` in acl.conf is a `viewer` for the `operations` room with these rules (in file order):
///   1. topic read rooms/%r/chat
///   2. topic read rooms/%r/announcements
///   3. topic deny rooms/%r/#
///
/// Before the fix (`insert(0)` reversed order), rule 3 was evaluated first and denied all access,
/// making rule 1 and 2 unreachable. This test verifies that rule ordering is now correct.
#[tokio::test]
async fn test_e2e_acl_conf_guest_auditor() {
    let acl = Arc::new(AclEngine::new(false));
    acl.load_from_acl_file("config/acl.conf")
        .await
        .expect("config/acl.conf must load");

    let server = BrokerServer::bind("127.0.0.1:0")
        .await
        .unwrap()
        .with_acl(acl);
    let addr = server.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = server.run().await;
    });

    // guest_auditor connects with correct password
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let mut buf = BytesMut::new();
    send_packet(
        &mut stream,
        MqttPacket::Connect(
            ConnectPacket::new("auditor_session")
                .with_credentials("guest_auditor", Bytes::from_static(b"auditor_pass")),
        ),
    )
    .await;
    let ack = timeout(Duration::from_secs(2), read_packet(&mut stream, &mut buf))
        .await
        .expect("ConnAck timeout");
    assert_eq!(
        ack,
        MqttPacket::ConnAck {
            session_present: false,
            reason_code: 0x00,
        },
        "guest_auditor must connect successfully"
    );

    // ALLOWED: subscribe to rooms/operations/chat (rule 1: read rooms/%r/chat)
    send_packet(
        &mut stream,
        MqttPacket::Subscribe {
            packet_id: 1,
            topics: vec![("rooms/operations/chat".into(), QoS::AtMostOnce)],
        },
    )
    .await;
    let suback = timeout(Duration::from_secs(2), read_packet(&mut stream, &mut buf))
        .await
        .expect("SubAck timeout");
    assert_eq!(
        suback,
        MqttPacket::SubAck {
            packet_id: 1,
            return_codes: vec![0x00],
        },
        "guest_auditor MUST be allowed to subscribe to rooms/operations/chat (F2 regression)"
    );

    // ALLOWED: subscribe to rooms/operations/announcements (rule 2)
    send_packet(
        &mut stream,
        MqttPacket::Subscribe {
            packet_id: 2,
            topics: vec![("rooms/operations/announcements".into(), QoS::AtMostOnce)],
        },
    )
    .await;
    let suback2 = timeout(Duration::from_secs(2), read_packet(&mut stream, &mut buf))
        .await
        .expect("SubAck timeout");
    assert_eq!(
        suback2,
        MqttPacket::SubAck {
            packet_id: 2,
            return_codes: vec![0x00],
        },
        "guest_auditor MUST be allowed to subscribe to rooms/operations/announcements (F2 regression)"
    );

    // DENIED: subscribe to rooms/operations/presence (rule 3: deny rooms/%r/#)
    send_packet(
        &mut stream,
        MqttPacket::Subscribe {
            packet_id: 3,
            topics: vec![("rooms/operations/presence".into(), QoS::AtMostOnce)],
        },
    )
    .await;
    let denied = timeout(Duration::from_secs(2), read_packet(&mut stream, &mut buf))
        .await
        .expect("SubAck timeout");
    assert_eq!(
        denied,
        MqttPacket::SubAck {
            packet_id: 3,
            return_codes: vec![0x80],
        },
        "guest_auditor must be denied on rooms/operations/presence"
    );

    // DENIED: publish to rooms/operations/chat (viewer role = read-only)
    send_packet(
        &mut stream,
        MqttPacket::Publish(PublishPacket {
            topic: "rooms/operations/chat".into(),
            qos: QoS::AtMostOnce,
            retain: false,
            dup: false,
            packet_id: None,
            payload: Bytes::from_static(b"illegal write"),
        }),
    )
    .await;
    // No deliver-back expected (viewer cannot publish)
    let no_msg = timeout(
        Duration::from_millis(200),
        read_packet(&mut stream, &mut buf),
    )
    .await;
    assert!(
        no_msg.is_err(),
        "guest_auditor must NOT be able to publish (viewer = read-only)"
    );
}

/// Regression test for F2: ACL rule ordering bug on device accounts.
///
/// `sensor_node` in acl.conf is a `device` with these rules (in file order):
///   1. topic write devices/%c/telemetry
///   2. topic read  devices/%c/commands
///   3. topic deny  #
///
/// Before the fix, rule 3 was evaluated first and denied every topic.
/// This test confirms that telemetry publish and commands subscribe work correctly.
#[tokio::test]
async fn test_e2e_acl_conf_sensor_node() {
    let acl = Arc::new(AclEngine::new(false));
    acl.load_from_acl_file("config/acl.conf")
        .await
        .expect("config/acl.conf must load");

    let server = BrokerServer::bind("127.0.0.1:0")
        .await
        .unwrap()
        .with_acl(acl);
    let addr = server.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = server.run().await;
    });

    // sensor_node must use ClientID == username (device role enforcement)
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let mut buf = BytesMut::new();
    send_packet(
        &mut stream,
        MqttPacket::Connect(
            ConnectPacket::new("sensor_node")
                .with_credentials("sensor_node", Bytes::from_static(b"sensor_token_77")),
        ),
    )
    .await;
    let ack = timeout(Duration::from_secs(2), read_packet(&mut stream, &mut buf))
        .await
        .expect("ConnAck timeout");
    assert_eq!(
        ack,
        MqttPacket::ConnAck {
            session_present: false,
            reason_code: 0x00,
        },
        "sensor_node must connect successfully"
    );

    // ALLOWED: subscribe to devices/sensor_node/commands (rule 2: read devices/%c/commands)
    send_packet(
        &mut stream,
        MqttPacket::Subscribe {
            packet_id: 1,
            topics: vec![("devices/sensor_node/commands".into(), QoS::AtLeastOnce)],
        },
    )
    .await;
    let suback = timeout(Duration::from_secs(2), read_packet(&mut stream, &mut buf))
        .await
        .expect("SubAck timeout");
    assert_eq!(
        suback,
        MqttPacket::SubAck {
            packet_id: 1,
            return_codes: vec![0x01],
        },
        "sensor_node MUST be allowed to subscribe to its own commands topic (F2 regression)"
    );

    // ALLOWED: publish QoS1 telemetry to devices/sensor_node/telemetry → must receive PUBACK
    send_packet(
        &mut stream,
        MqttPacket::Publish(PublishPacket {
            topic: "devices/sensor_node/telemetry".into(),
            qos: QoS::AtLeastOnce,
            retain: false,
            dup: false,
            packet_id: Some(42),
            payload: Bytes::from_static(b"temp=22.5C hum=60%"),
        }),
    )
    .await;
    let puback = timeout(Duration::from_secs(2), read_packet(&mut stream, &mut buf))
        .await
        .expect("PUBACK timeout for telemetry");
    assert_eq!(
        puback,
        MqttPacket::PubAck { packet_id: 42 },
        "sensor_node MUST receive PUBACK for telemetry publish (F2 regression)"
    );

    // DENIED: subscribe to rooms/# (caught by rule 3: deny #)
    send_packet(
        &mut stream,
        MqttPacket::Subscribe {
            packet_id: 2,
            topics: vec![("rooms/#".into(), QoS::AtMostOnce)],
        },
    )
    .await;
    let denied = timeout(Duration::from_secs(2), read_packet(&mut stream, &mut buf))
        .await
        .expect("SubAck timeout");
    assert_eq!(
        denied,
        MqttPacket::SubAck {
            packet_id: 2,
            return_codes: vec![0x80],
        },
        "sensor_node must be denied access to human rooms"
    );

    // DENIED: publish to another device's telemetry
    send_packet(
        &mut stream,
        MqttPacket::Publish(PublishPacket {
            topic: "devices/other_sensor/telemetry".into(),
            qos: QoS::AtLeastOnce,
            retain: false,
            dup: false,
            packet_id: Some(43),
            payload: Bytes::from_static(b"spoofed data"),
        }),
    )
    .await;
    let no_puback = timeout(
        Duration::from_millis(200),
        read_packet(&mut stream, &mut buf),
    )
    .await;
    assert!(
        no_puback.is_err(),
        "sensor_node must NOT receive PUBACK when publishing to another device's topic"
    );
}
