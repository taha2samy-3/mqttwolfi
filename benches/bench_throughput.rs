use bytes::{Buf, Bytes, BytesMut};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use wolf_mqtt::protocol::{
    decode_variable_byte_integer, encode_variable_byte_integer, ConnectPacket, MqttPacket,
    ProtocolVersion, PublishPacket, QoS,
};
use wolf_mqtt::routing::retained::RetainedStore;
use wolf_mqtt::routing::TopicTrie;
use wolf_mqtt::server::BrokerServer;

fn main() {
    println!("================================================================================");
    println!("          WolfiMQ Multi-Dimensional High-Precision Benchmark Suite              ");
    println!("================================================================================\n");

    bench_vbi_codec();
    bench_payload_size_scaling();
    bench_topic_trie_routing();
    bench_deep_nested_trie_hierarchy();
    bench_dynamic_subscription_churn();
    bench_all_packet_codecs_diversity();
    bench_packet_serialization();
    bench_end_to_end_routing_pipeline();
    bench_retained_store();
    bench_concurrent_multithreaded_routing();
    bench_live_tcp_loopback_throughput();
    bench_latency_percentiles();

    println!("================================================================================");
    println!("All multi-dimensional benchmarks completed successfully in release mode.");
    println!("================================================================================");
}

/// 1. Variable Byte Integer (VBI) Codec Benchmark
fn bench_vbi_codec() {
    println!("--- 1. Variable Byte Integer (VBI) Arithmetic Codec ---");
    let iterations = 2_000_000;
    let values = [127u32, 16_383, 2_097_151, 268_435_455];

    let mut buf = BytesMut::with_capacity(iterations * 4);
    let start_encode = Instant::now();
    for i in 0..iterations {
        let val = values[i % values.len()];
        let _ = encode_variable_byte_integer(val, &mut buf);
    }
    let encode_duration = start_encode.elapsed();
    let encode_ops_sec = (iterations as f64) / encode_duration.as_secs_f64();
    let encode_ns_op = (encode_duration.as_nanos() as f64) / (iterations as f64);

    let mut read_slice = &buf[..];
    let start_decode = Instant::now();
    for _ in 0..iterations {
        let _ = decode_variable_byte_integer(&mut read_slice);
    }
    let decode_duration = start_decode.elapsed();
    let decode_ops_sec = (iterations as f64) / decode_duration.as_secs_f64();
    let decode_ns_op = (decode_duration.as_nanos() as f64) / (iterations as f64);

    println!("  Iterations      : {} ops", iterations);
    println!(
        "  VBI Encode Speed: {:.2} ops/sec  ({:.2} ns/op)",
        encode_ops_sec, encode_ns_op
    );
    println!(
        "  VBI Decode Speed: {:.2} ops/sec  ({:.2} ns/op)\n",
        decode_ops_sec, decode_ns_op
    );
}

/// 2. Payload Scaling & Bandwidth Throughput (64B, 512B, 1KB, 16KB, 64KB, 256KB)
fn bench_payload_size_scaling() {
    println!("--- 2. Payload Size Scaling & Raw Data Bandwidth Throughput ---");
    let sizes = [
        ("64 B", 64usize, 500_000),
        ("512 B", 512, 300_000),
        ("1 KB", 1024, 250_000),
        ("16 KB", 16 * 1024, 50_000),
        ("64 KB", 64 * 1024, 15_000),
        ("256 KB", 256 * 1024, 4_000),
    ];

    println!(
        "  {:<8} | {:<12} | {:<16} | {:<14} | {:<12}",
        "Payload", "Iterations", "Encode pkts/s", "Decode pkts/s", "Bandwidth"
    );
    println!("  -----------------------------------------------------------------------");

    for (label, size, count) in sizes {
        let raw_payload = vec![0xABu8; size];
        let bytes_payload = Bytes::from(raw_payload);

        let pub_pkt = MqttPacket::Publish(PublishPacket {
            topic: "telemetry/stream/data".into(),
            qos: QoS::AtMostOnce,
            retain: false,
            dup: false,
            packet_id: None,
            payload: bytes_payload.clone(),
        });

        // Encode benchmark
        let mut buf = BytesMut::with_capacity(count * (size + 32));
        let start_enc = Instant::now();
        for _ in 0..count {
            let _ = pub_pkt.encode(&mut buf);
        }
        let enc_dur = start_enc.elapsed();
        let enc_pkts_sec = (count as f64) / enc_dur.as_secs_f64();

        // Decode benchmark
        let mut read_slice = &buf[..];
        let start_dec = Instant::now();
        for _ in 0..count {
            let _ = MqttPacket::decode(&mut read_slice).unwrap();
        }
        let dec_dur = start_dec.elapsed();
        let dec_pkts_sec = (count as f64) / dec_dur.as_secs_f64();

        let total_bytes = (count as f64) * (size as f64);
        let bandwidth_mb_sec = (total_bytes / (1024.0 * 1024.0)) / enc_dur.as_secs_f64();

        println!(
            "  {:<8} | {:<12} | {:<16.2} | {:<14.2} | {:<8.2} MB/s",
            label, count, enc_pkts_sec, dec_pkts_sec, bandwidth_mb_sec
        );
    }
    println!();
}

/// 3. Topic Trie Wildcard Matching Benchmark
fn bench_topic_trie_routing() {
    println!("--- 3. Topic Trie Wildcard Matching (Realistic Industrial Hierarchy) ---");
    let mut trie = TopicTrie::new();

    let filters = [
        "factory/+/temperature",
        "factory/zone1/#",
        "sensors/+/vibration",
        "telemetry/#",
        "home/livingroom/thermostat",
        "cars/+/engine/rpm",
        "powergrid/substation3/voltage",
    ];

    for (idx, filter) in filters.iter().enumerate() {
        trie.subscribe(filter, idx).unwrap();
    }

    let test_topics = [
        "factory/zone1/temperature",
        "factory/zone1/machine4/status",
        "sensors/motorA/vibration",
        "telemetry/battery/level",
        "home/livingroom/thermostat",
        "cars/bmw/engine/rpm",
        "unmatched/device/random",
    ];

    let iterations = 1_000_000;
    let start = Instant::now();
    let mut matched_count = 0usize;

    for i in 0..iterations {
        let topic = test_topics[i % test_topics.len()];
        matched_count += trie.matches(topic).len();
    }

    let duration = start.elapsed();
    let ops_sec = (iterations as f64) / duration.as_secs_f64();
    let ns_op = (duration.as_nanos() as f64) / (iterations as f64);

    println!("  Iterations      : {} queries", iterations);
    println!("  Matched Entities: {} total matches", matched_count);
    println!(
        "  Trie Match Speed: {:.2} queries/sec  ({:.2} ns/query)\n",
        ops_sec, ns_op
    );
}

/// 4. Deep Nested Topic Hierarchy & Complex Wildcard Pruning (10 levels deep)
fn bench_deep_nested_trie_hierarchy() {
    println!("--- 4. Deep Nested Hierarchy & Extreme Wildcard Branching (10 Levels Deep) ---");
    let mut trie = TopicTrie::new();

    // 10-level deep subscriptions
    trie.subscribe(
        "corp/us/chicago/plant4/zone12/line3/robot8/arm/joint2/temp",
        101u32,
    )
    .unwrap();
    trie.subscribe("corp/us/+/plant4/+/line3/+/arm/+/+", 102)
        .unwrap();
    trie.subscribe("corp/us/chicago/plant4/#", 103).unwrap();
    trie.subscribe("+/+/+/+/+/+/+/+/+/+", 104).unwrap();
    trie.subscribe("#", 105).unwrap();

    let deep_concrete_topic = "corp/us/chicago/plant4/zone12/line3/robot8/arm/joint2/temp";
    let iterations = 500_000;

    let start = Instant::now();
    let mut total_matches = 0;
    for _ in 0..iterations {
        let matches = trie.matches(deep_concrete_topic);
        total_matches += matches.len();
    }
    let dur = start.elapsed();
    let queries_sec = (iterations as f64) / dur.as_secs_f64();
    let ns_op = (dur.as_nanos() as f64) / (iterations as f64);

    println!("  Topic Depth     : 10 hierarchical levels");
    println!("  Iterations      : {} queries", iterations);
    println!("  Total Matches   : {} matches", total_matches);
    println!(
        "  Deep Match Speed: {:.2} queries/sec  ({:.2} ns/query)\n",
        queries_sec, ns_op
    );
}

/// 5. Dynamic Topic Subscription Churn (Subscribe & Unsubscribe Lifecycle)
fn bench_dynamic_subscription_churn() {
    println!("--- 5. Dynamic Topic Subscription & Unsubscription Churn ---");
    let mut trie = TopicTrie::new();
    let iterations = 300_000;

    // Benchmark registration (Subscribe)
    let start_sub = Instant::now();
    for i in 0..iterations {
        let topic = format!("churn/device_{}/state", i % 5000);
        let _ = trie.subscribe(&topic, (i % 100) as u32);
    }
    let sub_dur = start_sub.elapsed();
    let sub_ops_sec = (iterations as f64) / sub_dur.as_secs_f64();

    // Benchmark cancellation (Unsubscribe)
    let start_unsub = Instant::now();
    for i in 0..iterations {
        let topic = format!("churn/device_{}/state", i % 5000);
        let client_id = (i % 100) as u32;
        trie.unsubscribe(&topic, &client_id);
    }
    let unsub_dur = start_unsub.elapsed();
    let unsub_ops_sec = (iterations as f64) / unsub_dur.as_secs_f64();

    println!("  Total Churn Ops : {} sub/unsub cycles", iterations);
    println!("  Subscribe Speed : {:.2} operations/sec", sub_ops_sec);
    println!("  Unsubscribe Speed: {:.2} operations/sec\n", unsub_ops_sec);
}

/// 6. Multi-Packet Type Codec Diversity
fn bench_all_packet_codecs_diversity() {
    println!("--- 6. Multi-Packet Type Serialization & Deserialization Diversity ---");
    let iterations = 200_000;

    // 1. Connect Packet with Will
    let will = PublishPacket {
        topic: "device/will/status".into(),
        qos: QoS::AtLeastOnce,
        retain: true,
        dup: false,
        packet_id: None,
        payload: Bytes::from_static(b"DISCONNECTED_ABNORMALLY"),
    };
    let connect_pkt = MqttPacket::Connect(ConnectPacket {
        version: ProtocolVersion::V500,
        client_id: "industrial-gateway-99".into(),
        clean_start: true,
        keep_alive_sec: 60,
        will: Some(will),
        username: None,
        password: None,
    });

    // 2. Subscribe Packet with 4 Topics
    let sub_pkt = MqttPacket::Subscribe {
        packet_id: 42,
        topics: vec![
            ("sensors/temp/#".into(), QoS::AtLeastOnce),
            ("telemetry/voltage".into(), QoS::AtMostOnce),
            ("alerts/+/critical".into(), QoS::AtLeastOnce),
            ("system/heartbeat".into(), QoS::AtMostOnce),
        ],
    };

    // 3. ConnAck
    let connack_pkt = MqttPacket::ConnAck {
        session_present: true,
        reason_code: 0x00,
    };

    // 4. PingReq & PingResp
    let pingreq_pkt = MqttPacket::PingReq;
    let pingresp_pkt = MqttPacket::PingResp;

    // 5. PubAck
    let puback_pkt = MqttPacket::PubAck { packet_id: 888 };

    let packets = [
        ("Connect (with LWT)", connect_pkt),
        ("Subscribe (4 filters)", sub_pkt),
        ("ConnAck", connack_pkt),
        ("PingReq", pingreq_pkt),
        ("PingResp", pingresp_pkt),
        ("PubAck", puback_pkt),
    ];

    println!(
        "  {:<26} | {:<16} | {:<16}",
        "Packet Type", "Encode pkts/s", "Decode pkts/s"
    );
    println!("  -----------------------------------------------------------------");

    for (name, pkt) in packets {
        let mut buf = BytesMut::with_capacity(iterations * 128);
        let start_enc = Instant::now();
        for _ in 0..iterations {
            pkt.encode(&mut buf).unwrap();
        }
        let enc_dur = start_enc.elapsed();
        let enc_speed = (iterations as f64) / enc_dur.as_secs_f64();

        let mut read_slice = &buf[..];
        let start_dec = Instant::now();
        for _ in 0..iterations {
            let _ = MqttPacket::decode(&mut read_slice).unwrap();
        }
        let dec_dur = start_dec.elapsed();
        let dec_speed = (iterations as f64) / dec_dur.as_secs_f64();

        println!("  {:<26} | {:<16.2} | {:<16.2}", name, enc_speed, dec_speed);
    }
    println!();
}

/// 7. MQTT Packet Serialization & Codec Benchmark (Standard QoS 1 Publish)
fn bench_packet_serialization() {
    println!("--- 7. Standard QoS 1 Publish Wire Codec Benchmark ---");
    let iterations = 500_000;
    let payload =
        Bytes::from_static(b"{\"temp\": 24.5, \"humidity\": 60.2, \"device\": \"node-01\"}");

    let pub_pkt = MqttPacket::Publish(PublishPacket {
        topic: "factory/assembly/sensor1".into(),
        qos: QoS::AtLeastOnce,
        retain: false,
        dup: false,
        packet_id: Some(1024),
        payload: payload.clone(),
    });

    let mut buf = BytesMut::with_capacity(iterations * 64);
    let start_encode = Instant::now();
    for _ in 0..iterations {
        pub_pkt.encode(&mut buf).unwrap();
    }
    let encode_duration = start_encode.elapsed();
    let encode_ops_sec = (iterations as f64) / encode_duration.as_secs_f64();
    let encode_ns_op = (encode_duration.as_nanos() as f64) / (iterations as f64);

    let mut read_slice = &buf[..];
    let start_decode = Instant::now();
    for _ in 0..iterations {
        let _ = MqttPacket::decode(&mut read_slice).unwrap();
    }
    let decode_duration = start_decode.elapsed();
    let decode_ops_sec = (iterations as f64) / decode_duration.as_secs_f64();
    let decode_ns_op = (decode_duration.as_nanos() as f64) / (iterations as f64);

    println!("  Iterations      : {} packets", iterations);
    println!(
        "  Packet Encode   : {:.2} pkts/sec  ({:.2} ns/pkt)",
        encode_ops_sec, encode_ns_op
    );
    println!(
        "  Packet Decode   : {:.2} pkts/sec  ({:.2} ns/pkt)\n",
        decode_ops_sec, decode_ns_op
    );
}

/// 8. In-Memory Concurrent Message Routing Pipeline Benchmark
fn bench_end_to_end_routing_pipeline() {
    println!("--- 8. In-Memory Concurrent Message Routing Pipeline (Fan-out) ---");
    let mut trie = TopicTrie::new();
    let subscriber_count = 100;
    for id in 0..subscriber_count {
        trie.subscribe("devices/+/data", id).unwrap();
    }

    let iterations = 300_000;
    let start = Instant::now();
    let mut total_routed = 0usize;

    for i in 0..iterations {
        let topic = format!("devices/sensor_{}/data", i % 1000);
        let subscribers = trie.matches(&topic);
        total_routed += subscribers.len();
    }

    let duration = start.elapsed();
    let msgs_sec = (iterations as f64) / duration.as_secs_f64();
    let deliveries_sec = (total_routed as f64) / duration.as_secs_f64();

    println!(
        "  Subscribers     : {} active topic listeners",
        subscriber_count
    );
    println!("  Messages Process: {} messages", iterations);
    println!("  Routing Speed   : {:.2} msgs/sec", msgs_sec);
    println!(
        "  Fan-out Throughput: {:.2} message-deliveries/sec\n",
        deliveries_sec
    );
}

/// 9. Retained Messages Store Insertion & Query Benchmark
fn bench_retained_store() {
    println!("--- 9. Retained Messages Store Insertion & Fast-Path Query Benchmark ---");
    let mut store = RetainedStore::new();
    let iterations = 100_000;

    // 1. Benchmark Retained Store Updates
    let start_insert = Instant::now();
    for i in 0..iterations {
        let topic = format!("devices/unit_{}/telemetry", i % 5000);
        let packet = PublishPacket {
            topic,
            qos: QoS::AtMostOnce,
            retain: true,
            dup: false,
            packet_id: None,
            payload: Bytes::from_static(b"ACTIVE_ONLINE"),
        };
        store.update(packet);
    }
    let insert_dur = start_insert.elapsed();
    let insert_ops_sec = (iterations as f64) / insert_dur.as_secs_f64();

    // 2. Benchmark Retained Query with O(1) Fast-Path Concrete Topic Filter
    let query_iterations = 100_000;
    let start_query = Instant::now();
    let mut total_matches = 0;
    for _ in 0..query_iterations {
        let matches = store.get_matches_for_filter("devices/unit_42/telemetry");
        total_matches += matches.len();
    }
    let query_dur = start_query.elapsed();
    let query_ops_sec = (query_iterations as f64) / query_dur.as_secs_f64();

    // 3. Benchmark Retained Query with Wildcard Filter
    let wildcard_query_iterations = 2_000;
    let start_wildcard = Instant::now();
    let mut wildcard_matches = 0;
    for _ in 0..wildcard_query_iterations {
        let matches = store.get_matches_for_filter("devices/+/telemetry");
        wildcard_matches += matches.len();
    }
    let wildcard_dur = start_wildcard.elapsed();
    let wildcard_ops_sec = (wildcard_query_iterations as f64) / wildcard_dur.as_secs_f64();

    println!("  Retained Entries: {} stored topics", store.count());
    println!("  Insert Speed    : {:.2} updates/sec", insert_ops_sec);
    println!(
        "  O(1) Exact Query: {:.2} queries/sec (total matches: {})",
        query_ops_sec, total_matches
    );
    println!(
        "  Wildcard Query  : {:.2} queries/sec (total matches: {})\n",
        wildcard_ops_sec, wildcard_matches
    );
}

/// 10. Concurrent Multi-Threaded Contention Routing Benchmark
fn bench_concurrent_multithreaded_routing() {
    println!("--- 10. Concurrent Multi-Threaded Worker Lock Contention Routing ---");
    let thread_count = 8;
    let per_thread_messages = 50_000;

    let trie = Arc::new(std::sync::RwLock::new(TopicTrie::new()));
    {
        let mut t = trie.write().unwrap();
        for id in 0..50 {
            t.subscribe("fleet/+/telemetry", id).unwrap();
        }
    }

    let start = Instant::now();
    let mut handles = Vec::new();
    let total_matches = Arc::new(AtomicUsize::new(0));

    for thread_idx in 0..thread_count {
        let trie_clone = Arc::clone(&trie);
        let matches_acc = Arc::clone(&total_matches);

        let handle = thread::spawn(move || {
            let mut local_count = 0;
            for i in 0..per_thread_messages {
                let topic = format!("fleet/vehicle_{}_{}/telemetry", thread_idx, i % 100);
                let guard = trie_clone.read().unwrap();
                let res = guard.matches(&topic);
                local_count += res.len();
            }
            matches_acc.fetch_add(local_count, Ordering::Relaxed);
        });
        handles.push(handle);
    }

    for h in handles {
        h.join().unwrap();
    }

    let duration = start.elapsed();
    let total_messages = thread_count * per_thread_messages;
    let total_deliveries = total_matches.load(Ordering::Relaxed);
    let msgs_sec = (total_messages as f64) / duration.as_secs_f64();
    let deliveries_sec = (total_deliveries as f64) / duration.as_secs_f64();

    println!("  Worker Threads  : {} concurrent OS threads", thread_count);
    println!("  Total Messages  : {} messages", total_messages);
    println!("  Throughput      : {:.2} msgs/sec", msgs_sec);
    println!(
        "  Deliveries Speed: {:.2} message-deliveries/sec\n",
        deliveries_sec
    );
}

/// 11. Real Live TCP Loopback Network Socket Throughput Benchmark
fn bench_live_tcp_loopback_throughput() {
    println!("--- 11. Live TCP Network Socket Loopback End-to-End Throughput ---");

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let server = BrokerServer::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();

        tokio::spawn(async move {
            let _ = server.run().await;
        });

        // Connect Subscriber
        let mut sub_stream = TcpStream::connect(addr).await.unwrap();
        let mut sub_buf = BytesMut::with_capacity(8192);

        let conn_pkt = MqttPacket::Connect(ConnectPacket {
            version: ProtocolVersion::V500,
            client_id: "tcp_bench_sub".into(),
            clean_start: true,
            keep_alive_sec: 60,
            will: None,
            username: None,
            password: None,
        });
        let mut enc = BytesMut::new();
        conn_pkt.encode(&mut enc).unwrap();
        sub_stream.write_all(&enc).await.unwrap();

        let _ = read_next_packet(&mut sub_stream, &mut sub_buf).await;

        // Subscribe to "network/bench"
        let sub_pkt = MqttPacket::Subscribe {
            packet_id: 1,
            topics: vec![("network/bench".into(), QoS::AtMostOnce)],
        };
        enc.clear();
        sub_pkt.encode(&mut enc).unwrap();
        sub_stream.write_all(&enc).await.unwrap();
        let _ = read_next_packet(&mut sub_stream, &mut sub_buf).await;

        // Connect Publisher
        let mut pub_stream = TcpStream::connect(addr).await.unwrap();
        let mut pub_buf = BytesMut::with_capacity(1024);
        let pub_conn = MqttPacket::Connect(ConnectPacket {
            version: ProtocolVersion::V500,
            client_id: "tcp_bench_pub".into(),
            clean_start: true,
            keep_alive_sec: 60,
            will: None,
            username: None,
            password: None,
        });
        enc.clear();
        pub_conn.encode(&mut enc).unwrap();
        pub_stream.write_all(&enc).await.unwrap();
        let _ = read_next_packet(&mut pub_stream, &mut pub_buf).await;

        let num_messages = 5_000;
        let pub_packet = MqttPacket::Publish(PublishPacket {
            topic: "network/bench".into(),
            qos: QoS::AtMostOnce,
            retain: false,
            dup: false,
            packet_id: None,
            payload: Bytes::from_static(b"E2E_TCP_BENCHMARK_PAYLOAD"),
        });

        let mut out_msg_buf = BytesMut::new();
        pub_packet.encode(&mut out_msg_buf).unwrap();
        let frozen_msg = out_msg_buf.freeze();

        let start = Instant::now();

        // Spawn reader task
        let recv_task = tokio::spawn(async move {
            let mut received = 0;
            for _ in 0..num_messages {
                let _ = read_next_packet(&mut sub_stream, &mut sub_buf).await;
                received += 1;
            }
            received
        });

        // Publisher sends messages
        for _ in 0..num_messages {
            pub_stream.write_all(&frozen_msg).await.unwrap();
        }

        let total_received = recv_task.await.unwrap();
        let duration = start.elapsed();
        let tcp_msgs_sec = (num_messages as f64) / duration.as_secs_f64();
        let rtt_per_msg_us = (duration.as_micros() as f64) / (num_messages as f64);

        println!("  Socket Protocol : Asynchronous Tokio TCP Stream (Loopback)");
        println!("  Messages Sent   : {} messages", total_received);
        println!("  TCP Throughput  : {:.2} msgs/sec", tcp_msgs_sec);
        println!("  Avg Socket RTT  : {:.2} µs / message\n", rtt_per_msg_us);
    });
}

async fn read_next_packet(stream: &mut TcpStream, buf: &mut BytesMut) -> MqttPacket {
    loop {
        if !buf.is_empty() {
            let mut slice = &buf[..];
            if let Ok(pkt) = MqttPacket::decode(&mut slice) {
                let consumed = buf.len() - slice.len();
                buf.advance(consumed);
                return pkt;
            }
        }
        let n = stream.read_buf(buf).await.expect("Socket read failed");
        assert!(n > 0, "Unexpected EOF during socket read");
    }
}

/// 12. High-Precision Latency Distribution (p50 / p90 / p95 / p99 / p99.9 / max)
fn bench_latency_percentiles() {
    println!("--- 12. End-to-End Latency Percentile Distribution (100,000 Transactions) ---");
    let mut trie = TopicTrie::new();
    for i in 0..50 {
        trie.subscribe("iot/sensors/+/temp", i).unwrap();
    }

    let sample_count = 100_000;
    let mut latencies_ns = Vec::with_capacity(sample_count);

    let pub_pkt = MqttPacket::Publish(PublishPacket {
        topic: "iot/sensors/zoneA/temp".into(),
        qos: QoS::AtLeastOnce,
        retain: false,
        dup: false,
        packet_id: Some(101),
        payload: Bytes::from_static(b"26.8"),
    });

    let mut encode_buf = BytesMut::with_capacity(128);
    pub_pkt.encode(&mut encode_buf).unwrap();
    let frozen_bytes = encode_buf.freeze();

    for _ in 0..sample_count {
        let start = Instant::now();

        // 1. Packet Decode
        let mut slice = &frozen_bytes[..];
        let decoded = MqttPacket::decode(&mut slice).unwrap();

        // 2. Trie Route Lookup
        if let MqttPacket::Publish(ref p) = decoded {
            let _ = trie.matches(&p.topic);
        }

        // 3. Packet Re-encode (fanout preparation)
        let mut out_buf = BytesMut::with_capacity(64);
        decoded.encode(&mut out_buf).unwrap();

        let elapsed_ns = start.elapsed().as_nanos() as u64;
        latencies_ns.push(elapsed_ns);
    }

    latencies_ns.sort_unstable();

    let sum: u64 = latencies_ns.iter().sum();
    let mean_ns = (sum as f64) / (sample_count as f64);
    let p50 = latencies_ns[(sample_count as f64 * 0.50) as usize];
    let p90 = latencies_ns[(sample_count as f64 * 0.90) as usize];
    let p95 = latencies_ns[(sample_count as f64 * 0.95) as usize];
    let p99 = latencies_ns[(sample_count as f64 * 0.99) as usize];
    let p999 = latencies_ns[(sample_count as f64 * 0.999) as usize];
    let max = *latencies_ns.last().unwrap();

    println!(
        "  Sample Size     : {} full decode -> route -> encode cycles",
        sample_count
    );
    println!(
        "  Mean Latency    : {:.2} ns  ({:.3} µs)",
        mean_ns,
        mean_ns / 1_000.0
    );
    println!(
        "  p50 (Median)    : {} ns  ({:.3} µs)",
        p50,
        (p50 as f64) / 1_000.0
    );
    println!(
        "  p90             : {} ns  ({:.3} µs)",
        p90,
        (p90 as f64) / 1_000.0
    );
    println!(
        "  p95             : {} ns  ({:.3} µs)",
        p95,
        (p95 as f64) / 1_000.0
    );
    println!(
        "  p99             : {} ns  ({:.3} µs)",
        p99,
        (p99 as f64) / 1_000.0
    );
    println!(
        "  p99.9           : {} ns  ({:.3} µs)",
        p999,
        (p999 as f64) / 1_000.0
    );
    println!(
        "  Max Latency     : {} ns  ({:.3} µs)\n",
        max,
        (max as f64) / 1_000.0
    );
}
