use bytes::{Bytes, BytesMut};
use std::env;
use std::fs::File;
use std::io::Write;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use wolf_mqtt::auth::AclEngine;
use wolf_mqtt::broker::{BrokerContext, BrokerOptions};
use wolf_mqtt::protocol::{
    ConnectPacket, MqttPacket, ProtocolVersion, PublishPacket, QoS, SubscriptionOptions,
};
use wolf_mqtt::server::BrokerServer;
use wolf_mqtt::tls::{create_tls_acceptor, create_tls_connector, TlsServerConfig, WolfTlsStream};

#[allow(dead_code)]
#[derive(Default, Debug, Clone)]
struct BenchmarkResult {
    broker_name: String,
    tls_engine: String,
    concurrency: usize,
    handshake_ms: f64,
    total_messages: usize,
    expected_messages: usize,
    throughput_msgs_sec: f64,
    bandwidth_mb_sec: f64,
    mean_latency_us: f64,
    p50_latency_us: f64,
    p90_latency_us: f64,
    p95_latency_us: f64,
    p99_latency_us: f64,
    max_latency_us: f64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("================================================================================");
    println!("    WolfiMQ vs. Other Brokers: High-Load Standardized TLS Benchmark Suite       ");
    println!("================================================================================\n");

    let args: Vec<String> = env::args().collect();
    let mut msg_count = 10_000usize;
    let mut concurrency = 8usize;
    let mut payload_size = 128usize;
    let mut external_port: Option<u16> = None;
    let mut external_name = "Eclipse Mosquitto (OpenSSL)".to_string();
    let mut markdown_path: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--count" if i + 1 < args.len() => {
                msg_count = args[i + 1].parse().unwrap_or(10_000);
                i += 1;
            }
            "--concurrency" if i + 1 < args.len() => {
                concurrency = args[i + 1].parse().unwrap_or(8).max(1);
                i += 1;
            }
            "--payload-size" if i + 1 < args.len() => {
                payload_size = args[i + 1].parse().unwrap_or(128);
                i += 1;
            }
            "--external-port" if i + 1 < args.len() => {
                external_port = args[i + 1].parse().ok();
                i += 1;
            }
            "--external-name" if i + 1 < args.len() => {
                external_name = args[i + 1].clone();
                i += 1;
            }
            "--markdown-output" if i + 1 < args.len() => {
                markdown_path = Some(args[i + 1].clone());
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }

    println!("Standardized Benchmark Configuration:");
    println!("  Total Messages   : {}", msg_count);
    println!(
        "  Concurrency Load : {} concurrent TLS 1.3 clients",
        concurrency
    );
    println!("  Msgs Per Client  : {}", msg_count / concurrency);
    println!("  Payload Size     : {} bytes", payload_size);
    println!("  TLS Encryption   : Active (mTLS / TLS 1.3 - RFC 8446)\n");

    // 1. Benchmark WolfiMQ over TLS under High Concurrency
    println!("==> [1/2] Running WolfiMQ High-Load TLS Benchmark (Rust + wolfSSL / TLS 1.3)...");
    let wolf_res = benchmark_wolfimq(msg_count, concurrency, payload_size).await?;
    print_single_result(&wolf_res);

    // 2. If an external broker is configured, benchmark it under identical conditions
    let mut results = vec![wolf_res];

    if let Some(port) = external_port {
        println!(
            "\n==> [2/2] Running External Target: {} on port {}...",
            external_name, port
        );
        match benchmark_external_broker(&external_name, port, msg_count, concurrency, payload_size)
            .await
        {
            Ok(ext_res) => {
                print_single_result(&ext_res);
                results.push(ext_res);
            }
            Err(e) => {
                eprintln!(
                    "Warning: Failed to benchmark external broker {}: {}",
                    external_name, e
                );
            }
        }
    }

    // 3. Print Comparison Table
    println!("\n============================================================================================");
    println!("                     Side-by-Side High-Load TLS Broker Comparison                           ");
    println!("============================================================================================");
    print_comparison_table(&results);

    // 4. If requested, write Markdown file for GitHub Actions Summary
    if let Some(path) = markdown_path {
        write_markdown_summary(&path, &results)?;
        println!("\n[+] Standardized Markdown report saved to: {}", path);
    }

    Ok(())
}

async fn benchmark_wolfimq(
    msg_count: usize,
    concurrency: usize,
    payload_size: usize,
) -> Result<BenchmarkResult, Box<dyn std::error::Error + Send + Sync>> {
    let mut tls = TlsServerConfig::new("certs/server-cert.pem", "certs/server-key.pem");
    tls.client_ca_file = Some("certs/ca-cert.pem".into());
    let acceptor = create_tls_acceptor(&tls)?;

    // Size the per-session queue for the whole workload so the benchmark measures throughput,
    // not the overflow policy.
    let mut options = BrokerOptions::permissive();
    options.queue_limits.max_messages = msg_count.max(5000);
    options.queue_limits.max_bytes = (msg_count * (payload_size + 64)).max(8 << 20);
    let ctx = BrokerContext::with_options(Arc::new(AclEngine::new(true)), options);
    let server = BrokerServer::bind("127.0.0.1:0", ctx)
        .await?
        .with_tls(acceptor);
    let addr = server.local_addr()?;

    tokio::spawn(server.run());

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    run_tls_client_workload(
        "WolfiMQ",
        "wolfSSL Native / TLS 1.3",
        addr.port(),
        msg_count,
        concurrency,
        payload_size,
    )
    .await
}

async fn benchmark_external_broker(
    name: &str,
    port: u16,
    msg_count: usize,
    concurrency: usize,
    payload_size: usize,
) -> Result<BenchmarkResult, Box<dyn std::error::Error + Send + Sync>> {
    run_tls_client_workload(
        name,
        "OpenSSL / TLS 1.3",
        port,
        msg_count,
        concurrency,
        payload_size,
    )
    .await
}

async fn run_tls_client_workload(
    broker_name: &str,
    tls_engine: &str,
    port: u16,
    total_msg_count: usize,
    concurrency: usize,
    payload_size: usize,
) -> Result<BenchmarkResult, Box<dyn std::error::Error + Send + Sync>> {
    let connector = create_tls_connector(
        "certs/ca-cert.pem",
        Some(("certs/client-cert.pem", "certs/client-key.pem")),
    )?;

    let msgs_per_worker = total_msg_count / concurrency;
    let actual_total = msgs_per_worker * concurrency;
    let payload_len = payload_size.max(8);

    println!(
        "  -> Establishing {} concurrent TLS 1.3 / mTLS client sessions...",
        concurrency
    );
    let hs_start = Instant::now();

    // 1. Establish N concurrent TLS client sessions
    let mut connect_handles = Vec::with_capacity(concurrency);
    for worker_id in 0..concurrency {
        let connector_clone = connector.clone();
        let bname = broker_name.to_string();

        let handle = tokio::spawn(async move {
            let tcp = TcpStream::connect(("127.0.0.1", port)).await?;
            let mut tls = connector_clone.connect("localhost", tcp).await?;
            let mut buf = BytesMut::with_capacity(8192);

            let client_id = format!(
                "{}_c{}_{}",
                bname.to_lowercase().replace([' ', '(', ')', '/'], "_"),
                worker_id,
                std::process::id()
            );

            send_packet(
                &mut tls,
                MqttPacket::Connect(ConnectPacket {
                    version: ProtocolVersion::V311,
                    client_id,
                    clean_start: true,
                    keep_alive_sec: 60,
                    will: None,
                    username: None,
                    password: None,
                    properties: Default::default(),
                }),
            )
            .await?;
            let _ = read_next_packet(&mut tls, &mut buf).await?;

            let topic = format!("bench/tls/w{}_{}", worker_id, std::process::id());
            send_packet(
                &mut tls,
                MqttPacket::subscribe(
                    1,
                    vec![(topic.clone(), SubscriptionOptions::new(QoS::AtMostOnce))],
                ),
            )
            .await?;
            let _ = read_next_packet(&mut tls, &mut buf).await?;

            Ok::<(WolfTlsStream, BytesMut, String), Box<dyn std::error::Error + Send + Sync>>((
                tls, buf, topic,
            ))
        });
        connect_handles.push(handle);
    }

    let mut sessions = Vec::with_capacity(concurrency);
    for h in connect_handles {
        let res = h.await??;
        sessions.push(res);
    }
    let handshake_ms = hs_start.elapsed().as_secs_f64() * 1000.0;
    println!(
        "  -> All {} TLS sessions active in {:.2} ms (mean {:.2} ms/handshake)",
        concurrency,
        handshake_ms,
        handshake_ms / (concurrency as f64)
    );

    // 2. Run High-Load Concurrent Publish & Latency Measurement
    println!(
        "  -> Pipelining {} messages across {} concurrent streams...",
        actual_total, concurrency
    );

    let start_epoch = Instant::now();
    let run_start = Instant::now();
    let mut worker_tasks = Vec::with_capacity(concurrency);

    for (tls_stream, buf, topic) in sessions {
        let (mut read_half, mut write_half) = tokio::io::split(tls_stream);

        let task = tokio::spawn(async move {
            let mut latencies = Vec::with_capacity(msgs_per_worker);

            // Background receiver task
            let recv_task = tokio::spawn(async move {
                let mut in_buf = buf;
                let mut lats = Vec::with_capacity(msgs_per_worker);

                for _ in 0..msgs_per_worker {
                    // A lost message must not hang the benchmark: stop after 10 s of silence.
                    let Ok(pkt) = tokio::time::timeout(
                        std::time::Duration::from_secs(10),
                        read_next_packet(&mut read_half, &mut in_buf),
                    )
                    .await
                    else {
                        break;
                    };
                    let pkt = pkt?;
                    if let MqttPacket::Publish(pub_pkt) = pkt {
                        if pub_pkt.payload.len() >= 8 {
                            let sent_nanos =
                                u64::from_le_bytes(pub_pkt.payload[0..8].try_into().unwrap());
                            let now_nanos = start_epoch.elapsed().as_nanos() as u64;
                            if now_nanos >= sent_nanos {
                                let rtt_us = (now_nanos - sent_nanos) as f64 / 1000.0;
                                lats.push(rtt_us);
                            }
                        }
                    }
                }
                Ok::<Vec<f64>, Box<dyn std::error::Error + Send + Sync>>(lats)
            });

            // Publisher loop with nanosecond monotonic timestamp injection
            let mut payload_buf = vec![0x42u8; payload_len];
            for _ in 0..msgs_per_worker {
                let now_nanos = start_epoch.elapsed().as_nanos() as u64;
                payload_buf[0..8].copy_from_slice(&now_nanos.to_le_bytes());

                let pub_pkt = MqttPacket::Publish(PublishPacket::new(
                    topic.clone(),
                    Bytes::copy_from_slice(&payload_buf),
                ));

                let mut enc_buf = BytesMut::new();
                pub_pkt.encode(ProtocolVersion::V311, &mut enc_buf)?;
                write_half.write_all(&enc_buf).await?;
            }
            write_half.flush().await?;

            let received_lats = recv_task.await??;
            latencies.extend(received_lats);
            Ok::<Vec<f64>, Box<dyn std::error::Error + Send + Sync>>(latencies)
        });
        worker_tasks.push(task);
    }

    let mut all_latencies = Vec::with_capacity(actual_total);
    for task in worker_tasks {
        let lats = task.await??;
        all_latencies.extend(lats);
    }
    let total_dur = run_start.elapsed();
    let total_received = all_latencies.len();

    let throughput_msgs_sec = (total_received as f64) / total_dur.as_secs_f64();
    let total_bytes = (total_received * payload_len) as f64;
    let bandwidth_mb_sec = (total_bytes / (1024.0 * 1024.0)) / total_dur.as_secs_f64();

    all_latencies.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let mean_latency_us = if !all_latencies.is_empty() {
        all_latencies.iter().sum::<f64>() / (all_latencies.len() as f64)
    } else {
        0.0
    };

    let p50_latency_us = get_percentile(&all_latencies, 0.50);
    let p90_latency_us = get_percentile(&all_latencies, 0.90);
    let p95_latency_us = get_percentile(&all_latencies, 0.95);
    let p99_latency_us = get_percentile(&all_latencies, 0.99);
    let max_latency_us = all_latencies.last().copied().unwrap_or(0.0);

    Ok(BenchmarkResult {
        broker_name: broker_name.to_string(),
        tls_engine: tls_engine.to_string(),
        concurrency,
        handshake_ms,
        total_messages: total_received,
        expected_messages: actual_total,
        throughput_msgs_sec,
        bandwidth_mb_sec,
        mean_latency_us,
        p50_latency_us,
        p90_latency_us,
        p95_latency_us,
        p99_latency_us,
        max_latency_us,
    })
}

fn get_percentile(sorted: &[f64], pct: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((sorted.len() as f64) * pct).floor() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

async fn send_packet<W: AsyncWriteExt + Unpin>(
    stream: &mut W,
    packet: MqttPacket,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut buf = BytesMut::new();
    packet.encode(ProtocolVersion::V311, &mut buf)?;
    stream.write_all(&buf).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_next_packet<R: AsyncReadExt + Unpin>(
    stream: &mut R,
    buf: &mut BytesMut,
) -> Result<MqttPacket, Box<dyn std::error::Error + Send + Sync>> {
    loop {
        if let Some(pkt) = MqttPacket::decode_from(buf, ProtocolVersion::V311, usize::MAX)? {
            return Ok(pkt);
        }
        let n = stream.read_buf(buf).await?;
        if n == 0 {
            return Err("Unexpected socket EOF while awaiting MQTT packet".into());
        }
    }
}

fn print_single_result(res: &BenchmarkResult) {
    println!("  Broker Target    : {}", res.broker_name);
    println!("  Crypto Engine    : {}", res.tls_engine);
    println!(
        "  Concurrency      : {} concurrent clients",
        res.concurrency
    );
    println!(
        "  Delivered        : {} / {} messages",
        res.total_messages, res.expected_messages
    );
    println!("  TLS Handshake    : {:.2} ms", res.handshake_ms);
    println!(
        "  TLS Throughput   : {:.2} msgs/sec",
        res.throughput_msgs_sec
    );
    println!("  TLS Bandwidth    : {:.2} MB/s", res.bandwidth_mb_sec);
    println!("  Mean RTT Latency : {:.2} µs / msg", res.mean_latency_us);
    println!(
        "  Latency Percentiles (µs): p50: {:.2} | p90: {:.2} | p95: {:.2} | p99: {:.2} | max: {:.2}",
        res.p50_latency_us, res.p90_latency_us, res.p95_latency_us, res.p99_latency_us, res.max_latency_us
    );
}

fn print_comparison_table(results: &[BenchmarkResult]) {
    println!(
        "| {:<20} | {:<22} | {:<11} | {:<10} | {:<15} | {:<11} | {:<9} | {:<9} |",
        "Broker Target",
        "Crypto Engine",
        "Concurrency",
        "Handshake",
        "TLS Throughput",
        "Bandwidth",
        "Mean RTT",
        "p99 RTT"
    );
    println!("|:---------------------|:-----------------------|:------------|:-----------|:----------------|:------------|:----------|:----------|");
    for r in results {
        println!(
            "| {:<20} | {:<22} | {:<7} cl | {:<7.2} ms | {:<9.2} msg/s | {:<6.2} MB/s | {:<6.2} µs | {:<6.2} µs |",
            r.broker_name,
            r.tls_engine,
            r.concurrency,
            r.handshake_ms,
            r.throughput_msgs_sec,
            r.bandwidth_mb_sec,
            r.mean_latency_us,
            r.p99_latency_us
        );
    }
}

fn write_markdown_summary(path: &str, results: &[BenchmarkResult]) -> std::io::Result<()> {
    let mut file = File::create(path)?;
    writeln!(file, "### MQTT over TLS 1.3 (mutual TLS) throughput\n")?;
    writeln!(
        file,
        "| Broker | TLS engine | Clients | Handshakes (total) | Delivered | Throughput | Bandwidth | Mean RTT | p90 RTT | p99 RTT | Max RTT |"
    )?;
    writeln!(
        file,
        "| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"
    )?;
    for r in results {
        writeln!(
            file,
            "| **{}** | {} | {} | {:.1} ms | {} / {} | **{:.0} msg/s** | {:.2} MB/s | {:.1} µs | {:.1} µs | {:.1} µs | {:.1} µs |",
            r.broker_name,
            r.tls_engine,
            r.concurrency,
            r.handshake_ms,
            r.total_messages,
            r.expected_messages,
            r.throughput_msgs_sec,
            r.bandwidth_mb_sec,
            r.mean_latency_us,
            r.p90_latency_us,
            r.p99_latency_us,
            r.max_latency_us
        )?;
    }
    writeln!(
        file,
        "\n*QoS 0, pipelined publish/subscribe through the broker over loopback; RTT includes queueing \
         under load. Throughput counts delivered messages only.*"
    )?;
    Ok(())
}
