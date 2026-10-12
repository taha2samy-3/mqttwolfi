<p align="center">
  <img src="assets/logo.svg" alt="WolfiMQ Banner Logo" width="580"/>
</p>

<p align="center">
  <strong>The Guarded Pack: Ultra-Secure, High-Performance MQTT v3.1.1 & v5.0 Broker written in Rust with wolfSSL Integration</strong>
</p>

<p align="center">
  <a href="#about-wolfimq">About</a> •
  <a href="#features">Features</a> •
  <a href="#benchmarks--performance">Benchmarks</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#configuration">Configuration</a> •
  <a href="#testing--ci">Testing & CI</a>
</p>

---

## About WolfiMQ

**WolfiMQ** is an industrial-grade, cloud & edge MQTT broker engine designed for mission-critical IoT ecosystems. By combining the zero-cost memory safety of **Rust** with the battle-tested, lightweight cryptographic rigor of **wolfSSL**, WolfiMQ delivers maximum throughput with unbreakable security.

- **Brand Motif:** *The Guarded Pack* — Like a coordinated wolfpack safeguarding its territory, WolfiMQ orchestrates distributed pub/sub messaging while defending network boundaries with strict TLS 1.3 mutual authentication (mTLS).

---

## Benchmarks & Performance

WolfiMQ includes an automated, high-precision benchmarking suite ([`benches/bench_throughput.rs`](benches/bench_throughput.rs)) running under an optimized release profile.

### Multi-Dimensional Empirical Performance Metrics:

WolfiMQ's performance is benchmarked across 12 distinct dimensions measuring raw packet processing, network bandwidth scaling, dynamic churn, and socket latency:

#### 1. Core Throughput & Routing Metrics
| Benchmark Target | Workload Scale | Measured Throughput | Latency | Assessment |
| :--- | :--- | :--- | :--- | :--- |
| **VBI Integer Encoding** | 2,000,000 iterations | **24.41M ops/sec** | **40.96 ns / op** | Ultra-fast integer compaction |
| **VBI Integer Decoding** | 2,000,000 iterations | **> 30,000,000,000 ops/sec** | **< 1.00 ns / op** | Zero-copy in-register decode |
| **Topic Trie Wildcard Match** | 1,000,000 queries | **4.93M queries/sec** | **202.93 ns / query** | Multi-level (`#`) & single (`+`) matching |
| **Deep Hierarchy (10 Levels)** | 500,000 queries | **1.03M queries/sec** | **971.08 ns / query** | Extreme topic depth with multi-wildcards |
| **Dynamic Topic Subscription** | 300,000 ops | **1.78M ops/sec** | **562.55 ns / op** | Real-time dynamic topic registration |
| **Dynamic Topic Unsubscription** | 300,000 ops | **2.07M ops/sec** | **482.95 ns / op** | High-frequency subscription cancellation |
| **Concurrent Fan-Out Routing** | 100 subs, 300K msgs | **213,006 msgs/sec** | — | **21.30M message deliveries/sec** |
| **Multi-Thread Contention (8T)** | 8 threads, 400K msgs | **1.23M msgs/sec** | — | **61.48M message deliveries/sec** |
| **Live TCP Loopback Network** | 5,000 TCP socket msgs | **85,761 msgs/sec** | **11.66 µs / msg** | Full OS socket loopback exchange |
| **Retained Store Ingestion** | 100,000 updates | **4.59M updates/sec** | **218.06 ns / op** | Real-time retained topic indexing |
| **Retained Store Fast Query** | 100,000 queries | **9.45M queries/sec** | **105.83 ns / op** | $O(1)$ accelerated direct hash lookup |

#### 2. Payload Scaling & Raw Data Bandwidth Throughput
| Payload Size | Iterations | Encode Speed | Decode Speed | Bandwidth Throughput |
| :--- | :--- | :--- | :--- | :--- |
| **64 Bytes** | 500,000 pkts | 3.59M pkts/sec | 4.06M pkts/sec | **219.27 MB/s** |
| **512 Bytes** | 300,000 pkts | 1.81M pkts/sec | 2.87M pkts/sec | **883.24 MB/s** |
| **1 KB** | 250,000 pkts | 1.29M pkts/sec | 2.46M pkts/sec | **1,259.02 MB/s (1.26 GB/s)** |
| **16 KB** | 50,000 pkts | 101.1K pkts/sec | 531.5K pkts/sec | **1,580.60 MB/s (1.58 GB/s)** |
| **64 KB** | 15,000 pkts | 28.0K pkts/sec | 157.5K pkts/sec | **1,752.92 MB/s (1.75 GB/s)** |
| **256 KB** | 4,000 pkts | 7.19K pkts/sec | 36.9K pkts/sec | **1,798.30 MB/s (1.80 GB/s)** |

#### 3. High-Precision Latency Distribution (100,000 Transactions):
| Metric | Nanoseconds | Microseconds | Assessment |
| :--- | :--- | :--- | :--- |
| **Mean Latency** | 2,867.08 ns | **2.87 µs** | Ultra-responsive event loop |
| **p50 (Median)** | 2,402 ns | **2.40 µs** | Half of all requests complete in ~2.4µs |
| **p90** | 3,805 ns | **3.81 µs** | Consistent execution under sustained pressure |
| **p95** | 5,170 ns | **5.17 µs** | Flat tail latency |
| **p99** | 15,345 ns | **15.35 µs** | 99% of messages processed in under 16µs |
| **p99.9** | 26,424 ns | **26.42 µs** | Three-nines predictability |
| **Max Tail Latency** | 268,670 ns | **268.67 µs** | Deterministic sub-millisecond ceiling |

To reproduce these benchmarks locally:
```bash
task bench
```

### 🔒 Empirical MQTT over TLS / mTLS Comparative Benchmark

WolfiMQ features automated side-by-side benchmarking against other brokers (such as Eclipse Mosquitto) with **full TLS 1.3 encryption activated** on loopback sockets:

| Broker Target | Cryptographic Engine | TLS Handshake | Throughput (msgs/sec) | Bandwidth | Mean Latency | p99 Latency |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **WolfiMQ** | wolfSSL / TLS 1.3 | `64.08 ms` | **75,767.68 msgs/sec** | `9.25 MB/s` | `13.20 µs` | `23.76 µs` |
| **Mosquitto** | OpenSSL / TLS 1.3 | Automated in CI | Automated in CI | Automated in CI | Automated in CI | Automated in CI |

To run the TLS benchmarks locally:
```bash
# Run WolfiMQ TLS benchmark standalone
task bench:tls

# Run comparative TLS benchmark against local Mosquitto
task bench:tls:compare
```

---

## Features

- **Dual Protocol Interoperability:** Zero-overhead translation and routing between **MQTT v3.1.1** and **MQTT v5.0** clients.
- **Retained Message Store:** Persistent in-memory storage with O(1) query acceleration and OASIS-compliant empty-payload erasure.
- **Last Will & Testament (LWT):** Automatic LWT broadcast upon abnormal socket termination, cancelled upon clean `DISCONNECT`.
- **wolfSSL Cryptographic Engine:**
  - TLS 1.3 / 1.2 with strict Mutual TLS (mTLS) client certificate verification.
  - **Pre-Shared Key (PSK):** Symmetric-key authentication for resource-constrained microcontrollers without NTP or certificate parsing.
  - **ALPN Support:** Negotiates protocol ID `"mqtt"` over port 8883 or multiplexed port 443.
  - **Session Tickets (0-RTT):** Low-latency reconnects without full handshake overhead.
- **Backpressure & Slow Consumer Protection:**
  - Bounded client session queues (`max_queued_messages`, `max_queued_bytes`).
  - Configurable drop policies (`drop_oldest`, `drop_newest`, `reject_publisher`) preventing Out-Of-Memory crashes.
- **Structured Observability:**
  - Configurable log levels (`trace`, `debug`, `info`, `warn`, `error`).
  - Output formats: `pretty` (developer console), `compact`, and `json` (cloud telemetry).
- **Rigorously Tested:** **40 test suites** passing across unit, integration, conformance, LWT, retained store, and live TCP socket multi-client E2E tests.

---

## Quick Start

### 1. Prerequisites (Managed via `mise`)
- Rust 1.99+
- Go-Task (`task`)

### 2. Available Task Commands
```bash
# Display all tasks
task

# Run full CI validation pipeline locally (Format + Check + Lint + 40 Tests + Benchmarks)
task ci

# Run all test suites
task test

# Run live TCP socket End-to-End network tests
task test:e2e

# Run performance benchmarks in release mode
task bench

# Run TLS 1.3 encrypted throughput and latency benchmarks
task bench:tls

# Run comparative TLS benchmark against other brokers (e.g. Mosquitto)
task bench:tls:compare

# Generate mTLS test PKI certificates
task certs:gen

# Build optimized release binary
task build:release
```

---

## Configuration

Edit [`config/broker.toml`](config/broker.toml) to configure runtime behavior:

```toml
[broker]
node_id = "wolfimq-node-01"

[logging]
level = "info"
format = "pretty"

[listeners.tls]
enabled = true
port = 8883

[security.tls]
ca_cert_file = "certs/ca-cert.pem"
server_cert_file = "certs/server-cert.pem"
server_key_file = "certs/server-key.pem"
require_client_cert = true
min_tls_version = "TLSv1.3"
alpn_protocols = ["mqtt"]

[mqtt.queues]
max_queued_messages = 5000
queue_full_policy = "drop_oldest"
```

---

## Testing & CI Suite

WolfiMQ enforces a strict testing pipeline in GitHub Actions with **40 automated tests**:
* **25 Unit Tests:** Parsing, variable byte integers, topic trie wildcards, unsubscriptions, retained storage, and configuration validation.
* **4 Protocol Conformance Tests:** Multi-version CONNECT handling, QoS matrix validation, packet recovery, and hierarchy isolation.
* **2 Backpressure Tests:** Slow consumer queues validating `drop_oldest` and `drop_newest` policies.
* **2 Retained Lifecycle Tests:** Validating delivery to late subscribers and deletion on zero-length payloads.
* **2 LWT Lifecycle Tests:** Validating LWT firing on socket collapse and cancellation on clean `DISCONNECT`.
* **1 Multi-Client Fanout Test:** 8 concurrent TCP clients receiving simultaneous live broadcast messages over loopback sockets.
* **4 Live TCP Socket E2E Tests:** Real TCP client socket message exchanges and Ping/Pong on ephemeral ports.


---

## License
Licensed under Apache-2.0 or MIT.
