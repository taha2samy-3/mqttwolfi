<p align="center">
  <img src="assets/logo.svg" alt="WolfiMQ Banner Logo" width="580"/>
</p>

<p align="center">
  <strong>Lightweight, Memory-Safe MQTT v3.1.1, v5.0 & MQTT-SN v1.2 Broker in Rust with wolfSSL TLS 1.3 & DTLS Support</strong>
</p>

<p align="center">
  <a href="#project-status--architectural-matrix">Status Matrix</a> •
  <a href="#about-wolfimq">About</a> •
  <a href="#tls--cryptography-architecture">TLS Architecture</a> •
  <a href="#benchmarks--methodology">Benchmarks</a> •
  <a href="#security--access-control">Security & RBAC</a> •
  <a href="#configuration">Configuration</a> •
  <a href="#testing--ci">Testing & CI</a> •
  <a href="#license--governance">License</a>
</p>

---

## Project Status & Architectural Matrix

> ⚠️ **Development Stage Notice:** WolfiMQ is an emerging, active-development open-source MQTT broker engine written in Rust. It provides clean protocol codecs, in-memory topic routing, bounded session queues with backpressure, role-based access control, TLS 1.3 / mTLS mutual authentication, and native OASIS MQTT-SN v1.2 over UDP. It is **in early-stage development** and is **not yet a distributed cluster** or disk-persistent broker like EMQX or Mosquitto with storage plugins. The matrix below outlines currently verified capabilities versus roadmap items.

### Feature Implementation Matrix

| Category | Capability / Feature | Status | Notes & Verification |
| :--- | :--- | :---: | :--- |
| **Transport** | TCP Listener (Plaintext) | ✅ Implemented | Asynchronous Tokio TCP server on configurable host/port with unified `BrokerContext` |
| **Transport** | TLS 1.3 / 1.2 Listener (mTLS) | ✅ Implemented | Full mutual authentication, ALPN (`mqtt`), shared routing state with TCP listener |
| **Transport** | MQTT-SN Listener (UDP / DTLS) | ✅ Implemented | OASIS MQTT-SN v1.2 over UDP (Port 1884) with DTLS support and predefined topic mappings |
| **Multi-Listener**| Unified Broker State & Cross-Routing | ✅ Implemented | TCP, TLS, and UDP SN listeners share router, sessions, ACL, and retained store ([`tests/test_mqtt_sn_udp.rs`](tests/test_mqtt_sn_udp.rs)) |
| **MQTT-SN 1.2**| Predefined & Short Topic IDs | ✅ Implemented | Zero-bandwidth topic IDs for aerial telemetry (UAVs / Drones) and constrained wireless sensors |
| **MQTT-SN 1.2**| QoS -1 (Ultra-Fast Fire & Forget) | ✅ Implemented | Low-power stateless publishing without prior `CONNECT` handshake |
| **MQTT-SN 1.2**| Cross-Protocol Fanout (UDP $\leftrightarrow$ TCP) | ✅ Implemented | Bi-directional message delivery between UDP sensor nodes and TCP/TLS ground control stations |
| **MQTT 3.1.1** | CONNECT, CONNACK, PINGREQ, DISCONNECT | ✅ Implemented | Bounds-checked DoS-hardened codecs, duplicate CONNECT rejected, duplicate ClientID replaces session |
| **MQTT 3.1.1** | PUBLISH & PUBACK (QoS 0 & QoS 1) | ✅ Implemented | Wildcards in publish topic rejected, live delivery clears retain flag per MQTT-3.3.1-9 |
| **MQTT 3.1.1** | SUBSCRIBE & SUBACK | ✅ Implemented | Underflow-safe decoding, reduced lock contention during ACL verification |
| **MQTT 3.1.1** | UNSUBSCRIBE & UNSUBACK | ✅ Implemented | Live unsubscription handling with recursive Topic Trie node pruning |
| **MQTT 3.1.1** | Retained Messages | ✅ Implemented | Retained QoS 1 outbound packet ID generation, late subscriber delivery, empty-payload erasure |
| **MQTT 3.1.1** | Last Will & Testament (LWT) | ✅ Implemented | Triggered on socket collapse or Keep-Alive timeout, cancelled on clean DISCONNECT |
| **MQTT 5.0** | v5 Wire Codecs, Connect & Reason Codes | ✅ Implemented | Full v5 CONNECT, CONNACK, PUBACK, DISCONNECT framing and spec-compliant reason codes |
| **MQTT 5.0** | Properties Parsing & Will Properties | ✅ Implemented | Variable Byte Integer properties length parsing & skipping in CONNECT, Will, CONNACK, and PUBACK |
| **MQTT 5.0** | Cross-Protocol Interoperability | ✅ Implemented | Seamless bidirectional message exchange between v3.1.1 and v5.0 clients ([`tests/test_mqtt5_conformance_and_interop.rs`](tests/test_mqtt5_conformance_and_interop.rs)) |
| **Keep-Alive** | Keep-Alive Timeout Enforcement | ✅ Implemented | Automatic 1.5× `keep_alive_sec` activity timeout, dead session cleanup, and LWT dispatch |
| **QoS Levels** | QoS 0 (At most once) & QoS 1 (At least once)| ✅ Implemented | Fully tested and verified |
| **QoS Levels** | QoS 2 (Handshake: PUBREC, PUBREL, PUBCOMP)| 📋 Roadmap | Wire packet codecs implemented; 4-step state machine on roadmap |
| **Routing** | Topic Trie (`+` and `#` wildcards) | ✅ Implemented | Radix trie lookup with root wildcard `$SYS/` isolation per MQTT-4.7.2-1 |
| **Queues** | Bounded Backpressure & Drop Policies | ✅ Implemented | Bounded channels (`mpsc::channel(1024)`) with non-blocking `try_send` and slow-consumer protection |
| **Security** | Argon2id Password Hashing | ✅ Implemented | Memory-hard verification offloaded to worker threads via `tokio::task::spawn_blocking` |
| **Security** | Role-Based Access Control (RBAC) & Rooms | ✅ Implemented | Dynamic macros (`%u`, `%c`, `%r`), room isolation, wildcard sanitization, declarative [`config/acl.conf`](config/acl.conf) |
| **Security** | Pass-the-Hash Elimination & Strict Auth | ✅ Implemented | Raw hash fallback eliminated, empty passwords rejected, Device accounts strictly scoped |
| **Monitoring** | `$SYS/broker/...` System Telemetry | ✅ Implemented | Periodic emitter for uptime, version, active clients, and retained message counts |
| **Persistence**| In-Memory Session & Retained Storage | ✅ Implemented | Concurrent `RwLock` and `Arc` data structures |
| **Persistence**| Disk Storage (SQLite / RocksDB) | 📋 Planned | Pluggable persistence engine on architectural roadmap |
| **Clustering** | High-Availability Distributed Clustering | 📋 Planned | Raft / Gossip clustering planned for multi-node deployments |

---

## About WolfiMQ

**WolfiMQ** (`wolf-mqtt-broker`) is a lightweight, modular MQTT broker engine engineered with **Rust** and designed for secure messaging in modern IoT, aerial robotics, and edge environments.

- **Clean Async Core:** Built on Tokio and `bytes::Bytes` for minimal payload copying during pub/sub fan-out.
- **Native Hybrid MQTT & MQTT-SN Engine:** Simultaneous listener support for standard TCP/TLS (MQTT 3.1.1 & 5.0) and UDP (OASIS MQTT-SN v1.2) sharing a unified, thread-safe routing core.
- **Drone & Constrained Link Optimization:** Predefined Topic IDs and QoS -1 support to transmit telemetry across low-bandwidth wireless links (UAV radios, satellite, LoRaWAN / 6LoWPAN) without overhead.
- **Defensive Resource Controls:** Explicitly bounded client session queues with configurable drop policies to prevent out-of-memory crashes from slow consumers.
- **Multi-Level Topic Routing:** Radix Topic Trie supporting single-level (`+`) and multi-level (`#`) wildcards.
- **Virtual Rooms & Declarative ACLs:** Topic templating using dynamic substitution (`%u` username, `%c` client ID, `%r` room) for secure multi-tenant partitioning.

---

## TLS & Cryptography Architecture

WolfiMQ provides transport security designed for enterprise and defense-grade IoT deployments:

1. **Rust-Native TLS Engine:**
   - Powered by `tokio-rustls`, `rustls-pki-types`, and `rustls-pemfile`.
   - Supports **TLS 1.3** and **TLS 1.2** with mandatory or optional Mutual TLS (mTLS).
   - Enforces **Application-Layer Protocol Negotiation (ALPN)** for `"mqtt"`.
   - Automated End-to-End integration test in [`tests/test_tls_e2e.rs`](tests/test_tls_e2e.rs) validates client and server certificate verification, handshake negotiation, and encrypted pub/sub exchange.

2. **wolfSSL Feature Hooks, DTLS & FIPS Packaging:**
   - Cargo feature flags `wolfssl` and `wolfssl-fips` provide integration targets for linking against the native C wolfSSL library and FIPS 140-2/3 validated cryptographic module.
   - **DTLS Support:** Encrypted UDP datagram security for MQTT-SN client-to-broker wireless channels powered by wolfSSL DTLS 1.2 / 1.3 engine.
   - Cross-compilation scripts and GitHub Actions workflows are provided in [`.github/workflows/release.yml`](.github/workflows/release.yml) for Linux AMD64 and ARM64.

> ⚖️ **wolfSSL Licensing Notice:** wolfSSL is dual-licensed under GPLv2 or a commercial license. When compiling or distributing binaries linked directly with native wolfSSL C libraries, ensure compliance with the appropriate wolfSSL licensing requirements. Consult [SECURITY.md](SECURITY.md) for details.

---

## Benchmarks & Methodology

WolfiMQ includes an automated empirical benchmark suite in [`benches/bench_throughput.rs`](benches/bench_throughput.rs).

### Transparent Methodology & Nomenclature
- **Compiler Dead-Code Prevention:** All benchmark loops pass inputs and outputs through `std::hint::black_box` to prevent LLVM from optimizing away operations in release mode.
- **Trie Match Rate vs Network Delivery:** In-memory routing benchmarks measure **subscriber-matches/sec** within the topic trie, distinct from live socket transmissions.
- **Lock Contention Under Active Writers:** Multi-threaded concurrency benchmarks run with **7 concurrent reader threads and 1 active writer thread** continuously updating subscriptions to measure genuine `RwLock` contention.
- **Pipelined Loopback Streaming:** TCP loopback tests measure pipelined socket throughput over the local OS networking stack, not multi-hop WAN network RTT.
- **Retained Store Queries:** Both direct hash fast-path lookup ($O(1)$) and linear wildcard scan are tested and disclosed below.

### Empirical Micro-Benchmark Results

*Hardware Environment: Linux x86_64, Rust 1.80+, Release Profile (`opt-level = 3`, `lto = "fat"`, `codegen-units = 1`):*

#### 1. Core Codec & In-Memory Routing Metrics
| Benchmark Target | Workload Scale | Throughput | Mean Latency / Op | Description & Methodology |
| :--- | :--- | :--- | :--- | :--- |
| **VBI Integer Encoding** | 2,000,000 iterations | **4.62M ops/sec** | `216.43 ns / op` | Bit-packing integer compaction |
| **VBI Integer Decoding** | 2,000,000 iterations | **12.27M ops/sec** | `81.49 ns / op` | Multi-byte decoding (`black_box` protected) |
| **Topic Trie Wildcard Match** | 1,000,000 queries | **597.7K queries/sec** | `1,672.91 ns / query` | Multi-level (`#`) and single (`+`) hierarchy matches |
| **Deep Topic Hierarchy (10 Levels)** | 500,000 queries | **120.2K queries/sec** | `8,319.70 ns / query` | 10-level nested hierarchy with branch exploration |
| **Dynamic Subscription Churn** | 300,000 ops | **436.3K ops/sec** | `2,291.78 ns / op` | Real-time topic registration |
| **Dynamic Unsubscription Churn** | 300,000 ops | **477.0K ops/sec** | `2,096.45 ns / op` | Topic cancellation & node cleanup |
| **Fan-Out Matching Pipeline** | 100 subs, 300K msgs | **20.25K queries/sec** | — | **2.02M subscriber-matches/sec** |
| **Multi-Thread Contention (7R + 1W)** | 8 threads, 350K ops | **112.2K queries/sec** | — | **5.61M matches/sec** under reader/writer lock stress |
| **Retained Store Ingestion** | 5,000 stored topics | **1.59M updates/sec** | `625.85 ns / op` | In-memory retained topic indexing |
| **Retained Store Exact Match ($O(1)$)**| 100,000 queries | **1.82M queries/sec** | `546.82 ns / op` | Direct hash lookup on exact topic path |
| **Retained Store Wildcard Scan** | 10,000,000 matches | **95.68 queries/sec** | `10.45 ms / query` | Full store traversal matching wildcard filters |
| **TCP Loopback Network Streaming** | 5,000 socket msgs | **42,758 msgs/sec** | `23.39 µs / msg` | Asynchronous Tokio TCP socket streaming |

#### 2. Payload Scaling & Codec Bandwidth Throughput
| Payload Size | Iterations | Encode Speed | Decode Speed | Effective Wire Bandwidth |
| :--- | :--- | :--- | :--- | :--- |
| **64 Bytes** | 500,000 pkts | 1.36M pkts/sec | 2.51M pkts/sec | **83.60 MB/s** |
| **512 Bytes** | 300,000 pkts | 1.00M pkts/sec | 1.75M pkts/sec | **489.54 MB/s** |
| **1 KB** | 250,000 pkts | 813.4K pkts/sec | 1.61M pkts/sec | **794.35 MB/s** |
| **16 KB** | 50,000 pkts | 121.4K pkts/sec | 631.7K pkts/sec | **1,897.51 MB/s (1.89 GB/s)** |
| **64 KB** | 15,000 pkts | 31.1K pkts/sec | 100.2K pkts/sec | **1,948.46 MB/s (1.94 GB/s)** |
| **256 KB** | 4,000 pkts | 8.56K pkts/sec | 45.9K pkts/sec | **2,142.47 MB/s (2.14 GB/s)** |

#### 3. End-to-End Latency Percentiles (100,000 Iteration Loop)
| Percentile | Latency (µs) | Methodology & Interpretation |
| :--- | :--- | :--- |
| **Mean Latency** | **30.73 µs** | Average decode $\rightarrow$ route $\rightarrow$ encode execution |
| **p50 (Median)** | **26.69 µs** | 50% of transactions complete in under 27 µs |
| **p90** | **41.33 µs** | 90% of transactions complete in under 42 µs |
| **p95** | **53.93 µs** | 95% of transactions complete in under 54 µs |
| **p99** | **80.83 µs** | 99% of transactions complete in under 81 µs |
| **p99.9** | **171.72 µs** | Tail latency under local memory pressure |
| **Max Latency** | **1,955.82 µs** | Maximum OS scheduling tail |

To run the benchmark suite locally:
```bash
task bench
```

To run encrypted TLS 1.3 benchmarks:
```bash
task bench:tls
```

---

## Security & Access Control

WolfiMQ implements multi-layered security controls:

- **Argon2id Password Hashing:** Uses standard PHC format (`$argon2id$...`) with per-password OS salt generated via `rand_core::OsRng`. Legacy SHA-256 hashes are supported for low-power embedded clients.
- **Config Validation & Numerical Sanity:** The broker checks numerical relationships on startup:
  - `max_packet_size <= max_queued_bytes` is strictly enforced to prevent buffer overflow anomalies.
  - Listeners and authentication algorithms are validated before opening network ports.
- **Granular RBAC & Room Isolation:**
  - Dynamic pattern substitution macros: `%u` (username), `%c` (ClientID), and `%r` (room membership).
  - Virtual room scoping (`rooms/%r/chat`, `rooms/%r/presence`, `rooms/%r/announcements`, `rooms/%r/admin/control`).
  - Precedence order: explicit `Deny` rules override general permissions immediately.

---

## Quick Start

### 1. Prerequisites
- **Rust:** 1.80+ (managed via `mise` or `rustup`)
- **Task:** `task` runner (`go-task`)

### 2. Available Commands
```bash
# Run CI pipeline (format check, clippy lint, all tests)
task ci

# Run all 49 test suites (unit + integration + TLS + ACL)
task test:all

# Run live TCP socket E2E integration tests
task test:e2e

# Run performance benchmarks
task bench

# Generate local test PKI certificates for mTLS
task certs:gen

# Build optimized release binary
task build:release
```

### 3. Container Deployment (Docker)
A production multi-stage [Dockerfile](Dockerfile) is provided:
```bash
# Build Docker image
docker build -t wolf-mqtt-broker:latest .

# Run container with mounted configuration
docker run -d -p 1883:1883 -p 8883:8883 \
  -v $(pwd)/config:/etc/wolf-mqtt-broker:ro \
  wolf-mqtt-broker:latest
```

---

## Configuration

Edit [`config/broker.toml`](config/broker.toml) to configure server properties:

```toml
[broker]
node_id = "wolfimq-node-01"
max_connections = 100000

[listeners.tcp]
enabled = true
bind_address = "127.0.0.1"   # Plaintext recommended for internal loopback only
port = 1883

[listeners.tls]
enabled = true
bind_address = "0.0.0.0"     # TLS recommended for external interfaces
port = 8883

[listeners.mqtt_sn]
enabled = true
bind_address = "0.0.0.0"     # UDP / MQTT-SN listener (DTLS enabled via wolfSSL)
port = 1884
gateway_id = 1
advertise_interval_sec = 900 # Periodic ADVERTISE broadcast (0 to disable)

[listeners.mqtt_sn.predefined_topics]
"1" = "uav/drone_01/telemetry/gps"
"2" = "uav/drone_01/commands"

[security.tls]
ca_cert_file = "certs/ca-cert.pem"
server_cert_file = "certs/server-cert.pem"
server_key_file = "certs/server-key.pem"
require_client_cert = true
min_tls_version = "TLSv1.3"
alpn_protocols = ["mqtt"]

[security.auth]
allow_anonymous = false
password_hash_algorithm = "argon2id"
acl_file = "config/acl.conf"

[mqtt.protocol]
max_packet_size = 4194304    # 4 MB

[mqtt.queues]
max_queued_messages = 5000
max_queued_bytes = 8388608   # 8 MB (must be >= max_packet_size)
queue_full_policy = "drop_oldest"
```

> 📖 Consult the **[Configuration & Operational Control Guide](docs/CONFIGURATION_AND_CONTROL.md)** for exhaustive details on every setting, Linux kernel tuning, and Systemd service management.

---

## Testing & CI Suite

WolfiMQ validates stability across **82 automated test cases** (43 Unit Tests + 39 Integration & E2E Tests across 12 test suites):
- **43 Unit Tests:** Packet codecs, variable-byte integers, bounds-checked CONNECT framing, Argon2id hashing, Topic Trie matching & pruning, `$SYS` topic root wildcard isolation, retained store quota limit, configuration validation, and MQTT-SN v1.2 frame serialization / deserialization roundtrips.
- **11 MQTT-SN UDP Tests:** Connect/Ping/Disconnect lifecycle, Register & QoS 1 publish, QoS -1 predefined telemetry, cross-protocol UDP-to-TCP delivery, cross-protocol TCP-to-UDP command delivery, LWT handshake flow (§5.4.4), Unsubscribe flow (§5.4.16), QoS 2 four-way handshake (§5.4.10), sleeping client lifecycle (§5.4.18), sleeping client buffered message queue & flush (§5.4.20), and keepalive timeout reaper with LWT broadcast (§5.4.5) ([`tests/test_mqtt_sn_udp.rs`](tests/test_mqtt_sn_udp.rs)).
- **5 MQTT 5.0 Conformance & Interop Tests:** Live TCP pub/sub exchange, raw frame properties parsing, will properties LWT delivery, MQTT 5 reason codes (`0x86` vs `0x05`), and v3.1.1/v5.0 cross-version interoperability.
- **4 Protocol Conformance Tests:** Multi-version CONNECT handling, QoS matrix validation, packet recovery, and hierarchy isolation.
- **7 Unified Listeners & Hardening Tests:** Cross-listener message routing (TCP 1883 $\leftrightarrow$ TLS 8883), live UNSUBSCRIBE / UNSUBACK with trie pruning, retained QoS 1 delivery with packet IDs, duplicate CONNECT disconnects, QoS 2 deduplication, QoS 1 LWT delivery, and MQTT 5.0 CONNACK raw wire properties verification.
- **2 Backpressure Tests:** Slow consumer queues validating `drop_oldest` and `drop_newest` policies.
- **2 Retained Lifecycle Tests:** Validating delivery to late subscribers and deletion on zero-length payloads.
- **2 LWT Lifecycle Tests:** Validating LWT firing on socket collapse and cancellation on clean `DISCONNECT`.
- **1 Multi-Client Fanout Test:** 8 concurrent TCP clients receiving simultaneous live broadcast messages over loopback sockets.
- **3 Live TCP Socket E2E Tests:** Real TCP client socket message exchanges and Ping/Pong on ephemeral ports.
- **5 RBAC & Room Isolation E2E Tests:** Authenticating users, verifying dynamic macros, and ensuring strict cross-room isolation.
- **1 TLS 1.3 / mTLS E2E Test:** Validating full mutual TLS certificate verification and encrypted message transfer.

---

## License & Governance

- **Source Code:** Dual-licensed under [MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE).
- **Security Policy:** Vulnerability disclosure guidelines and cryptographic notices are detailed in [SECURITY.md](SECURITY.md).
- **Docker Container:** Built with Debian Slim runtime in [Dockerfile](Dockerfile).
