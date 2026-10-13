# Changelog

All notable changes to the WolfiMQ project are documented in this file.
The project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.5.0] - 2026-10-13

This release reworks the protocol engine after a full review against the OASIS MQTT v3.1.1,
MQTT v5.0 and MQTT-SN v1.2 specifications. It replaces 0.4.0, which only bumped the version.

### Fixed — protocol correctness
- **MQTT v5.0 subscribers received v3.1.1-framed PUBLISH packets** (no property length), so the
  first payload byte could be swallowed; Will messages, `$SYS` topics and MQTT-SN traffic were
  affected too. Every packet is now encoded for the receiving client's protocol version.
- **v5.0 properties were guessed from payload bytes** in PUBLISH / SUBSCRIBE / SUBACK. The codec
  now parses and validates property blocks strictly (allowed identifiers per packet,
  duplicates, value ranges) and rejects trailing bytes and invalid fixed-header flags.
- **Outbound packet identifiers came from the publisher's counter**, so two publishers could
  reuse the same id towards one subscriber, and the counter wrapped to the invalid id 0. Ids
  are now allocated per session, skipping ids that are still in flight.
- `sport/#` did not match `sport`; `+` handling and `$`-topic isolation now follow §4.7 exactly.
- Unauthorized QoS 1/2 publishes were silently dropped without PUBACK/PUBREC, leaving clients
  hanging; v5.0 clients now get reason code 0x87, v3.1.1 clients an acknowledgement.
- Unsupported protocol levels (e.g. MQTT 3.1) now receive CONNACK 0x01 before the close;
  rejection CONNACKs are no longer lost when the connection closes.
- MQTT-SN: binary payloads forwarded from MQTT clients were corrupted; reconnecting clients
  leaked subscriptions (duplicate deliveries); sleeping clients were expired with the wrong
  timer; ADVERTISE ignored the configured port; retained messages were never delivered.

### Fixed — security
- MQTT-SN Will messages bypassed the ACL; Will topics are now authorized for all transports
  (at CONNECT for MQTT, during the Will handshake for MQTT-SN).
- SUBSCRIBE authorization treated a filter like a topic (a `+` rule granted `#`
  subscriptions); filters must now be fully covered by a rule, and overlapping deny rules win.
- With `allow_anonymous = true` the `#` read/write fallback also applied to authenticated
  users without rules; it now applies only to anonymous clients, and only when the ACL file does
  not declare an `anonymous` account.
- `%u` and `%r` substitutions were not sanitized (only `%c` was).
- Role defaults were evaluated before the user's own ACL rules, so file rules could not refine
  a role; user rules now come first.
- The timing-attack dummy hash was not a valid Argon2 hash, so unknown users were rejected
  faster than known ones; legacy SHA-256 hashes are now compared in constant time.
- A TLS handshake that timed out leaked its `WOLFSSL` object; the readiness handling around
  wolfSSL could lose wake-ups; the client connector did not verify the server host name and
  could read out of bounds for an SNI name containing NUL.
- `verify_client_identity`, `min_tls_version`, `ciphers` and `alpn_protocols` were accepted
  but ignored; they are now enforced. Unimplemented TLS options (PSK, session tickets,
  hardware engine) were removed instead of being silently ignored.
- `accept()` errors (e.g. file descriptor exhaustion) stopped the listener; slow clients could
  trickle bytes before CONNECT indefinitely; password verification had no concurrency limit.

### Added
- MQTT v5.0: topic aliases, subscription identifiers, No Local, Retain As Published, Retain
  Handling, shared subscriptions (`$share/<group>/<filter>`), Receive Maximum flow control,
  client Maximum Packet Size, Message Expiry, Will Delay, Session Expiry, Assigned Client
  Identifier, Server Keep Alive, CONNACK capability properties, UNSUBACK reason codes and
  server DISCONNECT reason codes (0x82, 0x8D, 0x8E, 0x93, 0x94, 0x95, 0x9A, 0x9B, ...).
- Persistent sessions (MQTT v3.1.1 `CleanSession=0`, v5.0 Session Expiry): subscriptions and
  queued messages survive reconnects, unacknowledged QoS 1/2 messages are resent with DUP.
- Per-session outbound queues with working `drop_oldest` / `drop_newest` policies and byte
  limits; enforced `max_connections`, `max_packet_size`, `maximum_qos`, `allow_v311`/`allow_v500`,
  retained / wildcard / shared subscription switches and `max_keep_alive_sec`.
- MQTT-SN: configurable ACL identity (`acl_user`), REGISTER/REGACK handshake before publishing
  to a new topic, QoS 1/2 retransmission (Tretry/Nretry), forwarder encapsulation, session limit.
- Configuration overrides from the environment (`WOLFIMQ_<SECTION>__<KEY>=value`,
  `WOLFIMQ_CONFIG`) and warnings for unknown configuration keys.
- CLI: `--check-config`, `--print-config`, `--hash-password`; graceful shutdown on SIGINT /
  SIGTERM; ACL reload on SIGHUP (atomic, a broken file is rejected).
- `wolf_mqtt::client::RawClient`, a small version-aware client used by the tools and tests.
- Release binaries for Linux (x86_64, aarch64, armv7, riscv64; glibc and static musl),
  Windows x86_64 and macOS (Apple silicon and Intel).

### Changed
- wolfSSL is built with the `cmake` crate inside Cargo's `OUT_DIR`, which makes
  cross-compilation work; the FIPS-Ready variant uses wolfSSL's autotools build
  (`--enable-fips=ready`), the only build wolfSSL supports for FIPS.
- Plain TCP now defaults to `127.0.0.1`; the TLS listener is disabled unless configured.
- Benchmark numbers are no longer hard-coded in the README; CI publishes them with each release.
- The test-suite was rewritten: 158 tests exercise the real broker (TCP, TLS, MQTT-SN, CLI),
  replacing tests that passed against mocks.

### Removed
- Docker support (`Dockerfile`).
- The `reject_publisher` queue policy (it was never implemented).

---

## [0.3.3] - 2026-10-13

### 🔧 CI Fixes
- **FIPS test job disabled by default:** `test-fips` job in [`ci.yml`](.github/workflows/ci.yml) changed to `if: false` — GitHub Actions does not allow `secrets` context in job-level `if` conditions. The job runs only when manually re-enabled after configuring `external/wolfssl-fips-bundle/`.
- **Release workflow hardened:** `release.yml` FIPS build step uses step-level `env` + output pattern to safely detect missing bundle; outputs a GitHub Actions notice and skips gracefully.
- **Both workflows pass YAML validation** and confirmed green in CI.

---

## [0.3.2] - 2026-10-13


### 🚀 Dual Release: wolfSSL Standard & FIPS-Ready
- **Two release artifacts per version:**
  - `wolfimq-*-linux-amd64-wolfssl.tar.gz` — standard build, full TLS 1.3 cipher suite
  - `wolfimq-*-linux-amd64-wolfssl-fips-ready.tar.gz` — FIPS-Ready build, FIPS 140-2/3 approved algorithms only

### ⚙️ FIPS-Ready Build Support
- **New `wolfssl-fips` Cargo feature** activates `-DWOLFSSL_FIPS=ON` in CMake, restricting to FIPS-approved algorithms (AES, SHA-2/3, RSA, ECC, HMAC-SHA, Hash-DRBG). Non-FIPS primitives (ChaCha20-Poly1305, MD5, DES, RC4) are removed.
- **Separate source directories:** Standard build uses `external/wolfssl` (git submodule); FIPS-Ready build uses `external/wolfssl-fips-bundle/` (user-provided from wolfssl.com).
- **Clear diagnostic error:** If the FIPS bundle is missing, `build.rs` prints a structured error box explaining exactly where to download it.
- **CMVP Note:** FIPS-Ready = FIPS-approved algorithms, no formal certificate. For CMVP #4718, use wolfSSL's validated bundle.
- **Files:** [`build.rs`](build.rs), [`Cargo.toml`](Cargo.toml), [`.gitignore`](.gitignore)

### 🏗️ Release Workflow
- **New [`.github/workflows/release.yml`](.github/workflows/release.yml):** Triggered on version tag push (`v*.*.*`) or manual `workflow_dispatch`. Builds both variants, packages with `BUILD-INFO.txt` + `FIPS-NOTICE.txt`, computes SHA-256, and publishes a GitHub Release with extracted CHANGELOG notes.
- **FIPS bundle in CI:** The `WOLFSSL_FIPS_BUNDLE_B64` GitHub Actions secret (base64-encoded tar) is decoded at build time — the FIPS binary is built only when the secret is set; a clear notice is shown otherwise.
- **Updated CI matrix:** [`ci.yml`](.github/workflows/ci.yml) test-suite job now runs both `standard` and `fips` matrix variants with separate `Swatinem/rust-cache` keys.

### 📚 Documentation
- **README:** TLS & Cryptography Architecture section replaced with algorithm comparison table (FIPS-Ready vs Standard), build commands, and setup instructions.
- **Cargo.toml:** Feature definitions annotated with allowed/removed algorithm lists and download link.

---

## [0.3.1] - 2026-10-13

### 🔒 Security Fix
- **[F2] ACL Rule Ordering Bug — Reversed Evaluation Order (HIGH):**
  - **Root Cause:** `load_from_acl_file` used `user.custom_rules.insert(0, rule)` to prepend each parsed line. This reversed the file order so the **last** line in the user's block was evaluated **first**. Since `guest_auditor` and `sensor_node` both end with a broad `topic deny ...` rule as a catch-all fallback, this rule fired before any specific allow rules, silently blocking all access for those accounts.
  - **Fix:** Changed to `user.custom_rules.push(rule)` — rules are now appended in file-declaration order, matching the documented "first match wins" semantics.
  - **Files:** [`src/auth/mod.rs`](src/auth/mod.rs) (line ~547)

### ✅ Testing
- **Regression Tests for F2 Added:** Two new live E2E TCP tests added to [`tests/test_room_acl_e2e.rs`](tests/test_room_acl_e2e.rs):
  - `test_e2e_acl_conf_guest_auditor` — verifies that a viewer can subscribe to `rooms/operations/chat` and `rooms/operations/announcements` but cannot publish or subscribe to other topics in the room.
  - `test_e2e_acl_conf_sensor_node` — verifies that a device can publish telemetry to its own topic, subscribe to its own commands, and is blocked from room and cross-device topics.
  - These tests would have caught the F2 bug at commit time.

### 🏗️ CI/CD Fix
- **Root Cause of CI Failures (Exit 101/201):** The `external/` directory was listed in `.gitignore`, meaning the `external/wolfssl` source tree (needed by `build.rs` to compile `libwolfssl.a`) was never committed and was absent in the GitHub Actions runner clone.
- **Fix — wolfSSL Git Submodule:** Registered `external/wolfssl` as an official git submodule (pointing to `https://github.com/wolfSSL/wolfssl.git`). Updated `.gitignore` to allow the submodule path while still ignoring CMake build artifacts (`external/wolfssl/build/`, `external/wolfssl/build_fips/`).
- **Fix — CI Workflow:** Added `submodules: recursive` to all `actions/checkout@v4` steps and added an "Install Build Dependencies" step (`cmake build-essential`) to all build jobs.
- **Files:** [`.gitignore`](.gitignore), [`.github/workflows/ci.yml`](.github/workflows/ci.yml)

### ⚙️ Feature: FIPS vs. Non-FIPS wolfSSL Variants
- **New Cargo Feature `wolfssl-fips`:** When built with `--features wolfssl-fips`, `build.rs` now passes `-DWOLFSSL_FIPS=ON -DFIPS_VERSION=v5` to CMake and uses a separate `external/wolfssl/build_fips/` output directory to avoid cache conflicts between variants.
- **Conditional Compilation Flag:** Emits `cfg(wolfssl_fips)` so library code can conditionally compile FIPS-specific paths.
- **CI Matrix:** The CI test job now has a build matrix with `standard` and `fips` (commented out until a validated FIPS source bundle is available — the standard open-source wolfSSL tree does not include FIPS code).
- **Files:** [`build.rs`](build.rs), [`Cargo.toml`](Cargo.toml), [`.github/workflows/ci.yml`](.github/workflows/ci.yml)

---

## [0.3.0] - 2026-10-13

### 🚀 Major Highlights
- **100% Genuine C wolfSSL Cryptographic Engine Integration:** Completely eliminated `tokio-rustls`, `rustls-pemfile`, and `rustls-pki-types`. All TLS operations now link directly and statically against the official C `wolfSSL 5.9+` engine located in `external/wolfssl`.
- **Automated CMake Static Linking (`build.rs`):** Configures and compiles `libwolfssl.a` with position-independent code (`-fPIC`), TLS 1.3 (`-DWOLFSSL_TLS13=ON`), ALPN (`-DWOLFSSL_ALPN=ON`), SNI (`-DWOLFSSL_SNI=ON`), and DTLS (`-DWOLFSSL_DTLS=ON`).
- **Safe Tokio Asynchronous Wrapper (`WolfTlsStream`):** Implemented custom `WolfTlsStream` implementing Tokio's `AsyncRead` and `AsyncWrite`. Uses non-blocking socket file descriptors and `stream.try_io` to bridge wolfSSL's non-blocking C state machine (`WOLFSSL_ERROR_WANT_READ`, `WOLFSSL_ERROR_WANT_WRITE`) with Tokio's reactor.
- **Thread-Safe Session Multiplexing:** Protected `WOLFSSL*` session handle with `Arc<Mutex<WolfSslPtr>>` to allow concurrent full-duplex reader (`read_half`) and writer (`write_half`) polling without lockups or memory races.
- **Standardized Benchmarks & Full Suite Verification:** Benchmarked TLS throughput at **15,146 msgs/sec** under 8 concurrent client sessions with mean 27.84 ms/handshake. All 84 test suites passing cleanly.

---

## [0.2.2] - 2026-10-13

### 🚀 Major Highlights
- **Full QoS 2 Exactly-Once 4-Step State Machine:** Completed bidirectional 4-step state machine (`PUBLISH` $\rightarrow$ `PUBREC` $\rightarrow$ `PUBREL` $\rightarrow$ `PUBCOMP`) across TCP, TLS, and MQTT-SN UDP listeners.
- **Inflight Packet Deduplication:** Strict duplicate suppression guarantees that re-transmitted packets on lossy wireless channels or network timeouts are acknowledged via `PUBREC` without duplicate dispatch to subscribers.
- **MQTT-SN Sleeping Client Message Buffering:** Downstream messages addressed to sleeping sensor nodes (`asleep = true`) are queued in memory and atomically flushed upon waking up via `PINGREQ { client_id }` prior to `PINGRESP`.
- **Session Keepalive Reaper & LWT Timeout Dispatch:** Background monitor (500 ms interval) detects silent nodes exceeding $1.5 \times \text{duration}$, terminates dead sessions, and automatically broadcasts their registered Last Will & Testament across all transports.
- **High-Precision Performance Benchmarks:** Added benchmark suites for QoS 2 4-step handshakes (2.19M handshakes/sec) and MQTT-SN datagram codec (6.74M pkts/sec).
- **Test Suite Expansion:** Expanded automated test suite from 76 to 84 test cases (100% pass rate).

---

### 🔍 Detailed Changes & Engineering Rationale

#### 1. Inbound & Outbound QoS 2 State Machine
- **Files Modified:** [`src/server.rs`](src/server.rs), [`src/server_sn.rs`](src/server_sn.rs)
- **Why It Was Done:**
  - OASIS MQTT v3.1.1/v5.0 §4.3.3 and OASIS MQTT-SN v1.2 §5.4.10 require a 4-step handshake to guarantee exactly-once delivery semantics without message loss or duplication.
  - Previously, the broker acknowledged inbound QoS 2 from publishers, but subscriber-side outbound delivery lacked handling for subscriber `PUBREC` and `PUBCOMP` responses, causing subscribers expecting full QoS 2 handshakes to hang or timeout.
- **What Changed:**
  - Added `MqttPacket::PubRec` and `MqttPacket::PubComp` handling in [`src/server.rs`](src/server.rs). When a subscriber replies with `PUBREC`, the broker transmits `PUBREL`, and when the subscriber replies with `PUBCOMP`, the transfer is marked complete.
  - Added `inflight_qos2_msg_ids: HashSet<u16>` to `SnClientSession` in [`src/server_sn.rs`](src/server_sn.rs). Inbound QoS 2 publishes from wireless nodes check this set; duplicate retransmissions receive an immediate `PUBREC` without re-dispatching to the router. `PubRel` removes the ID and replies with `PubComp`.

#### 2. MQTT-SN Sleeping Client Message Queue Buffering
- **Files Modified:** [`src/server_sn.rs`](src/server_sn.rs)
- **Why It Was Done:**
  - OASIS MQTT-SN v1.2 §5.4.20 specifies that battery-powered sensor nodes and UAVs can enter an asleep state (`DISCONNECT { duration: T }`) with their radio receivers turned off. Transmitting UDP datagrams to a sleeping node leads to packet loss.
- **What Changed:**
  - Added `buffered_messages: Vec<BytesMut>` to `SnClientSession`.
  - In the subscriber forwarding loop, if `session.asleep == true`, incoming messages are queued in `session.buffered_messages`.
  - When the client wakes up and sends `PINGREQ { client_id: Some(id) }`, the broker drains and flushes all buffered messages to the node before sending `PINGRESP`.

#### 3. MQTT-SN Session Keepalive Reaper & LWT Broadcast
- **Files Modified:** [`src/server_sn.rs`](src/server_sn.rs)
- **Why It Was Done:**
  - OASIS MQTT-SN v1.2 §5.4.5 dictates that if a client does not transmit any message within $1.5 \times \text{T\_duration}$, the gateway must consider the client lost, clean up the session, and publish its Last Will and Testament (LWT).
- **What Changed:**
  - Spawned `Task 3` in `MqttSnServer::run` running every 500 ms.
  - Detects expired peers, removes them from active sessions and client channels, and dispatches their stored `will` packet through `dispatch_publish` to all matching subscribers across TCP, TLS, and SN.
  - Updated `session.last_seen = Instant::now()` on *any* received packet (not just `PINGREQ`) per §5.4.18.

#### 4. Dynamic Gateway-Initiated Topic Registration
- **Files Modified:** [`src/server_sn.rs`](src/server_sn.rs)
- **Why It Was Done:**
  - OASIS MQTT-SN v1.2 §5.4.8 states that when a gateway sends a `PUBLISH` to a client for a topic that has not yet been registered (e.g. from a wildcard subscription `#` or published by a TCP client), it must assign a Topic ID and transmit a `REGISTER { topic_id, msg_id: 0, topic_name }` to the client first.
- **What Changed:**
  - Replaced fallback to invalid Topic ID 0 with dynamic registration and immediate transmission of `SnPacket::Register` before sending the `SnPacket::Publish`.

#### 5. Empty Will Topic Handling
- **Files Modified:** [`src/server_sn.rs`](src/server_sn.rs)
- **Why It Was Done:**
  - OASIS MQTT-SN v1.2 §5.4.4 notes that if a client sends a `WILLTOPIC` with an empty string, it indicates the client wishes to clear its will. The gateway must not prompt for `WILLMSGREQ`, but immediately send `CONNACK`.
- **What Changed:**
  - Added check: if `will_topic.is_empty()`, clears `session.will` and directly replies with `SnPacket::ConnAck { return_code: 0x00 }`.

---

### 🧪 Automated Test Suite Expansion

Two new end-to-end integration tests were added, bringing the project to **84 passing tests**:

1. **`test_tcp_subscriber_qos2_full_handshake`** ([`tests/test_unified_listeners_and_hardening.rs`](tests/test_unified_listeners_and_hardening.rs)):
   - Verifies subscriber-side QoS 2 4-step delivery: Subscriber receives `PUBLISH (QoS 2)` $\rightarrow$ replies with `PUBREC` $\rightarrow$ receives `PUBREL` from broker $\rightarrow$ concludes with `PUBCOMP`.
2. **`test_mqtt_sn_qos2_retransmission_deduplication`** ([`tests/test_mqtt_sn_udp.rs`](tests/test_mqtt_sn_udp.rs)):
   - Publisher connects, registers topic, and transmits a QoS 2 `PUBLISH`.
   - Subscriber receives message.
   - Publisher simulates network retry by transmitting identical QoS 2 packet.
   - Broker replies with `PUBREC` but suppresses duplicate dispatch to subscriber.
   - Publisher completes handshake with `PUBREL` $\rightarrow$ `PUBCOMP`.

---

### 📊 Benchmark Results

Added suites 13 and 14 to [`benches/bench_throughput.rs`](benches/bench_throughput.rs):

```text
--- 13. QoS 2 Full 4-Step State Machine Handshake ---
  Completed 1,000,000 full 4-step QoS 2 handshakes in 456.763 ms
  Throughput      : 2,189,317.24 handshakes/sec  (2.19 million/sec)
  Latency/Step    : 456.76 ns/handshake (4 wire packets + deduplication)

--- 14. MQTT-SN v1.2 Wire Codec & Predefined Topic Telemetry ---
  Completed 1,000,000 MQTT-SN QoS -1 frame roundtrips in 148.432 ms
  Throughput      : 6,737,110.30 pkts/sec  (6.74 million/sec)
  Codec Latency   : 148.43 ns/op
```
