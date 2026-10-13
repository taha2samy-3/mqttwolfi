<p align="center">
  <img src="assets/logo.svg" alt="WolfiMQ" width="720"/>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#quick-start">Quick start</a> •
  <a href="#configuration">Configuration</a> •
  <a href="#security">Security</a> •
  <a href="#mqtt-sn-gateway">MQTT-SN</a> •
  <a href="#benchmarks">Benchmarks</a> •
  <a href="#development">Development</a> •
  <a href="#license">License</a>
</p>

---

**WolfiMQ** is an MQTT broker written in Rust. It speaks MQTT v3.1.1, MQTT v5.0 and
MQTT-SN v1.2 (UDP), uses [wolfSSL](https://www.wolfssl.com/) for TLS 1.3 / mutual TLS (with an
optional FIPS-Ready build), and ships as a single binary for Linux, Windows and macOS.

> **Status:** early-stage. The broker is a single node and keeps all state in memory
> (sessions and retained messages are lost on restart). It is not a replacement for clustered
> or disk-persistent brokers yet.

## Features

| Area | Supported |
| :--- | :--- |
| Protocols | MQTT v3.1.1, MQTT v5.0, MQTT-SN v1.2 over UDP — all sharing one routing core |
| Transports | TCP, TLS 1.2 / 1.3 via wolfSSL (mutual TLS, ALPN, cipher selection), UDP for MQTT-SN |
| QoS | 0, 1 and 2 in both directions, per-session packet ids, DUP resend on session resume |
| Sessions | Clean and persistent sessions (v3.1.1 `CleanSession=0`, v5.0 Session Expiry), session takeover |
| MQTT v5.0 | Properties forwarding, topic aliases, subscription identifiers, No Local, Retain As Published, Retain Handling, shared subscriptions (`$share/…`), Receive Maximum, Maximum Packet Size, Message Expiry, Will Delay, reason codes, server DISCONNECT |
| Retained / Will | Retained store with quotas and expiry; Last Will on abnormal close, keep-alive timeout or takeover |
| Security | Argon2id passwords, ACL with roles and `%u` / `%c` / `%r` macros, ClientID ↔ certificate binding, client certificate revocation (CRL), limits on connections, sessions, subscriptions, packets, queues and topic depth |
| Operations | TOML config + `WOLFIMQ_*` environment overrides, `$SYS/broker/...` metrics, SIGHUP ACL reload, graceful SIGTERM |
| MQTT-SN | Predefined and short topic ids, REGISTER, QoS −1, Will, sleeping clients, retransmission, forwarder encapsulation |

Not implemented: clustering, disk persistence, MQTT over WebSockets, MQTT v5.0 enhanced
authentication (AUTH), DTLS for MQTT-SN.

## Quick start

### Download a release

Each [release](../../releases) contains archives for:

| Archive suffix | Platform |
| :--- | :--- |
| `linux-x86_64`, `linux-aarch64`, `linux-armv7`, `linux-riscv64` | Linux, glibc ≥ 2.17 (riscv64: ≥ 2.27) |
| `linux-x86_64-musl`, `linux-aarch64-musl` | Linux, fully static (any distribution, Alpine) |
| `windows-x86_64` | Windows 10 / Server 2016 or newer |
| `macos-aarch64`, `macos-x86_64` | macOS (Apple silicon / Intel) |

```bash
sha256sum -c wolfimq-<version>-linux-x86_64.tar.gz.sha256      # verify the download
tar xzf wolfimq-<version>-linux-x86_64.tar.gz && cd wolfimq-<version>-linux-x86_64
bash scripts/generate_certs.sh certs        # throw-away test PKI; use real certificates in production
./bin/wolf-broker --config config/broker.toml
```

### Build from source

Requirements: Rust ≥ 1.85, CMake, a C compiler, and OpenSSL ≥ 1.1.1 command line tools (only
for the test PKI; on macOS the system LibreSSL does not work: `brew install openssl@3`).

```bash
git clone --recursive <repository-url> && cd wolfimq   # or: git submodule update --init
cargo build --release
./target/release/wolf-broker --help
```

### Try it

The sample configuration enables mutual TLS on 8883 (MQTT-SN is disabled). Create a test PKI
in `certs/`, then, for a quick local test, also enable plain TCP on loopback through the
environment:

```bash
bash scripts/generate_certs.sh certs    # throw-away CA, server and client certificates
WOLFIMQ_LISTENERS__TCP__ENABLED=true ./target/release/wolf-broker --config config/broker.toml
./target/release/wolf-simulate          # in another terminal: runs a scripted pub/sub session
```

`wolf-simulate --tls` does the same over TLS using `certs/`. The sample `config/acl.conf`
contains example accounts with **publicly known passwords**: replace them before exposing the
broker.

## Configuration

Configuration comes from (highest priority first) environment variables, the TOML file, and
compiled defaults. Any key can be overridden from the environment:

```bash
WOLFIMQ_LISTENERS__TCP__PORT=1884 \
WOLFIMQ_SECURITY__AUTH__ALLOW_ANONYMOUS=true \
WOLFIMQ_SECURITY__TLS__ALPN_PROTOCOLS='["mqtt"]' \
  wolf-broker --config /etc/wolfimq/broker.toml
```

| Command | Purpose |
| :--- | :--- |
| `wolf-broker --check-config` | Validate configuration, ACL file and TLS material, then exit |
| `wolf-broker --print-config` | Print the effective configuration (file + environment) |
| `wolf-broker --hash-password` | Read a password on stdin, print an `acl.conf` `password_hash:` entry |
| `kill -HUP <pid>` | Reload the ACL file atomically; applies to existing connections too (a broken file is rejected) |
| `kill -TERM <pid>` | Graceful shutdown (v5.0 clients receive DISCONNECT 0x8B) |

Unknown or misspelled keys produce a warning at startup. See
**[docs/CONFIGURATION_AND_CONTROL.md](docs/CONFIGURATION_AND_CONTROL.md)** for every setting,
the ACL format, TLS / PKI setup, systemd and kernel tuning.

## Security

- **Use TLS outside localhost.** Plain TCP defaults to `127.0.0.1`. The TLS listener uses
  wolfSSL with TLS 1.3 by default (TLS 1.2 optional), mutual TLS, CRL revocation checks, ALPN
  and configurable cipher suites; no session resumption and no 0-RTT. `verify_client_identity`
  binds the MQTT ClientID to the certificate CN / SAN and then refuses connections without a
  certificate.
- **Passwords** are Argon2id hashes in `config/acl.conf` (`--hash-password`). Rejecting an
  unknown user costs the same Argon2id verification as a known one, and concurrent
  verifications are bounded.
- **Authorization** uses first-match ACL rules per user, followed by role defaults
  (`admin`, `moderator`, `member`, `viewer`, `device`). A subscription is granted only if an
  allow rule covers the entire filter; Will topics are checked like publishes. ClientIDs and
  user names cannot inject wildcards or macros into rules.
- **Limits**: packet size, topic depth, connections, sessions, subscriptions per session,
  per-session queue (count and bytes, `drop_oldest` or `drop_newest`), retained store,
  CONNECT + authentication deadline and TLS handshake timeout.

Report vulnerabilities as described in [SECURITY.md](SECURITY.md).

### wolfSSL builds

| Variant | Command | wolfSSL source |
| :--- | :--- | :--- |
| Standard (default) | `cargo build --release` | `external/wolfssl` submodule, pinned to `v5.9.4-stable` |
| FIPS-Ready | `cargo build --release --no-default-features --features wolfssl-fips` | wolfSSL FIPS-Ready bundle in `external/wolfssl-fips-bundle/` (or `WOLFSSL_FIPS_BUNDLE_DIR`) |

"FIPS-Ready" means FIPS-approved algorithms only; it is **not** a CMVP-validated module.

## MQTT-SN gateway

The UDP gateway shares sessions, subscriptions and retained messages with the MQTT listeners,
so a drone publishing over MQTT-SN reaches a ground station subscribed over TLS and vice versa.

- **Identity:** MQTT-SN v1.2 has no credentials. All SN clients act as the ACL user named in
  `listeners.mqtt_sn.acl_user` (or as the anonymous identity when it is empty), so give that
  user minimal rights.
- **Topics:** predefined topic ids (configured), two-character short topics, and REGISTER;
  the gateway registers new topic names with the client before publishing on them.
- **Delivery:** QoS 0, 1, 2 with retransmission and QoS −1 (connectionless, predefined / short
  topics; off by default); sleeping clients get buffered messages on wake-up; Will on timeout;
  persistent sessions keep topic registrations across reconnects.
- **Caution:** traffic is unauthenticated and unencrypted, and clients are identified by a UDP
  address that can be spoofed. The gateway is disabled in the sample configuration; enable it
  only on a trusted network.

## Benchmarks

Benchmark figures are produced by CI on GitHub-hosted runners, not maintained by hand:

- every [release](../../releases) contains `BENCHMARKS.md` and shows the results in its notes;
- every push to the main branch publishes the same report in the workflow run summary.

The report covers end-to-end MQTT over TLS 1.3 throughput and latency (side by side with
Mosquitto on the same runner) plus codec and routing micro-benchmarks. Run it locally with:

```bash
task bench:report          # or: bash scripts/ci_benchmarks.sh BENCHMARKS.md
```

## Development

```bash
task ci                     # fmt check, clippy -D warnings, all tests
task test                   # unit tests + live TCP / TLS / MQTT-SN / CLI suites
task build:cross TARGET=aarch64-unknown-linux-gnu   # cross build via cargo-zigbuild
```

Integration tests start real listeners on ephemeral ports and generate a throw-away PKI with
`openssl`. CI runs formatting, clippy, tests on Linux and macOS, the minimum Rust version,
cross builds, a dependency audit and the benchmarks.

### Releasing

1. Update `version` in `Cargo.toml` and add a section to `CHANGELOG.md`.
2. Tag and push: `git tag -a v<version> -m "WolfiMQ v<version>" && git push origin v<version>`.
3. The release workflow checks that the tag matches `Cargo.toml`, runs the tests, builds all
   platforms, runs the benchmarks and publishes the GitHub release with checksums.

## License

WolfiMQ's source code is dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE).

Binaries link wolfSSL statically. wolfSSL 5.9.x is licensed under the GPLv3 (or commercially by
wolfSSL Inc.), so distributed binaries — including the release archives — are subject to the
GPLv3 unless you have a commercial wolfSSL license. See [SECURITY.md](SECURITY.md) and
`third-party/wolfssl/` in the release archives.
