# WolfiMQ configuration and operations guide

Reference for configuring, securing and operating the `wolf-broker` binary.

## Contents

1. [Architecture](#1-architecture)
2. [Configuration sources](#2-configuration-sources)
3. [Configuration reference](#3-configuration-reference)
4. [Command line, signals and shutdown](#4-command-line-signals-and-shutdown)
5. [Access control (`acl.conf`)](#5-access-control-aclconf)
6. [TLS and PKI](#6-tls-and-pki)
7. [MQTT protocol behaviour](#7-mqtt-protocol-behaviour)
8. [MQTT-SN gateway](#8-mqtt-sn-gateway)
9. [Monitoring](#9-monitoring)
10. [Deployment](#10-deployment)
11. [Building, cross-compiling and FIPS](#11-building-cross-compiling-and-fips)
12. [Benchmarks](#12-benchmarks)

---

## 1. Architecture

```
  MQTT 3.1.1 / 5.0 over TCP     MQTT 3.1.1 / 5.0 over TLS     MQTT-SN 1.2 over UDP
     [listeners.tcp]               [listeners.tls]             [listeners.mqtt_sn]
            │                         wolfSSL                          │
            └──────────────┬─────────────┴───────────────┬─────────────┘
                           │       shared broker state     │
                ┌──────────┴──────────┬──────────────┬────┴─────────────┐
                │ sessions & queues   │ subscriptions│ retained store   │
                │ (per client id)     │ (topic trie) │ (quotas, expiry) │
                └─────────────────────┴──────────────┴──────────────────┘
```

- Every connection has a reader task (decodes and handles client packets) and a writer task
  (drains the session queue and encodes each packet for the client's protocol version).
- A **session** belongs to a client id and may outlive its connection (persistent sessions).
  It holds the subscriptions, a bounded outbound queue, the QoS 1/2 inflight window and the
  inbound QoS 2 de-duplication state.
- A background task runs once per second: session expiry, delayed Will messages, retained
  message expiry and `$SYS` metrics.
- All state lives in memory; a restart clears sessions and retained messages.

## 2. Configuration sources

Priority (highest first):

1. **Environment variables** `WOLFIMQ_<PATH>` — the TOML key path in upper case with `__`
   between levels. Values are parsed as TOML literals; anything else is taken as a string.
2. **The TOML file** — `--config <file>`, else `$WOLFIMQ_CONFIG`, else `config/broker.toml` if it
   exists. A file named explicitly must exist.
3. **Compiled defaults.**

```bash
WOLFIMQ_LISTENERS__TCP__PORT=1884                       # integer
WOLFIMQ_SECURITY__AUTH__ALLOW_ANONYMOUS=true            # boolean
WOLFIMQ_BROKER__NODE_ID=edge-07                         # string (unquoted is fine)
WOLFIMQ_SECURITY__TLS__ALPN_PROTOCOLS='["mqtt"]'        # array
WOLFIMQ_LISTENERS__MQTT_SN__PREDEFINED_TOPICS__5=uav/x  # map entry
```

`wolf-broker --print-config` shows the merged result. Unknown keys (typos, options removed in
newer versions) are reported as warnings at startup.

## 3. Configuration reference

### `[broker]`

| Key | Default | Description |
| :--- | :--- | :--- |
| `node_id` | `"wolf-broker-node-01"` | Name of this broker instance (logs). |
| `max_connections` | `100000` | Maximum simultaneous TCP + TLS connections; extra connections are closed immediately. `0` = unlimited. |
| `worker_threads` | `0` | Tokio worker threads; `0` = one per CPU core. |
| `connect_timeout_sec` | `10` | Time a new connection has to deliver its CONNECT packet (prevents slow-drip connections). |
| `shutdown_grace_sec` | `5` | How long SIGINT / SIGTERM waits for connections to close. |

### `[logging]`

| Key | Default | Description |
| :--- | :--- | :--- |
| `level` | `"info"` | `trace`, `debug`, `info`, `warn`, `error`. `RUST_LOG` overrides it when set. |
| `format` | `"pretty"` | `pretty`, `compact` or `json`. |
| `target` | `true` | Include the module path. |
| `thread_ids` | `false` | Include thread ids. |
| `line_numbers` | `false` | Include source line numbers. |

### `[listeners.tcp]` — plain MQTT

| Key | Default | Description |
| :--- | :--- | :--- |
| `enabled` | `true` | Plain TCP listener. The sample `broker.toml` disables it. |
| `bind_address` | `"127.0.0.1"` | Credentials are not encrypted: keep this on loopback or a trusted network. |
| `port` | `1883` | |

### `[listeners.tls]` — MQTT over wolfSSL TLS

| Key | Default | Description |
| :--- | :--- | :--- |
| `enabled` | `false` | TLS listener (settings in `[security.tls]`). The sample file enables it. |
| `bind_address` | `"0.0.0.0"` | |
| `port` | `8883` | |

### `[listeners.mqtt_sn]` — MQTT-SN gateway (UDP)

| Key | Default | Description |
| :--- | :--- | :--- |
| `enabled` | `false` | |
| `bind_address` | `"0.0.0.0"` | |
| `port` | `1884` | |
| `gateway_id` | `1` | Sent in ADVERTISE / GWINFO. |
| `advertise_interval_sec` | `900` | ADVERTISE broadcast period; `0` disables it. |
| `advertise_address` | `"255.255.255.255"` | ADVERTISE destination (sent to `<address>:<port>`). |
| `acl_user` | `""` | ACL account used by all MQTT-SN clients. Empty = anonymous identity (needs `allow_anonymous`). Must exist in the ACL file. |
| `max_sessions` | `10000` | Maximum connected MQTT-SN clients. |
| `allow_qos_minus1` | `true` | Accept connectionless QoS −1 publishes (predefined / short topic ids only). |
| `retry_interval_sec` | `10` | Retransmission interval for unacknowledged QoS 1/2 messages and REGISTER (Tretry). |
| `max_idle_sec` | `3600` | Clients that connected with keep-alive 0 are dropped after this much silence. |
| `max_retries` | `3` | Retransmissions before the client is treated as lost (Nretry). |
| `predefined_topics` | `{}` | Map of topic id (1–65534, as a string key) to topic name. |

### `[security.tls]`

| Key | Default | Description |
| :--- | :--- | :--- |
| `ca_cert_file` | `"certs/ca-cert.pem"` | CA used to verify client certificates. |
| `server_cert_file` | `"certs/server-cert.pem"` | Server certificate chain (PEM). |
| `server_key_file` | `"certs/server-key.pem"` | Server private key (PEM). |
| `require_client_cert` | `true` | Mutual TLS: clients must present a certificate signed by `ca_cert_file`. |
| `verify_client_identity` | `false` | Require the MQTT ClientID to equal the client certificate CN or one of its SANs (needs `require_client_cert`). |
| `min_tls_version` | `"TLSv1.3"` | `"TLSv1.2"` or `"TLSv1.3"`. |
| `ciphers` | `""` | wolfSSL cipher list, `:` or `,` separated (e.g. `TLS13-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256`). Empty = wolfSSL defaults. Invalid lists fail at startup. |
| `alpn_protocols` | `["mqtt"]` | ALPN protocols; a client offering only other protocols is rejected. Empty = no ALPN. |
| `handshake_timeout_sec` | `10` | Maximum TLS handshake duration. |

### `[security.auth]`

| Key | Default | Description |
| :--- | :--- | :--- |
| `allow_anonymous` | `false` | Accept clients without a user name; they use the `anonymous` ACL account, or full access if the ACL file declares none (a warning is logged). |
| `password_hash_algorithm` | `"argon2id"` | Algorithm used by `--hash-password`: `argon2id` or `sha256` (legacy). Verification accepts both formats. |
| `acl_file` | `"config/acl.conf"` | Accounts and rules. A missing or invalid file stops the broker at startup. Empty = no accounts. |
| `max_concurrent_auth` | `0` | Concurrent Argon2 verifications; `0` = number of CPU cores. |
| `client_id_takeover` | `"same_user"` | A new connection with a ClientID already in use replaces the old one only if it belongs to the same user (`same_user`), or always (`any`, the plain MQTT behaviour). |

### `[mqtt.protocol]`

| Key | Default | Description |
| :--- | :--- | :--- |
| `allow_v311` / `allow_v500` | `true` / `true` | Accepted protocol versions (others get CONNACK 0x01 / 0x84). |
| `max_packet_size` | `4194304` | Largest packet accepted, fixed header included; announced to v5.0 clients. Larger packets close the connection (v5.0: DISCONNECT 0x95). Must not exceed `max_queued_bytes`. |
| `receive_maximum` | `65535` | Inbound QoS 2 messages a v5.0 client may have unacknowledged (announced in CONNACK). |
| `topic_alias_maximum` | `20` | Topic aliases a v5.0 client may use; `0` disables them. |
| `max_keep_alive_sec` | `3600` | v5.0 clients asking for more (or for 0) are told this value via Server Keep Alive. `0` = no limit. |
| `maximum_qos` | `2` | Highest QoS granted; subscriptions are downgraded, v5.0 publishes above it are rejected (0x9B). |
| `allow_wildcard_subscriptions` | `true` | |
| `allow_retained_messages` | `true` | When `false`, v5.0 retained publishes are rejected (0x9A) and v3.1.1 ones are delivered as non-retained. |
| `allow_shared_subscriptions` | `true` | `$share/<group>/<filter>` subscriptions. |

### `[mqtt.queues]`

| Key | Default | Description |
| :--- | :--- | :--- |
| `max_queued_messages` | `5000` | Messages buffered per session (slow subscriber or offline persistent session). |
| `max_queued_bytes` | `8388608` | Payload + topic bytes buffered per session. |
| `queue_full_policy` | `"drop_oldest"` | `drop_oldest` keeps the newest messages, `drop_newest` keeps the oldest. Dropped messages are counted in `$SYS/broker/messages/dropped`. |
| `max_inflight_messages` | `32` | Unacknowledged outbound QoS 1/2 messages per session. The effective window is the smaller of this and the client's Receive Maximum, and the bytes held for retransmission are also capped by `max_queued_bytes`. |
| `default_message_expiry_sec` | `0` | Drop queued messages without a Message Expiry Interval after waiting this long. `0` = never. |
| `max_session_expiry_sec` | `86400` | Cap for the v5.0 Session Expiry Interval, and lifetime of v3.1.1 `CleanSession=0` sessions after disconnect. `0` disables persistent sessions. |

### `[mqtt.retained]`

| Key | Default | Description |
| :--- | :--- | :--- |
| `max_messages` | `100000` | Maximum retained topics; new topics beyond it are not stored. |
| `max_bytes` | `67108864` | Maximum total retained payload + topic bytes. |

### `[monitoring]`

| Key | Default | Description |
| :--- | :--- | :--- |
| `sys_topics_enabled` | `true` | Publish metrics under `$SYS/broker/...` (retained). |
| `sys_update_interval_sec` | `30` | Publication period. |

## 4. Command line, signals and shutdown

```text
wolf-broker [OPTIONS]
  -c, --config <FILE>          Configuration file [env: WOLFIMQ_CONFIG]
      --check-config           Validate configuration, ACL file and TLS files, then exit
      --print-config           Print the effective configuration as TOML
      --hash-password [PASS]   Print an acl.conf password_hash entry (stdin when PASS is omitted)
  -h, --help                   Help
  -V, --version                Version
```

Exit codes: `0` success, `1` runtime or configuration error, `2` invalid arguments.

| Signal | Effect |
| :--- | :--- |
| `SIGINT`, `SIGTERM` | Stop accepting connections, send DISCONNECT 0x8B (Server shutting down) to v5.0 clients, close connections, wait up to `shutdown_grace_sec`. |
| `SIGHUP` | Reload `acl_file`. The new file replaces all accounts atomically; if it does not parse, the old rules stay active and an error is logged. New rules apply immediately to existing connections and subscriptions (deliveries are re-checked), and removed accounts lose all access; passwords are only checked at the next CONNECT. |

Prefer reading the password from stdin so it does not end up in the shell history:

```bash
wolf-broker --hash-password            # type the password, press Enter
# password_hash:$argon2id$v=19$m=19456,t=2,p=1$...
```

## 5. Access control (`acl.conf`)

```ini
# user <name> [password:<pass>] [password_hash:<hash>] [role:<role>] [rooms:<r1,r2>|rooms:*]
user superadmin password_hash:$argon2id$... role:admin rooms:*

user dev_sarah password_hash:$argon2id$... role:member rooms:engineering
topic readwrite users/%u/notes          # rules listed under a user apply to that user

user sensor_node password_hash:$argon2id$... role:device

user sn_gateway                          # no password: cannot log in, used as acl_user
topic readwrite uav/#

user anonymous                           # used when allow_anonymous = true
topic read public/#
topic deny #
```

- `topic <read|write|readwrite|deny> <pattern>` (`pattern` is a synonym of `topic`).
- Macros: `%u` user name, `%c` ClientID, `%r` each of the user's rooms (`rooms:*` = any room).
  A substitution value containing `+`, `#`, `/` or NUL never matches, so ClientIDs or user
  names cannot widen a rule.
- Syntax errors (unknown directives, attributes or permissions, invalid patterns, rules before
  any `user`) are reported with their line number and stop the broker / reject a reload.

**Evaluation (first match wins).** For each user the rules are, in order: the rules listed
under the user, then the role defaults below.

- *Publish* to a topic: the first rule whose pattern matches the topic decides. `deny` refuses;
  a rule granting write allows; a rule without write permission is skipped.
- *Subscribe* to a filter: the first allow rule that **covers** the entire filter (every topic
  the filter can match) with read permission grants it; any earlier `deny` rule that merely
  **overlaps** the filter refuses it. Example: a member cannot subscribe to
  `rooms/engineering/#` because it overlaps the denied `rooms/%r/admin/#`.
- Nothing matched: denied. `admin` users bypass all checks.

| Role | Default rules (after the user's own rules) |
| :--- | :--- |
| `admin` | unrestricted |
| `moderator` | readwrite `rooms/%r/#`, readwrite `users/%u/#` |
| `member` | deny `rooms/%r/admin/#`; readwrite `rooms/%r/chat`, `rooms/%r/presence`, `users/%u/private`; read `rooms/%r/announcements` |
| `viewer` | read `rooms/%r/chat`, `rooms/%r/announcements`; deny `rooms/%r/#` |
| `device` | write `devices/%c/telemetry`; read `devices/%c/commands`; deny `#`. The user name must equal the ClientID. |
| none | only the listed rules |

Wildcards in the first level never match topics starting with `$` (MQTT §4.7.2), so `#` does
not grant `$SYS/#`; list it explicitly when needed.

Denied operations: v5.0 clients get reason code 0x87 (Not authorized) in PUBACK / PUBREC /
SUBACK / CONNACK; v3.1.1 clients get SUBACK 0x80, CONNACK 0x04 / 0x05, and denied publishes are
acknowledged and dropped (v3.1.1 has no negative acknowledgement).

## 6. TLS and PKI

wolfSSL is linked statically. TLS 1.3 is the default; set `min_tls_version = "TLSv1.2"` to also
accept TLS 1.2 clients. TLS 1.0 / 1.1 are not compiled in.

Development PKI:

```bash
bash scripts/generate_certs.sh certs            # CA, server (CN=localhost, SAN localhost/127.0.0.1), client (CN=client01)
CLIENT_CN=sensor-17 bash scripts/generate_certs.sh certs-sensor17
openssl x509 -in certs/server-cert.pem -noout -ext subjectAltName
```

With `verify_client_identity = true` a client presenting a certificate for `sensor-17` must
connect with ClientID `sensor-17` (CN or any SAN DNS name); otherwise CONNACK 0x87 / 0x05.

Test a TLS listener with the bundled simulator:

```bash
wolf-simulate --tls --port 8883 --ca certs/ca-cert.pem --cert certs/client-cert.pem --key certs/client-key.pem
```

## 7. MQTT protocol behaviour

- **Versions:** MQTT v3.1.1 (level 4) and v5.0 (level 5). MQTT 3.1 (`MQIsdp`, level 3) gets
  CONNACK 0x01. The first packet must be CONNECT; a second CONNECT is a protocol error.
- **Client identifiers:** empty ClientIDs get a generated id (`wolfimq-<hex>`, returned to v5.0
  clients as Assigned Client Identifier); v3.1.1 requires `CleanSession = 1` for that.
- **Keep alive:** the connection is closed after 1.5 × keep alive without a complete packet
  (v5.0: DISCONNECT 0x8D), and the Will is published.
- **Sessions:** v3.1.1 `CleanSession = 0` and v5.0 Session Expiry Interval > 0 keep the session
  after disconnect (capped by `max_session_expiry_sec`; v5.0 clients are told the effective
  value). Only such a persistent session can be resumed, and only by the same user. Reconnecting with `clean_start = 0` resumes it: CONNACK session present = 1, queued
  messages are delivered, unacknowledged QoS 1/2 messages are resent with DUP and their
  original packet ids.
- **Takeover:** a new connection with a ClientID in use closes the old connection (v5.0:
  DISCONNECT 0x8E), subject to `client_id_takeover`.
- **Will:** published on abnormal close, keep-alive timeout, takeover, or DISCONNECT 0x04. A
  v5.0 Will Delay Interval postpones it; resuming the session before then cancels it.
- **QoS:** each subscriber receives `min(publish QoS, granted QoS)`. Outbound packet ids are
  allocated per session and never reused while in flight. At most `max_inflight_messages`
  deliveries (or the client's Receive Maximum, if lower) are unacknowledged at a time. Inbound QoS 2 duplicates (same
  packet id before PUBREL) are acknowledged but not delivered twice.
- **Flow control:** a v5.0 client's Receive Maximum limits unacknowledged QoS 1/2 deliveries;
  its Maximum Packet Size causes larger messages to be skipped for it.
- **Message expiry:** expired messages are not delivered; forwarded messages carry the remaining
  lifetime.
- **Retained messages:** zero-length payload clears; delivered with RETAIN = 1 on subscribe
  (subject to Retain Handling), never to shared subscriptions.
- **Shared subscriptions:** `$share/<group>/<filter>`; each message goes to one member,
  round-robin, preferring connected members.
- **Errors:** malformed packets close the connection (v5.0: DISCONNECT 0x81 / 0x82 / 0x95 / …
  before closing).

## 8. MQTT-SN gateway

The gateway implements MQTT-SN v1.2 over UDP as an aggregating gateway: SN clients get broker
sessions like MQTT clients, so subscriptions, retained messages and Will messages are shared.

- **Identity:** set `acl_user` to an account (usually without a password) whose rules describe
  what SN devices may do. MQTT-SN has no credentials and UDP source addresses can be spoofed;
  run the gateway only on trusted networks.
- **Connect:** `CONNECT` (optionally with the Will handshake `WILLTOPICREQ` → `WILLTOPIC` →
  `WILLMSGREQ` → `WILLMSG`) → `CONNACK`. Reconnecting from the same address replaces the link.
- **Topics:** predefined ids from `predefined_topics`, two-character short names, and
  `REGISTER`. When a message arrives for a topic the client has no id for, the gateway sends
  `REGISTER` and publishes only after `REGACK`. Wildcard subscriptions return topic id 0.
- **QoS:** −1 (no connection, predefined / short ids only, still authorized against
  `acl_user`), 0, 1 and 2. One QoS 1/2 message is in flight per client and retransmitted every
  `retry_interval_sec` with DUP set, up to `max_retries`, after which the client is lost and its
  Will is published. An unacknowledged message stays in the session and is delivered again
  when a persistent client reconnects.
- **Sleeping clients:** `DISCONNECT` with a duration puts the client to sleep; messages are queued
  in its session (subject to the queue limits). `PINGREQ` with the ClientID wakes it: queued
  messages are sent, then `PINGRESP`, and the client sleeps again. No message within 1.5 × the
  sleep duration ends the session.
- **Forwarders:** encapsulated frames (`0xFE`) are answered encapsulated for the same wireless
  node id.

## 9. Monitoring

Retained topics published every `sys_update_interval_sec`:

| Topic | Value |
| :--- | :--- |
| `$SYS/broker/version` | `WolfiMQ <version>` |
| `$SYS/broker/uptime` | seconds |
| `$SYS/broker/clients/connected` | connected sessions (MQTT + MQTT-SN) |
| `$SYS/broker/clients/total` | sessions including disconnected persistent ones |
| `$SYS/broker/messages/received` / `sent` / `dropped` | counters |
| `$SYS/broker/bytes/received` / `sent` | payload bytes |
| `$SYS/broker/retained/count` | retained topics |
| `$SYS/broker/subscriptions/count` | subscriptions |

Subscribe with an account allowed to read `$SYS/#` (admins are).

## 10. Deployment

### systemd

```ini
# /etc/systemd/system/wolfimq.service
[Unit]
Description=WolfiMQ MQTT broker
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=wolfimq
Group=wolfimq
WorkingDirectory=/opt/wolfimq
ExecStart=/opt/wolfimq/bin/wolf-broker --config /opt/wolfimq/config/broker.toml
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=3s
LimitNOFILE=1048576
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadOnlyPaths=/opt/wolfimq

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now wolfimq
sudo systemctl reload wolfimq        # reload acl.conf
```

Binding ports below 1024 requires `AmbientCapabilities=CAP_NET_BIND_SERVICE`.

### Operating system limits

Each connection uses one file descriptor; raise `LimitNOFILE` (systemd) or `nofile`
(`/etc/security/limits.d/`) to at least `max_connections` plus a margin. For many concurrent
connections also consider:

```bash
# /etc/sysctl.d/99-wolfimq.conf
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.ip_local_port_range = 1024 65535
```

## 11. Building, cross-compiling and FIPS

```bash
cargo build --release                                         # native build
task build:cross TARGET=aarch64-unknown-linux-gnu             # needs cargo-zigbuild + zig
cargo zigbuild --release --target x86_64-unknown-linux-musl   # static Linux binary
```

`build.rs` compiles the wolfSSL submodule with CMake (via the `cmake` crate) into Cargo's
`OUT_DIR` for the selected target, with TLS 1.3 / 1.2, ALPN, SNI, Curve25519 and hardening
enabled and old TLS versions, DTLS and examples disabled.

**FIPS-Ready:** download the wolfSSL FIPS-Ready bundle, extract it to
`external/wolfssl-fips-bundle/` (or set `WOLFSSL_FIPS_BUNDLE_DIR`), then:

```bash
cargo build --release --no-default-features --features wolfssl-fips
wolf-broker --version     # reports the FIPS-Ready build
```

The bundle is built with wolfSSL's autotools (`--enable-fips=ready`) including the in-core
integrity hash step. FIPS-Ready is not a CMVP-validated module.

## 12. Benchmarks

Benchmark results are generated by CI (see the release notes and `BENCHMARKS.md` of each
release). Locally:

```bash
task bench                 # codec, trie, retained store and loopback micro-benchmarks
task bench:tls             # MQTT over TLS 1.3 throughput with 8 clients
task bench:tls:compare     # the same, side by side with a local Mosquitto if installed
task bench:report          # everything, written to BENCHMARKS.md
```

`wolf-bench-tls` options: `--concurrency <n>`, `--count <messages>`, `--payload-size <bytes>`,
`--external-port <port>` / `--external-name <name>` (benchmark another broker),
`--markdown-output <file>`. Numbers depend heavily on the machine; compare runs from the same
hardware only.
