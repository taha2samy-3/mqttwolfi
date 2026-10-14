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
   - [MQTT over WebSockets](#7a-mqtt-over-websockets)
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
- Memory is bounded by configuration: connections, sessions (connected or offline),
  subscriptions per session, queued messages and bytes per session (properties included),
  the retained store, packet size and topic depth (200 levels).

## 2. Configuration sources

Priority (highest first):

1. **Environment variables** `WOLFIMQ_<PATH>` — the TOML key path in upper case with `__`
   between levels. Values are parsed as TOML literals; anything else is taken as a string. A
   string that looks like a number or boolean must be quoted as TOML:
   `WOLFIMQ_BROKER__NODE_ID='"123"'`.
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

Relative paths (`acl_file`, certificate, key and CRL files) are resolved against the broker's
**working directory**, not against the configuration file. Use absolute paths in services, or
set `WorkingDirectory=` (see the systemd unit below).

## 3. Configuration reference

### `[broker]`

| Key | Default | Description |
| :--- | :--- | :--- |
| `node_id` | `"wolf-broker-node-01"` | Name of this broker instance (logs). |
| `max_connections` | `100000` | Maximum simultaneous TCP + TLS connections; extra connections are closed immediately (without a CONNACK). `0` = unlimited. |
| `max_sessions` | `200000` | Sessions kept in memory, connected or persisted offline, MQTT and MQTT-SN together. A new session beyond it is refused (CONNACK 0x03 / v5.0 0x97 Quota exceeded); existing sessions can always resume. `0` = unlimited. |
| `worker_threads` | `0` | Tokio worker threads; `0` = one per CPU core. |
| `connect_timeout_sec` | `10` | Time a new connection has to deliver its CONNECT packet **and be authenticated** (prevents slow-drip connections and unbounded waiting for a password verification slot; on timeout: CONNACK 0x03 / 0x89). |
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

### `[listeners.ws]` / `[listeners.wss]` — MQTT over WebSockets

| Key | Default (`ws` / `wss`) | Description |
| :--- | :--- | :--- |
| `enabled` | `false` / `false` | |
| `bind_address` | `"127.0.0.1"` / `"0.0.0.0"` | Plain `ws` carries credentials unencrypted: keep it on loopback behind a TLS-terminating reverse proxy (a warning is logged otherwise). |
| `port` | `8083` / `8084` | |
| `path` | `"/mqtt"` | HTTP path accepting MQTT; other paths get 404. Query strings are ignored. |
| `allowed_origins` | `[]` | Browser origins allowed to connect, e.g. `["https://dashboard.example.com"]`; `"*"` allows any. Requests without an `Origin` header (non-browser clients) and same-origin requests (`Origin` equal to the `Host` the client connected to, as Paho sends) are always accepted; other origins get 403. This stops other web sites from connecting with a visitor's browser (cross-site WebSocket hijacking). |
| `trusted_proxies` | `[]` | IP addresses of reverse proxies whose `X-Forwarded-For` header gives the client address (last entry). Ignored from any other peer. |
| `max_header_bytes` | `8192` | Largest HTTP upgrade request (1024–65536); larger requests get 431. |
| `require_client_cert` | — / `false` | `wss` only: require client certificates on this listener. With `security.tls.verify_client_identity = true`, clients without a certificate are refused on every listener. |

`wss` uses the certificate, key, CA, CRL, cipher and minimum-version settings of
`[security.tls]`. The HTTP upgrade must complete within `connect_timeout_sec`; WebSocket frames
larger than `max_packet_size` are refused (close code 1009).

### `[listeners.mqtt_sn]` — MQTT-SN gateway (UDP)

| Key | Default | Description |
| :--- | :--- | :--- |
| `enabled` | `false` | MQTT-SN has no authentication or encryption; see [§8](#8-mqtt-sn-gateway). The sample file keeps it disabled and on loopback. |
| `bind_address` | `"0.0.0.0"` | Bind it to the interface of the trusted sensor network only. |
| `port` | `1884` | |
| `gateway_id` | `1` | Sent in ADVERTISE / GWINFO. |
| `advertise_interval_sec` | `900` | ADVERTISE broadcast period; `0` disables it. |
| `advertise_address` | `"255.255.255.255"` | ADVERTISE destination (sent to `<address>:<port>`). |
| `acl_user` | `""` | ACL account used by all MQTT-SN clients. Empty = anonymous identity (needs `allow_anonymous`). Must exist in the ACL file. |
| `max_sessions` | `10000` | Maximum MQTT-SN sessions, connected or persisted (`CleanSession = 0`). |
| `allow_qos_minus1` | `false` | Accept connectionless QoS −1 publishes (predefined / short topic ids only). They need no session at all, so anyone who can send a UDP datagram to the gateway can publish with the rights of `acl_user`. |
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
| `verify_client_identity` | `false` | Require the MQTT ClientID to equal the client certificate CN or one of its subject alternative names (needs `require_client_cert`). Connections without a verified certificate — plain TCP — are then refused (CONNACK 0x05 / 0x87). |
| `crl_file` | `""` | PEM certificate revocation list issued by the CA in `ca_cert_file`; revoked client certificates fail the handshake (needs `require_client_cert`). Read at startup only: restart the broker after publishing a new CRL, and before the CRL's *Next Update* date, after which wolfSSL rejects every client certificate. Empty = no revocation checks. |
| `min_tls_version` | `"TLSv1.3"` | `"TLSv1.2"` or `"TLSv1.3"`. |
| `ciphers` | `""` | wolfSSL cipher list, `:` or `,` separated (e.g. `TLS13-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256`). Empty = wolfSSL defaults. Invalid lists fail at startup. |
| `alpn_protocols` | `["mqtt"]` | ALPN protocols; a client offering only other protocols is rejected. Empty = no ALPN. |
| `handshake_timeout_sec` | `10` | Maximum TLS handshake duration. |

### `[security.auth]`

| Key | Default | Description |
| :--- | :--- | :--- |
| `allow_anonymous` | `false` | Accept clients without a user name; they use the `anonymous` ACL account, or read/write access to every topic matched by `#` (not `$SYS/...`) if the ACL file declares none (a warning is logged). |
| `password_hash_algorithm` | `"argon2id"` | Algorithm used by `--hash-password`: `argon2id` or `sha256` (legacy). Verification accepts both formats. |
| `acl_file` | `"config/acl.conf"` | Accounts and rules. A missing or invalid file stops the broker at startup. Empty = no accounts. |
| `max_concurrent_auth` | `0` | Concurrent Argon2 verifications; `0` = number of CPU cores. |
| `client_id_takeover` | `"same_user"` | `same_user`: a ClientID whose client is **connected** can only be taken over by the same user; an **offline** session of another user is discarded and replaced by a fresh one (never resumed), so a parked session cannot lock the owner out. MQTT-SN clients never replace another user's MQTT session. `any`: always take over (plain MQTT behaviour). Sessions are only ever resumed by the user that created them. |

### `[mqtt.protocol]`

| Key | Default | Description |
| :--- | :--- | :--- |
| `allow_v311` / `allow_v500` | `true` / `true` | Accepted protocol versions (others get CONNACK 0x01 / 0x84). |
| `max_packet_size` | `4194304` | Largest packet accepted, fixed header included; announced to v5.0 clients. Larger packets close the connection (v5.0: DISCONNECT 0x95). Must not exceed `max_queued_bytes`. The CONNECT packet, buffered before authentication, is limited to 256 KiB. |
| `receive_maximum` | `65535` | Inbound QoS 2 messages a v5.0 client may have unacknowledged (announced in CONNACK). |
| `topic_alias_maximum` | `20` | Topic aliases a v5.0 client may use; `0` disables them. |
| `max_keep_alive_sec` | `3600` | v5.0 clients asking for more (or for 0) are told this value via Server Keep Alive and must follow it. v3.1.1 and MQTT-SN have no such mechanism: a larger keep alive is refused (v3.1.1 CONNACK 0x02, as Mosquitto does; MQTT-SN CONNACK rejected). A v3.1.1 keep alive of 0 (no keep alive) is accepted. `0` = no limit. |
| `maximum_qos` | `2` | Highest QoS granted; subscriptions are downgraded, v5.0 publishes above it are refused with DISCONNECT 0x9B (v5.0 clients learn the limit from CONNACK). v3.1.1 cannot be told, so its publishes are accepted and delivered at `maximum_qos`. |
| `max_subscriptions_per_session` | `10000` | Subscriptions one session may hold; more are refused with SUBACK 0x97 (v3.1.1: 0x80). Replacing an existing subscription is always allowed. `0` = unlimited. |
| `allow_wildcard_subscriptions` | `true` | |
| `allow_retained_messages` | `true` | When `false`, v5.0 retained publishes are refused with DISCONNECT 0x9A and v3.1.1 ones are delivered as non-retained. |
| `allow_shared_subscriptions` | `true` | `$share/<group>/<filter>` subscriptions. |

### `[mqtt.queues]`

| Key | Default | Description |
| :--- | :--- | :--- |
| `max_queued_messages` | `5000` | Messages buffered per session (slow subscriber or offline persistent session). |
| `max_queued_bytes` | `8388608` | Bytes buffered per session: topic + payload + v5.0 properties (User Properties, Correlation Data, …). |
| `queue_full_policy` | `"drop_oldest"` | When the queue is full, expired messages are removed first; then `drop_oldest` keeps the newest messages and `drop_newest` keeps the oldest. Every dropped message is counted in `$SYS/broker/messages/dropped`. |
| `max_inflight_messages` | `32` | Unacknowledged outbound QoS 1/2 messages per session. The effective window is the smaller of this and the client's Receive Maximum, and the bytes held for retransmission are also capped by `max_queued_bytes`. |
| `default_message_expiry_sec` | `0` | Drop queued messages without a Message Expiry Interval after waiting this long. `0` = never. |
| `max_session_expiry_sec` | `86400` | Cap for the v5.0 Session Expiry Interval, and lifetime of v3.1.1 `CleanSession=0` sessions after disconnect. v3.1.1 itself has no session expiry (Mosquitto keeps such sessions forever by default): a device offline for longer loses its subscriptions and queued messages and reconnects with session present = 0. `0` disables persistent sessions. |

### `[mqtt.retained]`

| Key | Default | Description |
| :--- | :--- | :--- |
| `max_messages` | `100000` | Maximum retained topics; new topics beyond it are not stored. |
| `max_bytes` | `67108864` | Maximum total retained bytes (topic + payload + properties). |

A retained message that does not fit is not stored, and the previous retained message of that
topic is removed (the new message must replace it, MQTT-3.3.1-5). v5.0 publishers get
PUBACK / PUBREC 0x97 (Quota exceeded); the message is still delivered to current subscribers.

### `[monitoring]`

| Key | Default | Description |
| :--- | :--- | :--- |
| `sys_topics_enabled` | `true` | Publish metrics under `$SYS/broker/...` (retained). |
| `sys_update_interval_sec` | `30` | Publication period. |

## 4. Command line, signals and shutdown

```text
wolf-broker [OPTIONS]
  -c, --config <FILE>          Configuration file [env: WOLFIMQ_CONFIG]
      --check-config           Validate configuration, ACL file and TLS files (loads the
                               certificates, key and CRL into wolfSSL), then exit
      --print-config           Print the effective configuration as TOML
      --hash-password [PASS]   Print an acl.conf password_hash entry (stdin when PASS is omitted)
  -h, --help                   Help
  -V, --version                Version
```

Exit codes: `0` success, `1` runtime or configuration error, `2` invalid arguments.

Signals are Unix only. On Windows, Ctrl+C performs the graceful shutdown and the ACL can only
be reloaded by restarting the broker. (Windows builds are cross-compiled and checked in CI but
not exercised by the test suite.)

| Signal | Effect |
| :--- | :--- |
| `SIGINT`, `SIGTERM` | Stop accepting connections, send DISCONNECT 0x8B (Server shutting down) to v5.0 clients, close connections, wait up to `shutdown_grace_sec`. |
| `SIGHUP` | Reload `acl_file`. The new file replaces all accounts atomically; if it does not parse, the old rules stay active and an error is logged. New rules apply immediately to existing connections and subscriptions (deliveries are re-checked), and removed accounts lose all access; passwords are only checked at the next CONNECT. |

Prefer reading the password from stdin so it does not end up in the shell history or the
process list (`--hash-password PASS` exposes it to both). The input is echoed on a terminal;
use `read -rs` to avoid that:

```bash
read -rs PW && printf '%s' "$PW" | wolf-broker --hash-password; unset PW
# password_hash:$argon2id$v=19$m=19456,t=2,p=1$...
```

## 5. Access control (`acl.conf`)

```ini
# user <name> [password:<pass>] [password_hash:<hash>] [role:<role>] [rooms:<r1,r2>|rooms:*]
user superadmin password_hash:$argon2id$... role:admin rooms:*

# Rules listed under a user apply to that user.
user dev_sarah password_hash:$argon2id$... role:member rooms:engineering
topic readwrite users/%u/notes

user sensor_node password_hash:$argon2id$... role:device

# No password: cannot log in over MQTT; used as listeners.mqtt_sn.acl_user.
user sn_gateway
topic write uav/+/telemetry/#
topic read uav/+/commands

# Used when allow_anonymous = true.
user anonymous
topic read public/#
topic deny #
```

Comments must be on their own line: `#` is a valid topic character, so text after a rule is
not a comment and is reported as a syntax error.

- `topic <read|write|readwrite|deny> <pattern>` (`pattern` is a synonym of `topic`).
- Macros: `%u` user name, `%c` ClientID, `%r` each of the user's rooms (`rooms:*` = any room).
  Macros are replaced in a single pass, so substituted text is never expanded again. A user
  name or ClientID containing `+`, `#`, `/`, `%` or NUL cannot be substituted: an allow rule
  using it does not match, and a **deny rule using it matches everything** (fails closed).
  ClientIDs and user names therefore cannot widen or switch off a rule.
- Roles: `admin`, `moderator`, `member`, `viewer`, `device` or `custom`; anything else is an
  error.
- Syntax errors (unknown directives, roles, attributes or permissions, invalid patterns, rules
  before any `user`, trailing text after a rule) are reported with their line number and stop
  the broker / reject a reload.
- The shipped `config/acl.conf` is a **template with publicly known passwords**. Replace every
  password (or remove the accounts) before exposing the broker; the broker logs a warning for
  every plaintext `password:` entry.

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
| `admin` | unrestricted (every topic, including `$SYS/#`) |
| `moderator` | readwrite `rooms/%r/#`, readwrite `users/%u/#` |
| `member` | deny `rooms/%r/admin/#`; readwrite `rooms/%r/chat`, `rooms/%r/presence`, `users/%u/private`; read `rooms/%r/announcements` |
| `viewer` | read `rooms/%r/chat`, `rooms/%r/announcements`; deny `rooms/%r/#` |
| `device` | write `devices/%c/telemetry`; read `devices/%c/commands`; deny `#`. The user name must equal the ClientID. |
| none | only the listed rules |

Wildcards in the first level never match topics starting with `$` (MQTT §4.7.2), so `#` does
not grant `$SYS/#`; list it explicitly when needed.

Denied operations: v5.0 clients get reason code 0x87 (Not authorized) in PUBACK / PUBREC /
SUBACK; v3.1.1 clients get SUBACK 0x80, and denied publishes are acknowledged and dropped
(v3.1.1 has no negative acknowledgement). Refused connections: wrong user name or password
CONNACK 0x86 (v3.1.1: 0x04), anonymous access disabled or ClientID not matching the
certificate 0x87 (0x05), a `device` user with another ClientID 0x85 (0x02).

## 6. TLS and PKI

wolfSSL is linked statically. TLS 1.3 is the default; set `min_tls_version = "TLSv1.2"` to also
accept TLS 1.2 clients. TLS 1.0 / 1.1 are not compiled in.

- **Keys:** peer RSA keys shorter than 2048 bits and ECC keys shorter than 256 bits are
  refused.
- **No session resumption, no 0-RTT:** session tickets, PSK and TLS 1.3 early data are compiled
  out. Early data can be replayed by an attacker, which for MQTT would mean replayed CONNECT or
  PUBLISH packets; MQTT connections are long-lived, so a full handshake per connection is cheap.
- **Revocation:** `crl_file` enables CRL checks of client certificates (the certificate itself,
  against the CRL of its issuing CA). OCSP is not supported.

Development PKI:

```bash
bash scripts/generate_certs.sh certs            # CA, server (CN=localhost, SAN localhost/127.0.0.1), client (CN=client01)
CLIENT_CN=sensor-17 bash scripts/generate_certs.sh certs-sensor17
openssl x509 -in certs/server-cert.pem -noout -ext subjectAltName
```

The script also writes `revoked-client-{cert,key}.pem` and `crl.pem`, a CRL that revokes that
certificate, to try `crl_file`. With your own CA, regenerate the CRL after revoking:

```bash
openssl ca -config ca.cnf -revoke client-cert.pem
openssl ca -config ca.cnf -gencrl -out crl.pem     # then restart the broker
```

With `verify_client_identity = true` a client presenting a certificate for `sensor-17` must
connect with ClientID `sensor-17`; otherwise CONNACK 0x87 / 0x05. The identities are the
subject CN and every subject alternative name as reported by wolfSSL (DNS, and also e-mail
and URI entries), compared as text: only issue client certificates whose names you are
prepared to see used as ClientIDs, and never names containing NUL characters.

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
  (v5.0: DISCONNECT 0x8D), and the Will is published. `max_keep_alive_sec` bounds it (see
  above); a v5.0 client that asked for 0 gets Server Keep Alive = `max_keep_alive_sec` and is
  disconnected if it stays silent longer.
- **Sessions:** v3.1.1 `CleanSession = 0` and v5.0 Session Expiry Interval > 0 keep the session
  after disconnect (capped by `max_session_expiry_sec`; v5.0 clients are told the effective
  value). Only such a persistent session can be resumed, only by the same user and only over
  the same protocol family (MQTT and MQTT-SN never resume each other's sessions).
  Reconnecting with `clean_start = 0` resumes it: CONNACK session present = 1, pending PUBREL
  packets are resent, unacknowledged QoS 1/2 messages are resent with DUP and their original
  packet ids — never more at once than the new connection's Receive Maximum allows, and with
  their remaining Message Expiry Interval — then queued messages follow.
- **Takeover:** a new connection with a ClientID in use closes the old connection (v5.0:
  DISCONNECT 0x8E), subject to `client_id_takeover`. The session stays attached to the old
  connection until it has finished, so a third connection cannot slip in between.
- **Will:** published on abnormal close, keep-alive timeout, takeover, or a DISCONNECT with any
  reason code other than 0x00. A v5.0 Will Delay Interval postpones it; resuming the session
  before then cancels it. The Will is published on behalf of its session, so that session's
  own No Local subscriptions do not receive it.
- **QoS:** each subscriber receives `min(publish QoS, granted QoS)`. Outbound packet ids are
  allocated per session and never reused while in flight. At most `max_inflight_messages`
  deliveries (or the client's Receive Maximum, if lower) are unacknowledged at a time. Inbound QoS 2 duplicates (same
  packet id before PUBREL) are acknowledged but not delivered twice.
- **Flow control:** a v5.0 client's Receive Maximum limits unacknowledged QoS 1/2 deliveries;
  its Maximum Packet Size causes larger messages to be skipped for it.
- **Message expiry:** expired messages are not delivered; forwarded messages carry the remaining
  lifetime. A Message Expiry Interval of **0** means the message has expired on arrival (as the
  specification reads): it is never delivered, and as a retained message it is never visible.
  Omit the property for messages that should not expire.
- **Retained messages:** zero-length payload clears; delivered with RETAIN = 1 on subscribe
  (subject to Retain Handling), never to shared subscriptions. Subscribing and taking the
  retained snapshot happen atomically with respect to publishers, so a subscriber never gets a
  stale retained message after a newer live one, nor the same message twice.
- **Shared subscriptions:** `$share/<group>/<filter>`; each message goes to one member,
  round-robin, preferring connected members.
- **Errors:** malformed packets close the connection (v5.0: DISCONNECT 0x81 / 0x82 / 0x95 / …
  with a Reason String before closing). Examples: a property not allowed in the packet type
  (0x81), a Response Topic with wildcards, an empty topic without Topic Alias, Authentication
  Data without Authentication Method (0x82), a QoS 0 message with Payload Format Indicator 1
  and invalid UTF-8 (0x99). UNSUBSCRIBE with an invalid filter gets UNSUBACK 0x8F.
- **Topics:** at most 200 levels; deeper topic names or filters are rejected (SUBACK 0x8F,
  DISCONNECT 0x90 for PUBLISH).
- **Enhanced authentication** (AUTH packets, v5.0 Authentication Method) is not supported:
  CONNACK 0x8C.

## 7a. MQTT over WebSockets

The WebSocket transport follows RFC 6455 and chapter 6 of MQTT v3.1.1 / v5.0. After the HTTP
upgrade the connection is handled exactly like a TCP or TLS connection (same authentication,
ACL, sessions and limits).

- **Upgrade:** `GET <path>` over HTTP/1.1 with `Upgrade: websocket`, `Sec-WebSocket-Version:
  13` (otherwise 426) and a valid `Sec-WebSocket-Key`. The client must offer the subprotocol
  `mqtt` (MQTT-6.0.0-3), which the server selects (MQTT-6.0.0-4); MQTT 3.1's `mqttv3.1` alone is
  refused. The `Sec-WebSocket-Accept` digest is computed with wolfCrypt.
- **Frames:** MQTT is carried in binary frames only; a text frame closes the connection with
  1003 (MQTT-6.0.0-1). MQTT packets may span frames and a frame may hold several packets
  (MQTT-6.0.0-2). Client frames must be masked (1002 otherwise); extensions such as
  `permessage-deflate` are not negotiated (compression of encrypted traffic enables
  CRIME/BREACH-style attacks); pings are answered with pongs.
- **Closing:** a WebSocket Close without an MQTT DISCONNECT is an abnormal end: the Will is
  published, as for a dropped TCP connection.
- **Not supported:** serving web pages, HTTP/2 WebSockets (RFC 8441), the PROXY protocol.

## 8. MQTT-SN gateway

The gateway implements MQTT-SN v1.2 over UDP as an aggregating gateway: SN clients get broker
sessions like MQTT clients, so subscriptions, retained messages and Will messages are shared.

- **Identity:** set `acl_user` to an account (usually without a password) whose rules describe
  what SN devices may do — keep them minimal, every SN client gets them. MQTT-SN has no
  credentials and UDP source addresses can be spoofed: anyone who can reach the port can act
  as `acl_user`, and a spoofed CONNECT + SUBSCRIBE can make the gateway send traffic to a
  third party. Run the gateway only on trusted networks.
- **Connect:** `CONNECT` (optionally with the Will handshake `WILLTOPICREQ` → `WILLTOPIC` →
  `WILLMSGREQ` → `WILLMSG`) → `CONNACK`, always before any `PUBLISH` or `REGISTER` of a resumed
  session. A keep alive above `max_keep_alive_sec` is rejected. A `CONNECT` from the same
  address and ClientID with `CleanSession = 0` re-activates the existing link in place (e.g. a
  sleeping client becoming active); otherwise reconnecting from the same address replaces the
  link. A `PINGREQ` from an unknown address is answered with `DISCONNECT`, telling the client
  to connect again (gateway restart, NAT rebinding).
- **Persistent sessions:** with `CleanSession = 0` the client's topic registrations, Will and
  pending PUBREL are kept with its session and restored when it reconnects, from any address.
- **Topics:** predefined ids from `predefined_topics`, two-character short names, and
  `REGISTER`. When a message arrives for a topic the client has no id for, the gateway sends
  `REGISTER` and publishes only after `REGACK`. A subscription to a topic name returns the
  topic id that later deliveries use; wildcard subscriptions return topic id 0. Per client:
  at most 256 registered topics and 256 subscriptions, topic names up to 512 bytes; beyond
  that the gateway answers with return code 0x01 (congestion).
- **Return codes from the client:** `PUBACK` 0x02 (invalid topic id) makes the gateway forget
  the registration and register the topic again; 0x01 (congestion) on `PUBACK` or `REGACK`
  pauses deliveries for `retry_interval_sec` and retries; other rejections drop the message.
  A `PUBLISH` (also QoS 0) with an unknown topic id is answered with `PUBACK` 0x02.
- **QoS:** −1 (no connection, predefined / short ids only, still authorized against
  `acl_user`), 0, 1 and 2. One QoS 1/2 message is in flight per client and retransmitted every
  `retry_interval_sec` with DUP set, up to `max_retries`, after which the client is lost and its
  Will is published. An unacknowledged message stays in the session and is delivered again
  when a persistent client reconnects.
- **Sleeping clients:** `DISCONNECT` with a duration puts the client to sleep; messages are queued
  in its session (subject to the queue limits) and nothing is retransmitted while it sleeps.
  `PINGREQ` with the ClientID wakes it: an unacknowledged message is resent, queued messages
  are sent, then `PINGRESP`, and the client sleeps again. A sleeping client may publish
  without waking up. No packet within 1.5 × the sleep duration counts as a lost client: the
  link is closed and the Will published; a persistent session (`CleanSession = 0`) is kept for
  `max_session_expiry_sec`.
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
`OUT_DIR` for the selected target, with TLS 1.3 / 1.2, ALPN, SNI, Curve25519, CRL and
hardening enabled, and old TLS versions, DTLS, session tickets, TLS 1.3 early data (0-RTT) and
examples disabled.

**FIPS-Ready:** download the wolfSSL FIPS-Ready bundle, extract it to
`external/wolfssl-fips-bundle/` (or set `WOLFSSL_FIPS_BUNDLE_DIR`), then:

```bash
cargo build --release --no-default-features --features wolfssl-fips
wolf-broker --version     # reports the FIPS-Ready build
```

The bundle is built with wolfSSL's autotools (`--enable-fips=ready`) including the in-core
integrity hash step, which runs wolfCrypt's test program: build FIPS-Ready natively on the
target platform (cross-compilation is not supported for it). FIPS-Ready is not a
CMVP-validated module.

## 12. Benchmarks

Benchmark results are generated by CI (see the release notes and `BENCHMARKS.md` of each
release). Locally:

```bash
task bench                 # codec, trie, retained store and loopback micro-benchmarks
task bench:tls             # MQTT over TLS 1.3 throughput with 8 clients
task bench:tls:compare     # TLS and WebSocket + TLS, side by side with a local Mosquitto if installed
task bench:report          # everything, written to BENCHMARKS.md
```

`wolf-bench-tls` options: `--transport tls|wss` (mutual TLS, or WebSocket + TLS with server
authentication only, as browsers use), `--ws-path <path>`, `--concurrency <n>`,
`--count <messages>`, `--payload-size <bytes>`,
`--external-port <port>` / `--external-name <name>` (benchmark another broker),
`--markdown-output <file>`. Numbers depend heavily on the machine; compare runs from the same
hardware only.
