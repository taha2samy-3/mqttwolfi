# Security Policy

## Supported versions

| Version | Supported |
| :--- | :---: |
| 0.6.x | ✅ |
| 0.5.x | ❌ (a crafted SUBSCRIBE can crash the broker, ACL macro injection; upgrade) |
| < 0.5 | ❌ (contains known protocol and authorization defects, see `CHANGELOG.md`) |

## Reporting a vulnerability

Please do **not** open a public issue. Report vulnerabilities privately through
**GitHub Security Advisories** ("Report a vulnerability" on the repository's Security tab).

Include the affected version, configuration, reproduction steps and, if possible, a packet
capture or test case. We aim to acknowledge reports within a few days and will coordinate a
disclosure date with you once a fix is available.

## Security model in brief

- **Transport**: plain TCP is intended for loopback / trusted networks only. Use the wolfSSL TLS
  listener (TLS 1.3 by default, optional mutual TLS, CRL-based revocation of client
  certificates, RSA ≥ 2048 / ECC ≥ 256 bits, no session resumption or 0-RTT) for anything else.
- **MQTT-SN** runs over plain UDP with no authentication and no encryption; clients are
  identified by a source address that can be spoofed, and every SN client acts with the
  rights of the configured `acl_user`. It is disabled in the sample configuration; only expose
  it on trusted radio / sensor networks, give `acl_user` minimal rights and keep
  `allow_qos_minus1` off unless needed.
- **Authentication**: user names and passwords from the ACL file, stored as Argon2id PHC
  strings (`wolf-broker --hash-password`). Legacy unsalted SHA-256 hashes are accepted for
  compatibility but not recommended. Unknown users, password-less and legacy accounts all cost
  at least one default Argon2id verification, so response times do not reveal which user names
  exist (accounts hashed with non-default Argon2 parameters take their own time). Concurrent
  verifications are bounded (`security.auth.max_concurrent_auth`) and waiting for one counts
  against the CONNECT deadline. There is no lock-out or rate limit for failed logins: limit
  exposure with mutual TLS or a firewall.
- **Authorization**: first-match ACL rules with `%u` / `%c` / `%r` substitution in one pass. A
  user name or ClientID that could inject wildcards, levels or another macro is never
  substituted: allow rules using it do not match and deny rules using it match everything.
  Subscriptions must be fully covered by an allow rule; read access is re-checked at delivery.
  Will topics are authorized like publishes. With `verify_client_identity`, the MQTT ClientID
  must match the client certificate's CN or a subject alternative name, and connections
  without a client certificate are refused.
- **Sessions**: a session is only resumed by the user that created it. A connected ClientID
  cannot be taken over by another user (with the default `client_id_takeover = "same_user"`);
  an offline session of another user is replaced, so nobody can lock an account out of its
  ClientID.
- **Resource limits**: packet size (CONNECT: 256 KiB before authentication), topic depth (200
  levels), connections, sessions, subscriptions per session, per-session queue size and bytes
  (properties included), inflight window, retained store size and bytes, MQTT-SN sessions,
  topic registrations and keep alive, CONNECT + authentication deadline and TLS handshake
  timeout are all bounded by configuration or fixed limits.
- **Shipped templates**: `config/acl.conf` contains example accounts with publicly known
  plaintext passwords. Replace them before exposing the broker.

## Cryptography and licensing notice

- **wolfSSL** is linked statically. The pinned wolfSSL release (5.9.4) is licensed under the
  **GNU GPL v3** (or a commercial license from wolfSSL Inc.). WolfiMQ's own source code is
  MIT / Apache-2.0, but binaries that include wolfSSL — including the published release
  archives — are subject to GPLv3 terms unless you hold a commercial wolfSSL license. The
  license texts are shipped in `third-party/wolfssl/` inside every release archive.
- **FIPS**: the `wolfssl-fips` feature builds against a wolfSSL **FIPS-Ready** bundle
  (FIPS-approved algorithms only). FIPS-Ready is **not** a CMVP-validated module. A validated
  deployment requires wolfSSL's commercially licensed FIPS package and its operational
  guidance.
