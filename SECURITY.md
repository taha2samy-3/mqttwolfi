# Security Policy

## Supported versions

| Version | Supported |
| :--- | :---: |
| 0.5.x | ✅ |
| < 0.5 | ❌ (contains known protocol and authorization defects, see `CHANGELOG.md`) |

## Reporting a vulnerability

Please do **not** open a public issue. Report vulnerabilities privately through
**GitHub Security Advisories** ("Report a vulnerability" on the repository's Security tab).

Include the affected version, configuration, reproduction steps and, if possible, a packet
capture or test case. We aim to acknowledge reports within a few days and will coordinate a
disclosure date with you once a fix is available.

## Security model in brief

- **Transport**: plain TCP is intended for loopback / trusted networks only. Use the wolfSSL TLS
  listener (TLS 1.3 by default, optional mutual TLS) for anything else. MQTT-SN runs over plain
  UDP: it has no encryption and its sessions are identified by source address, which can be
  spoofed. Only expose it on trusted radio / sensor networks.
- **Authentication**: user names and passwords from the ACL file, stored as Argon2id PHC
  strings (`wolf-broker --hash-password`). Legacy unsalted SHA-256 hashes are accepted for
  compatibility but not recommended. Unknown users cost the same verification time as known
  ones, and concurrent verifications are bounded (`security.auth.max_concurrent_auth`).
- **Authorization**: first-match ACL rules with `%u` / `%c` / `%r` substitution (values that
  could inject wildcards or levels never match). Subscriptions must be fully covered by an allow
  rule. Will topics are authorized like publishes. With `verify_client_identity`, the MQTT
  ClientID must match the client certificate's CN or a SAN.
- **Resource limits**: packet size, connection count, per-session queue size and bytes, retained
  store size, MQTT-SN session count, CONNECT deadline and TLS handshake timeout are all bounded
  by configuration.

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
