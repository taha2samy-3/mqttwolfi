# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.3.x   | :white_check_mark: |

## Reporting a Vulnerability

WolfiMQ takes cryptographic and network security seriously. If you discover a security vulnerability, do NOT file a public issue.

Please report vulnerabilities via **GitHub Security Advisories** or by emailing the maintainers directly.

### Disclosure Guidelines
- Provide detailed steps to reproduce the vulnerability.
- Include candidate PoC (Proof of Concept) packet captures or test cases if applicable.
- Allow maintainers reasonable time to issue a patch before public disclosure.

## Cryptographic Assurance & Licensing Notice
- **wolfSSL Integration**: wolfSSL is distributed under the GNU General Public License v2 (GPLv2) or a commercial license from wolfSSL Inc. When building binary distributions linked with wolfSSL, users and distributors must comply with GPLv2 obligations or hold a commercial license from wolfSSL Inc.
- **TLS 1.3 & mTLS**: Mutual TLS client authentication verifies certificates against the trusted Root CA.
- **FIPS 140-2/3**: When compiled with the `wolfssl-fips` feature flag, the broker operates in FIPS-Ready mode using FIPS-approved cryptographic algorithms. For a formally validated build (CMVP Certificate #4718), a commercially licensed wolfSSL FIPS source bundle is required.
