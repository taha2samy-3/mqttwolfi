#!/usr/bin/env bash
# Generates a throw-away test PKI (CA, server and client certificates) for TLS / mTLS.
# Usage: scripts/generate_certs.sh [output-dir]   (default: certs)
# NOT for production use: keys are unencrypted and the CA is self-signed.
set -euo pipefail

CERTS_DIR="${1:-certs}"
CLIENT_CN="${CLIENT_CN:-client01}"
mkdir -p "${CERTS_DIR}"

echo "==> Generating test PKI in ${CERTS_DIR}/"

# 1. Root certificate authority
openssl req -x509 -newkey rsa:2048 -nodes -keyout "${CERTS_DIR}/ca-key.pem" \
    -out "${CERTS_DIR}/ca-cert.pem" -days 3650 \
    -subj "/C=US/ST=CA/O=WolfiMQ Test Authority/CN=WolfiMQ Test Root CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

# 2. Server certificate with subject alternative names
openssl req -newkey rsa:2048 -nodes -keyout "${CERTS_DIR}/server-key.pem" \
    -out "${CERTS_DIR}/server-req.pem" \
    -subj "/C=US/ST=CA/O=WolfiMQ Broker/CN=localhost" 2>/dev/null
openssl x509 -req -in "${CERTS_DIR}/server-req.pem" \
    -CA "${CERTS_DIR}/ca-cert.pem" -CAkey "${CERTS_DIR}/ca-key.pem" -CAcreateserial \
    -out "${CERTS_DIR}/server-cert.pem" -days 825 \
    -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth") 2>/dev/null

# 3. Client certificate for mutual TLS (CN and SAN carry the MQTT ClientID)
openssl req -newkey rsa:2048 -nodes -keyout "${CERTS_DIR}/client-key.pem" \
    -out "${CERTS_DIR}/client-req.pem" \
    -subj "/C=US/ST=CA/O=WolfiMQ Client Device/CN=${CLIENT_CN}" 2>/dev/null
openssl x509 -req -in "${CERTS_DIR}/client-req.pem" \
    -CA "${CERTS_DIR}/ca-cert.pem" -CAkey "${CERTS_DIR}/ca-key.pem" -CAcreateserial \
    -out "${CERTS_DIR}/client-cert.pem" -days 825 \
    -extfile <(printf "subjectAltName=DNS:${CLIENT_CN}\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth") 2>/dev/null

rm -f "${CERTS_DIR}"/*-req.pem "${CERTS_DIR}"/*.srl
echo "==> Done: ca-cert.pem, server-{cert,key}.pem, client-{cert,key}.pem"
