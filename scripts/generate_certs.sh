#!/usr/bin/env bash
set -euo pipefail

CERTS_DIR="certs"
mkdir -p "${CERTS_DIR}"

echo "==> Generating PKI test certificates for mTLS verification with SAN..."

# 1. Root Certificate Authority (CA)
openssl req -x509 -newkey rsa:2048 -nodes -keyout "${CERTS_DIR}/ca-key.pem" \
    -out "${CERTS_DIR}/ca-cert.pem" -days 3650 \
    -subj "/C=US/ST=CA/O=WolfMQTT Test Authority/CN=RootCA"

# 2. Broker Server Certificate & Private Key with Subject Alternative Name (SAN)
openssl req -newkey rsa:2048 -nodes -keyout "${CERTS_DIR}/server-key.pem" \
    -out "${CERTS_DIR}/server-req.pem" \
    -subj "/C=US/ST=CA/O=WolfMQTT Broker/CN=localhost"

openssl x509 -req -in "${CERTS_DIR}/server-req.pem" \
    -CA "${CERTS_DIR}/ca-cert.pem" -CAkey "${CERTS_DIR}/ca-key.pem" -CAcreateserial \
    -out "${CERTS_DIR}/server-cert.pem" -days 365 \
    -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth")

# 3. Client Certificate & Private Key for mTLS
openssl req -newkey rsa:2048 -nodes -keyout "${CERTS_DIR}/client-key.pem" \
    -out "${CERTS_DIR}/client-req.pem" \
    -subj "/C=US/ST=CA/O=WolfMQTT Client Device/CN=client01"

openssl x509 -req -in "${CERTS_DIR}/client-req.pem" \
    -CA "${CERTS_DIR}/ca-cert.pem" -CAkey "${CERTS_DIR}/ca-key.pem" -CAcreateserial \
    -out "${CERTS_DIR}/client-cert.pem" -days 365 \
    -extfile <(printf "extendedKeyUsage=clientAuth")

rm -f "${CERTS_DIR}"/*-req.pem "${CERTS_DIR}"/*.srl

echo "==> Test certificates successfully generated with SAN in ${CERTS_DIR}/"
