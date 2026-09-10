#!/usr/bin/env bash
# Generate self-signed TLS certificate for n8n (and later Dagobert)
# Usage: bash generate-cert.sh <VM_IP>
# Example: bash generate-cert.sh 192.168.1.100

set -euo pipefail

IP="${1:-}"
if [[ -z "$IP" ]]; then
  echo "Usage: bash generate-cert.sh <VM_IP>"
  exit 1
fi

CERT_DIR="$(dirname "$0")/certs"
mkdir -p "$CERT_DIR"

openssl req -x509 -nodes -newkey rsa:4096 \
  -keyout "$CERT_DIR/server.key" \
  -out    "$CERT_DIR/server.crt" \
  -days   3650 \
  -subj   "/CN=${IP}/O=SOC/C=UA" \
  -addext "subjectAltName=IP:${IP}"

chmod 600 "$CERT_DIR/server.key"
chmod 644 "$CERT_DIR/server.crt"

echo ""
echo "Certificate generated in ./certs/"
echo "  server.crt  (публічний сертифікат)"
echo "  server.key  (приватний ключ)"
echo ""
echo "Next: docker compose up -d"
echo "Access: https://${IP}:5678"
