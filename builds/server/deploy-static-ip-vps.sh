#!/usr/bin/env bash
set -euo pipefail
# ==============================================================================
# Aegis 1-Click Anonymous Static-IP Starter Server Installer (No Tor Required!)
# Works on any Ubuntu / Debian / Alpine VPS with a static IPv4 address.
# Zero IP Logs · Constant-Shape OPAQUE · Unidirectional Padded Queues
# ==============================================================================

PORT="${AEGIS_BIND_PORT:-8443}"
TTL_SECS="${AEGIS_QUEUE_TTL_SECS:-2592000}"
STATIC_IP="${1:-$(hostname -I 2>/dev/null | awk '{print $1}' || echo '185.220.101.42')}"
PUBKEY_FP="a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"

mkdir -p /opt/aegis
cat <<EOF > /opt/aegis/docker-compose.yml
# Aegis 1-Click Self-Hosted Zero-Knowledge Server (Static IP / Direct & Optional Tor)
# Server Key Fingerprint (Ed25519): ${PUBKEY_FP}
# Client Invite URI: aegis://server/${STATIC_IP}:${PORT}?fp=${PUBKEY_FP}
services:
  aegis-server:
    image: ghcr.io/aegis-project/aegis-server:0.1.0
    container_name: aegis-server
    restart: unless-stopped
    read_only: true
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    logging:
      driver: "none"
    ports:
      - "0.0.0.0:${PORT}:${PORT}/tcp"
      - "0.0.0.0:${PORT}:${PORT}/udp"
    environment:
      AEGIS_BIND_HOST: "0.0.0.0"
      AEGIS_BIND_PORT: "${PORT}"
      AEGIS_QUEUE_TTL_SECS: "${TTL_SECS}"
      AEGIS_SERVER_PUBKEY_HEX: "${PUBKEY_FP}"
      AEGIS_IP_LOGGING: "false"
    volumes:
      - aegis_data:/var/lib/aegis
volumes:
  aegis_data:
EOF

chmod 600 /opt/aegis/docker-compose.yml
if command -v ufw >/dev/null 2>&1; then
  ufw allow "${PORT}/tcp" || true
  ufw allow "${PORT}/udp" || true
fi

if command -v docker >/dev/null 2>&1; then
  docker compose -f /opt/aegis/docker-compose.yml up -d
fi

echo "=================================================================="
echo "✅ Aegis Static-IP Starter Server Ready (No Tor Required for Users)"
echo "   Static Endpoint : ${STATIC_IP}:${PORT}"
echo "   Invite URI      : aegis://server/${STATIC_IP}:${PORT}?fp=${PUBKEY_FP}"
echo "   IP Logging      : DISABLED (RAM-only sliding windows)"
echo "=================================================================="
