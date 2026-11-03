#!/usr/bin/env bash
set -euo pipefail

# Starts aegis-serverd in Docker on a Linux host. The server speaks plain HTTP;
# put a TLS reverse proxy in front of it for public use.

PORT="${1:-8443}"

umask 077
mkdir -p /opt/aegis
cat > /opt/aegis/docker-compose.yml <<COMPOSE
services:
  aegis-server:
    image: ghcr.io/aegis-project/aegis-server:0.2.0
    container_name: aegis-server
    restart: unless-stopped
    read_only: true
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    logging:
      driver: "none"
    command: ["--bind", "0.0.0.0", "--port", "${PORT}", "--data-dir", "/var/lib/aegis"]
    ports:
      - "${PORT}:${PORT}/tcp"
    volumes:
      - aegis_data:/var/lib/aegis
volumes:
  aegis_data:
COMPOSE

if command -v docker >/dev/null 2>&1; then
  docker compose -f /opt/aegis/docker-compose.yml up -d
else
  echo "docker is not installed; compose file written to /opt/aegis/docker-compose.yml" >&2
fi

echo "aegis-serverd is configured on tcp/${PORT}"
