#!/bin/sh
set -e

mkdir -p /app/config

echo "$FLEET_KEY" > /app/config/fleet-key.pem
echo "$TLS_CERT" > /app/config/tls-cert.pem
echo "$TLS_KEY" > /app/config/tls-key.pem

chmod 600 /app/config/*

exec tesla-http-proxy \
    -key-file /app/config/fleet-key.pem \
    -cert /app/config/tls-cert.pem \
    -tls-key /app/config/tls-key.pem \
    -host 0.0.0.0 \
    -port 443
