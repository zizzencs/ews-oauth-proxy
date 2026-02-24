#!/bin/bash
# Generate a self-signed TLS certificate for ews-oauth-proxy

mkdir -p certs

FQDN=${1:-"localhost"}
IP=${2:-"127.0.0.1"}

SAN="DNS:localhost,IP:127.0.0.1"

if [ "$FQDN" != "localhost" ]; then
    SAN="$SAN,DNS:$FQDN"
fi

if [ "$IP" != "127.0.0.1" ]; then
    SAN="$SAN,IP:$IP"
fi

echo "Generating self-signed certificate for CN: $FQDN"
echo "Subject Alternate Names: $SAN"

openssl req -x509 -newkey rsa:4096 \
    -keyout certs/key.pem \
    -out certs/cert.pem \
    -sha256 -days 3650 -nodes \
    -subj "/CN=$FQDN" \
    -addext "subjectAltName=$SAN" 2>/dev/null

echo "Success! key.pem and cert.pem generated in the 'certs/' directory."
