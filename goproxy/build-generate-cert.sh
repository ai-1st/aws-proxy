#!/bin/bash
set -e

# Build the certificate generator
echo "Building certificate generator..."
go build -o build/generate-cert ./cmd/generate-cert

echo "Certificate generator built successfully"
echo "You can now generate certificates using:"
echo "./build/generate-cert --ips=127.0.0.1,::1 --dns=localhost,aws-proxy"
