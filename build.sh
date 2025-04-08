#!/bin/bash
set -e

# Create build directory if it doesn't exist
mkdir -p build

# Generate a self-signed SSL certificate
echo "Generating self-signed SSL certificate..."
openssl req -x509 -newkey rsa:4096 -keyout build/aws-proxy.key -out build/aws-proxy.crt -days 365 -nodes -subj "/CN=aws-proxy" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

# Build Docker image
echo "Building Docker image..."
docker build -t aws-proxy .

echo "Build completed successfully!"
docker stop aws-proxy 
docker rm aws-proxy 
docker run -d -p 80:80 -p 443:443 --name aws-proxy aws-proxy
