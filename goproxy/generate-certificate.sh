#!/bin/bash
set -e

# Build the Docker image
echo "Building Docker image..."
docker build -t aws-proxy .

# Create a directory for certificates
CERT_DIR="$(pwd)/certs"
mkdir -p "$CERT_DIR"

# Run the container in the background
echo "Generating certificates..."
docker run --entrypoint /app/generate-cert -v "$CERT_DIR:/app/certs" aws-proxy

# Check if certificates exist
if [ -f "$CERT_DIR/aws-proxy.crt" ] && [ -f "$CERT_DIR/aws-proxy.key" ]; then
    echo "Certificates successfully generated and extracted to $CERT_DIR"
    echo "Certificate path: $CERT_DIR/aws-proxy.crt"
    
    # Copy certificate to the test_lambda directory for AWS Lambda
    TEST_LAMBDA_DIR="$(pwd)/../test_lambda"
    if [ -d "$TEST_LAMBDA_DIR" ]; then
        cp "$CERT_DIR/aws-proxy.crt" "$TEST_LAMBDA_DIR/"
        echo "Certificate copied to $TEST_LAMBDA_DIR/aws-proxy.crt"
    fi
else
    echo "Certificate generation failed"
    exit 1
fi
