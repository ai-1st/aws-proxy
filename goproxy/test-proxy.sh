#!/bin/bash

# Test script for the Go-based AWS proxy implementation

# Build the proxy
echo "Building AWS proxy..."
cd "$(dirname "$0")"
go build -o build/aws-proxy ./cmd/aws-proxy

# Define certificate paths
CERT_FILE="aws-proxy.crt"
KEY_FILE="aws-proxy.key"
ABSOLUTE_CERT_PATH="$(pwd)/$CERT_FILE"

# Start the proxy in the background with output to a log file
echo "Starting AWS proxy on port 8080..."
cd build
./aws-proxy --addr=:8080 --permissive=true --verbose=true --cert="$CERT_FILE" --key="$KEY_FILE" > aws-proxy.log 2>&1 &
PROXY_PID=$!

# Wait for the proxy to start
sleep 3

# Check if certificate file exists
if [ -f "$CERT_FILE" ]; then
    echo "Using certificate file: $ABSOLUTE_CERT_PATH"
else
    echo "Certificate file not found at: $ABSOLUTE_CERT_PATH"
    echo "Checking log for certificate location..."
    # Find the CA certificate file from logs as fallback
    CERT_FILE=$(grep -m 1 "CA certificate saved to:" /tmp/aws-proxy.log 2>/dev/null | awk '{print $NF}' || echo "$CERT_FILE")
    echo "Using certificate from log: $CERT_FILE"
fi

# Set up environment variables for AWS CLI
export HTTP_PROXY=http://localhost:8080
export HTTPS_PROXY=http://localhost:8080
export AWS_CA_BUNDLE=$CERT_FILE
export AWS_CLI_AUTO_PROMPT=on-partial

# Function to clean up
cleanup() {
    echo "Stopping AWS proxy..."
    kill $PROXY_PID
    unset HTTP_PROXY
    unset HTTPS_PROXY
    unset AWS_CA_BUNDLE
    unset AWS_CLI_AUTO_PROMPT
    exit
}

# Set up trap to clean up on exit
trap cleanup INT TERM EXIT

echo
echo "Testing with AWS CLI twice..."
echo "Running: aws sts get-caller-identity"
aws sts get-caller-identity
echo "Running: aws sts get-caller-identity (second call)"
aws sts get-caller-identity
echo "Running: aws sts assume-role"
aws sts assume-role --role-arn $TEST_ASSUME_ROLE --role-session-name Test

echo
echo "Proxy logs"
cat aws-proxy.log

kill $PROXY_PID
