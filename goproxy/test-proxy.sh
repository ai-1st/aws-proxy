#!/bin/bash

# Test script for the Go-based AWS proxy implementation

# Function to clean up
cleanup() {
    echo "Stopping AWS proxy..."
    kill $PROXY_PID
    unset HTTP_PROXY
    unset HTTPS_PROXY
    unset AWS_CA_BUNDLE
    unset AWS_CLI_AUTO_PROMPT
    unset AWS_ACCESS_KEY_ID
    unset AWS_SECRET_ACCESS_KEY
    unset AWS_SESSION_TOKEN
    exit
}

# Set up trap to clean up on exit
trap cleanup INT TERM EXIT

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
./aws-proxy --addr=:8080 --permissive=false --allowed-accounts=$ALLOWED_ACCOUNTS --verbose=true --cert="$CERT_FILE" --key="$KEY_FILE" > aws-proxy.log 2>&1 &
PROXY_PID=$!

# Wait for the proxy to start
sleep 1

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

use_proxy() {
    local use_proxy=$1
    if [ "$use_proxy" = true ]; then
        export HTTP_PROXY=http://localhost:8080
        export HTTPS_PROXY=http://localhost:8080
        export AWS_CA_BUNDLE=$CERT_FILE
    else
        unset HTTP_PROXY
        unset HTTPS_PROXY
        unset AWS_CA_BUNDLE
    fi
}
# Function to assume a role and export the credentials
assume_role() {
    local role_arn=$1
    local external_id=$2
    
    echo "Running: aws sts assume-role for $role_arn" 
    # Add external ID if provided
    if [ -n "$external_id" ]; then
        source_role_credentials=$(aws sts assume-role --role-arn "$role_arn" --role-session-name "Test" --external-id "$external_id")
    else
        source_role_credentials=$(aws sts assume-role --role-arn "$role_arn" --role-session-name "Test")
    fi
    
    # Add external ID if provided
    if [ -n "$external_id" ]; then
        source_role_credentials=$(aws sts assume-role --role-arn "$role_arn" --role-session-name "Test" --external-id "$external_id")
    else
        source_role_credentials=$(aws sts assume-role --role-arn "$role_arn" --role-session-name "Test")
    fi
    
    # Extract and export credentials
    export AWS_ACCESS_KEY_ID=$(echo $source_role_credentials | jq -r '.Credentials.AccessKeyId')
    export AWS_SECRET_ACCESS_KEY=$(echo $source_role_credentials | jq -r '.Credentials.SecretAccessKey')
    export AWS_SESSION_TOKEN=$(echo $source_role_credentials | jq -r '.Credentials.SessionToken')
}

echo "Proxied: aws sts get-caller-identity"
use_proxy true
aws sts get-caller-identity
assume_role "$TEST_ASSUME_ROLE"

echo "Running: aws sts assume-role with new credentials but not through proxy"
use_proxy false
assume_role "$TEST_ASSUME_ROLE2" "$TEST_EXTERNAL_ID" false

echo "Proxy should block this request"
use_proxy true
aws sts get-caller-identity

echo "Now correctly assume all roles throught proxy"
use_proxy true
unset AWS_ACCESS_KEY_ID
unset AWS_SECRET_ACCESS_KEY
unset AWS_SESSION_TOKEN
assume_role "$TEST_ASSUME_ROLE"
assume_role "$TEST_ASSUME_ROLE2" "$TEST_EXTERNAL_ID" true
aws sts get-caller-identity

echo "Proxy logs"
# cat aws-proxy.log

kill $PROXY_PID
