#!/bin/bash
set -e

# Configuration
FUNCTION_NAME="rds-scanner"
PAYLOAD_FILE="env/payload.json"

# Check if payload file exists
if [ ! -f "$PAYLOAD_FILE" ]; then
    echo "Error: $PAYLOAD_FILE not found"
    echo "Please run assume_roles.sh first to generate the payload"
    exit 1
fi

# Invoke the Lambda function
echo "Invoking $FUNCTION_NAME..."
aws lambda invoke \
    --function-name "$FUNCTION_NAME" \
    --payload file://"$PAYLOAD_FILE" \
    --cli-binary-format raw-in-base64-out \
    env/output.json

# Check if the invocation was successful
if [ $? -eq 0 ]; then
    echo "Lambda invocation successful"
    echo "Output saved to output.json"
    cat output.json
else
    echo "Lambda invocation failed"
    exit 1
fi