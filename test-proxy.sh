#!/bin/bash
set -e

echo "Setting up environment variables for AWS CLI proxy configuration..."

# Configure AWS CLI to use our proxy
export HTTP_PROXY=http://localhost:80
export HTTPS_PROXY=https://localhost:443
#export AWS_CA_BUNDLE=./build/aws-proxy.crt
export AWS_MAX_ATTEMPTS=1

echo "Environment variables set:"
echo "HTTP_PROXY=$HTTP_PROXY"
echo "HTTPS_PROXY=$HTTPS_PROXY"
echo "AWS_CA_BUNDLE=$AWS_CA_BUNDLE"


echo "Testing AWS proxy with get-caller-identity..."

# Use the AWS CLI to make a request through our proxy
aws sts get-caller-identity --debug

echo "Test completed!"
