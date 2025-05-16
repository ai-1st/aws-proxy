#!/bin/bash
set -e

# Configuration
LAYER_NAME="aws-proxy-cert"
LAYER_DESC="AWS Proxy CA certificate for HTTPS interception"
REGIONS=(
    "us-east-1"
    # "us-east-2"
    # "us-west-1"
    # "us-west-2"
)

# Check if aws-proxy.crt exists
if [ ! -f "certs/aws-proxy.crt" ]; then
    echo "Error: certs/aws-proxy.crt not found"
    echo "Please run the proxy first to generate the certificate"
    exit 1
fi

# Check system certificates exists
if [ ! -f "/etc/ssl/certs/ca-certificates.crt" ]; then
    echo "Error: /etc/ssl/certs/ca-certificates.crt not found"
    exit 1
fi

# Create the layer zip file
mkdir temp
cd temp
mkdir certs
cat /etc/ssl/certs/ca-certificates.crt ../certs/aws-proxy.crt > certs/ca-bundle.crt
zip -r aws-proxy-cert-layer.zip certs/
# Publish the layer to each region
for region in "${REGIONS[@]}"; do
    echo "Publishing layer to $region..."
    
    # Create a new layer version
    VERSION=$(aws lambda publish-layer-version \
        --layer-name "$LAYER_NAME" \
        --description "$LAYER_DESC" \
        --license-info "MIT" \
        --zip-file "fileb://aws-proxy-cert-layer.zip" \
        --compatible-runtimes nodejs20.x python3.9 python3.10 python3.11 python3.12 python3.13 java11 java17 java21 provided.al2 provided.al2023 \
        --compatible-architectures x86_64 arm64 \
        --region "$region" \
        --query 'Version' \
        --output text)
    
    # Make the layer public
    aws lambda add-layer-version-permission \
        --layer-name "$LAYER_NAME" \
        --version-number "$VERSION" \
        --statement-id public \
        --action lambda:GetLayerVersion \
        --principal "*" \
        --region "$region"
    
    echo "Layer version $VERSION published in $region"
    echo "ARN: arn:aws:lambda:$region:\$(aws sts get-caller-identity --query Account --output text):layer:$LAYER_NAME:$VERSION"
done

# Clean up
cd ..
rm -rf temp/

echo "Layer creation complete"
