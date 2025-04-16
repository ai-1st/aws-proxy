#!/bin/bash
set -e

# Configuration
LAYER_NAME="aws-proxy-cert"
LAYER_DESC="AWS Proxy CA certificate for HTTPS interception"
REGIONS=(
    "us-east-1"
    "us-east-2"
    "us-west-1"
    "us-west-2"
)

# Check if aws-proxy.crt exists
if [ ! -f "build/aws-proxy.crt" ]; then
    echo "Error: build/aws-proxy.crt not found"
    echo "Please run the proxy first to generate the certificate"
    exit 1
fi

# Create a temporary directory for the layer
TEMP_DIR=$(mktemp -d)
mkdir -p "$TEMP_DIR/opt"

# Copy the certificate to the layer directory
cp build/aws-proxy.crt "$TEMP_DIR/opt/"

# Create the layer zip file
cd "$TEMP_DIR"
zip -r ../aws-proxy-cert-layer.zip .
cd - > /dev/null

# Publish the layer to each region
for region in "${REGIONS[@]}"; do
    echo "Publishing layer to $region..."
    VERSION=$(aws lambda publish-layer-version \
        --layer-name "$LAYER_NAME" \
        --description "$LAYER_DESC" \
        --license-info "MIT" \
        --zip-file "fileb://$TEMP_DIR/../aws-proxy-cert-layer.zip" \
        --compatible-runtimes provided provided.al2 nodejs python java ruby dotnet go1.x \
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
rm -rf "$TEMP_DIR"
rm "$TEMP_DIR/../aws-proxy-cert-layer.zip"

echo "Layer creation complete"
