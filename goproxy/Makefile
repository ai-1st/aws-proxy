# AWS Proxy Makefile
.PHONY: all build generate-cert custom-cert run lambda-layer clean clean-all test help

# Output directories
BUILD_DIR = build
CERTS_DIR = certs
KEYS_DIR = keys

# Go build flags
GO_BUILD_FLAGS = -ldflags="-s -w"

# Binary names
PROXY_BIN = $(BUILD_DIR)/aws-proxy
CERT_GEN_BIN = $(BUILD_DIR)/generate-cert

# Default target
all: build

# Create necessary directories
dirs:
	mkdir -p $(BUILD_DIR)
	mkdir -p $(CERTS_DIR)
	mkdir -p $(KEYS_DIR)

# Build the main proxy binary
build: dirs
	@echo "Building AWS Proxy..."
	go build $(GO_BUILD_FLAGS) -o $(PROXY_BIN) ./cmd/aws-proxy
	@echo "AWS Proxy built successfully at $(PROXY_BIN)"
	@echo "Building certificate generator..."
	go build $(GO_BUILD_FLAGS) -o $(CERT_GEN_BIN) ./cmd/generate-cert
	@echo "Certificate generator built successfully at $(CERT_GEN_BIN)"

# Generate certificates with default settings
generate-cert: build-generate-cert dirs
	@echo "Generating certificates..."
	$(CERT_GEN_BIN) --cert=$(CERTS_DIR)/aws-proxy.crt --key=$(KEYS_DIR)/aws-proxy.key

# Generate certificates with custom settings (usage: make custom-cert IPS=1.2.3.4,5.6.7.8 DNS=example.com,proxy.local)
custom-cert: build-generate-cert dirs
	@echo "Generating certificates with custom settings..."
	$(CERT_GEN_BIN) --cert=$(CERTS_DIR)/aws-proxy.crt --key=$(KEYS_DIR)/aws-proxy.key \
		$(if $(IPS),--ips=$(IPS)) \
		$(if $(DNS),--dns=$(DNS))

# Run the proxy (will build if necessary)
run: build
	@echo "Running AWS Proxy..."
	$(PROXY_BIN) $(ARGS)

# Create and publish Lambda layer
lambda-layer:
	@echo "Creating and publishing Lambda layer..."
	./lambda-layer.sh

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	@echo "Cleaned."

# Deep clean (build artifacts and certificates)
clean-all: clean
	@echo "Cleaning certificates..."
	rm -rf $(CERTS_DIR)
	rm -rf $(KEYS_DIR)
	@echo "All cleaned."

# Run tests
test:
	@echo "Running tests..."
	go test -v ./...

# Show help
help:
	@echo "AWS Proxy Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  all              Build everything (default)"
	@echo "  build            Build the AWS Proxy binary and the certificate generator"
	@echo "  generate-cert    Generate certificates with default settings"
	@echo "  custom-cert      Generate certificates with custom settings"
	@echo "                   Usage: make custom-cert IPS=1.2.3.4,5.6.7.8 DNS=example.com,proxy.local"
	@echo "  run              Run the AWS Proxy (builds if necessary)"
	@echo "                   Usage: make run ARGS=\"--permissive=false --allowed-accounts=123456789012\""
	@echo "  lambda-layer     Create and publish Lambda layer"
	@echo "  clean            Remove build artifacts"
	@echo "  clean-all        Remove build artifacts and certificates"
	@echo "  test             Run tests"
	@echo "  help             Show this help message"
