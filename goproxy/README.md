# AWS Proxy (Go Implementation)

A Go-based implementation of the AWS proxy using the goproxy library for MITM interception of AWS API calls.

## Features

- Intercepts and inspects AWS API calls
- Logs request and response details
- Permissive mode (allows all requests but logs details)
- Support for TLS interception with custom certificates
- Caching capability for responses (configurable)

## Requirements

- Go 1.16 or higher

## Building

```bash
# Build the binary
cd goproxy
go build -o ./build/aws-proxy ./cmd/aws-proxy
```

## Running

```bash
# Run with default settings (permissive mode, caching enabled)
cd build
./aws-proxy

# Run with custom options
./aws-proxy --addr=:8081 --permissive=true --verbose=true
```

## Command Line Options

- `--addr`: Proxy listen address (default: ":8080")
- `--verbose`: Enable verbose logging (default: true)
- `--cert`: Path to TLS certificate file (optional)
- `--key`: Path to TLS key file (optional)
- `--permissive`: Allow all requests regardless of IAM role (default: true)
- `--cache`: Enable response caching (default: true)

## Docker

Build and run using Docker:

```bash
# Build the Docker image
cd goproxy
docker build -t aws-proxy .

# Run the container
docker run -p 8080:8080 aws-proxy
```

## Setting Up Clients

To use the proxy with AWS clients, set the following environment variables:

```bash
export HTTP_PROXY=http://localhost:8080
export HTTPS_PROXY=http://localhost:8080
```

For proper TLS interception, clients need to trust the proxy's CA certificate.

## Architecture

The proxy consists of several components:

1. **Proxy Server**: Handles HTTP/HTTPS connections and MITM interception
2. **Certificate Manager**: Manages TLS certificates for MITM
3. **Policy Engine**: Validates IAM roles (in permissive mode, allows everything)
4. **Cache Manager**: Caches responses for improved performance

## Current Implementation

This is a permissive implementation that allows all requests but logs what is happening. It:

- Logs all AWS API requests and responses
- Identifies AWS-specific headers and SigV4 signatures
- Detects STS and GetCallerIdentity calls
- Provides infrastructure for future role-based access control

## Future Enhancements

- Parse SigV4 signatures to extract Access Key IDs
- Implement role-based access control
- Parse STS responses to extract assumed role information
- Implement more sophisticated caching rules
- Add metrics and monitoring
