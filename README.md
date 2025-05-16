# AWS Proxy (Go Implementation)

A Go-based implementation of the AWS proxy using the goproxy library for MITM interception of AWS API calls.

## Features

- Intercepts and inspects AWS API calls
- Logs request and response details
- Permissive mode (allows all requests but logs details)
- Support for TLS interception with custom certificates
- Account-based access control
- STS AssumeRole request monitoring

## Requirements

- Go 1.16 or higher
- make
- zip
- aws cli 

## Building

```bash
# Build the binary
cd goproxy
go build -o ./build/aws-proxy ./cmd/aws-proxy
```

## Running

```bash
# Run with default settings (permissive mode)
cd build
./aws-proxy

# Run with custom options
./aws-proxy --addr=:8081 --permissive=true --verbose=true --allowed-accounts=123456789012,987654321098
```

## Command Line Options

- `--addr`: Proxy listen address (default: ":8080")
- `--verbose`: Enable verbose logging (default: true)
- `--cert`: Path to TLS certificate file (default: aws-proxy.crt in current directory)
- `--key`: Path to TLS key file (default: aws-proxy.key in current directory)
- `--permissive`: Allow all requests regardless of IAM role (default: true)
- `--allowed-accounts`: Comma-separated list of allowed AWS account IDs

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
export AWS_CA_BUNDLE=/path/to/aws-proxy.crt  # Path to the proxy's CA certificate
```

For proper TLS interception, clients need to trust the proxy's CA certificate. The proxy will output the path to its CA certificate on startup.

## Architecture

The proxy consists of several components:

1. **Proxy Server**: Handles HTTP/HTTPS connections and MITM interception
2. **Certificate Manager**: Manages TLS certificates for MITM, including dynamic certificate generation
3. **Policy Engine**: Controls access based on AWS account IDs and monitors STS AssumeRole calls
4. **TLS Interceptor**: Handles HTTPS connection interception with custom certificates

## Current Implementation

This implementation provides:

- Full TLS interception with custom certificate authority
- Account-based access control via allowed account list
- Monitoring of STS AssumeRole requests and responses
- XML-formatted error responses for denied requests
- Automatic certificate generation for intercepted hosts
- Proper handling of AWS request signatures

## Future Enhancements

- Parse SigV4 signatures to extract Access Key IDs
- Implement more granular role-based access control
- Parse STS responses to extract assumed role information
- Add metrics and monitoring
- Support for AWS service-specific policies
