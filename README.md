# AWS Proxy

An asynchronous proxy server for AWS API requests with SSL termination, request/response logging, and certificate management.

## Description

AWS Proxy is a MITM (Man-In-The-Middle) proxy server that intercepts and logs AWS API requests and responses. It provides:

- SSL termination and inspection of HTTPS traffic
- Detailed logging of request and response headers and bodies
- Support for AWS API authentication and authorization
- Certificate management for secure connections

## Installation

```bash
# Install dependencies
poetry install

# Generate certificates (first run will do this automatically)
# Certificates are stored in ~/.aws-proxy/certs/
```

## Certificate Setup

For HTTPS inspection to work properly, you need to trust the CA certificate:

1. The certificate is automatically generated at `~/.aws-proxy/certs/mitm.pem`
2. Add this certificate to your system's trusted certificate store:

   **macOS**:
   ```bash
   sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/.aws-proxy/certs/mitm.pem
   ```

   **Linux**:
   ```bash
   # Debian/Ubuntu
   sudo cp ~/.aws-proxy/certs/mitm.pem /usr/local/share/ca-certificates/aws-proxy-ca.crt
   sudo update-ca-certificates
   ```

## Usage

### Starting the Proxy Server

```bash
# Start the proxy server
poetry run aws-proxy

# Or with custom host/port
poetry run aws-proxy --host 127.0.0.1 --port 8080
```

### Testing with curl

```bash
# Test with curl
curl -x http://127.0.0.1:8080 https://example.com

# Or use the test script
./test.sh
```

### Testing AWS API Calls

```bash
# Test basic AWS operations
poetry run python tests/test_aws_calls.py

# Test with a specific IAM role
poetry run python tests/test_aws_calls.py --role-arn "arn:aws:iam::ACCOUNT_ID:role/ROLE_NAME"

# Skip specific tests
poetry run python tests/test_aws_calls.py --skip-s3 --skip-sts
```

### AWS SDK Configuration

To configure AWS SDKs to use the proxy:

**Python (boto3)**:
```python
import boto3
from botocore.config import Config

proxy_config = Config(
    proxies={
        'http': 'http://127.0.0.1:8080',
        'https': 'http://127.0.0.1:8080',
    }
)

# Use the CA certificate for verification
s3 = boto3.client('s3', config=proxy_config, verify='~/.aws-proxy/certs/mitm.pem')
```

**AWS CLI**:
```bash
# Set environment variables
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
export AWS_CA_BUNDLE=~/.aws-proxy/certs/mitm.pem

# Run AWS CLI commands
aws s3 ls
```

## Logs

The proxy server logs all requests and responses to the console. You can redirect logs to files:

```bash
# Log proxy output to a file
poetry run aws-proxy > proxy_log.txt 2>&1
```

## Architecture

- **main.py**: Core proxy server implementation using the MITM package
- **middleware.py**: Request/response interceptor and logger
- **http.py**: HTTP parsing utilities
- **tests/**: Test scripts for validating proxy functionality

## License

MIT