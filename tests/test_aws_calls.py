import boto3
from botocore.config import Config
import os
import argparse

# Proxy configuration
PROXY_HOST = os.environ.get("PROXY_HOST", "127.0.0.1")
PROXY_PORT = os.environ.get("PROXY_PORT", "8080")
PROXY_URL = f"http://{PROXY_HOST}:{PROXY_PORT}"

# CA Certificate configuration
CA_CERT_PATH = os.path.expanduser("~/.aws-proxy/certs/mitm.pem")

# Suppress warnings if needed
# warnings.filterwarnings("ignore", category=InsecureRequestWarning)

PROXY_CONFIG = Config(
    proxies={
        'http': PROXY_URL,
        'https': PROXY_URL,  # Re-enable HTTPS proxy configuration
    }
)

def assume_role(sts_client, role_arn, session_name="AssumedRoleSession"):
    """Assumes the specified IAM role and returns temporary credentials."""
    print(f"Attempting to assume role: {role_arn}")
    try:
        assumed_role_object = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName=session_name
        )
        credentials = assumed_role_object['Credentials']
        print("Successfully assumed role.")
        return boto3.Session(
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken'],
        )
    except Exception as e:
        print(f"Error assuming role {role_arn}: {e}")
        raise

def test_s3_ls(session):
    """Tests listing S3 buckets using the provided session."""
    print("\nTesting S3 List Buckets...")
    s3_client = session.client('s3', config=PROXY_CONFIG, verify=CA_CERT_PATH)
    try:
        response = s3_client.list_buckets()
        print("Successfully listed S3 buckets:")
        for bucket in response.get('Buckets', []):
            print(f"  - {bucket['Name']}")
    except Exception as e:
        print(f"Error listing S3 buckets: {e}")

def test_sts_get_caller_identity(session):
    """Tests getting caller identity using the provided session."""
    print("\nTesting STS Get Caller Identity...")
    sts_client = session.client('sts', config=PROXY_CONFIG, verify=CA_CERT_PATH)
    try:
        response = sts_client.get_caller_identity()
        print("Successfully got caller identity:")
        print(f"  Account: {response.get('Account')}")
        print(f"  UserId: {response.get('UserId')}")
        print(f"  Arn: {response.get('Arn')}")
    except Exception as e:
        print(f"Error getting caller identity: {e}")

def test_assume_role(role_arn=None):
    """Tests assuming a specific IAM role."""
    print("\nTesting STS Assume Role...")

    # Use default credentials to assume the role initially
    # The assume_role call itself will go through the proxy
    sts_client = boto3.client("sts", config=PROXY_CONFIG, verify=CA_CERT_PATH)
    try:
        assumed_session = assume_role(sts_client, role_arn)
        print("Testing commands with assumed role credentials...")
        # Test other commands using the assumed role's session
        test_sts_get_caller_identity(assumed_session)
        # You could add test_s3_ls(assumed_session) here if the role has s3:ListBucket permissions
    except Exception as e:
        print(f"Failed to assume role or test commands with it: {e}")

if __name__ == "__main__":
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Test AWS API calls through a proxy')
    parser.add_argument('--role-arn', type=str, help='IAM role ARN to assume')
    parser.add_argument('--skip-s3', action='store_true', help='Skip S3 bucket listing test')
    parser.add_argument('--skip-sts', action='store_true', help='Skip STS get caller identity test')
    parser.add_argument('--skip-assume-role', action='store_true', help='Skip assume role test')
    args = parser.parse_args()

    print(f"Configuring boto3 to use proxy: {PROXY_URL}")
    
    # Check if the CA certificate exists
    if not os.path.exists(CA_CERT_PATH):
        print(f"Warning: CA certificate not found at {CA_CERT_PATH}")
        print("You may need to install the certificate or the tests will fail.")
        print("The certificate should be generated when the proxy server first runs.")

    # Use default credentials from environment/AWS config for initial tests
    default_session = boto3.Session()

    if not args.skip_s3:
        test_s3_ls(default_session)
    
    if not args.skip_sts:
        test_sts_get_caller_identity(default_session)
    
    if not args.skip_assume_role:
        test_assume_role(args.role_arn)

    print("\nAll tests completed.")
