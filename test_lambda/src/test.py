import json
import boto3
from botocore.config import Config
import ssl, os, botocore

proxy_definitions = {
    'https': 'http://localhost:8080'
}

my_config = Config(
    region_name='us-east-1',
    signature_version='v4',
    proxies=proxy_definitions,
    proxies_config={
        'proxy_ca_bundle': 'goproxy/certs/aws-proxy.crt'
    }
)

def lambda_handler(event, context):
    print("botocore version:", botocore.__version__)   # need ≥ 1.28
    print("AWS_CA_BUNDLE:", os.getenv("AWS_CA_BUNDLE"))
    print("Verify paths:", ssl.get_default_verify_paths())

    client = boto3.client('sts') # , config=my_config)
    response = client.get_caller_identity()

    return {
        'statusCode': 200,
        'body': response
    }

if __name__ == '__main__':
    res = lambda_handler(None, None)
    print(res)
    