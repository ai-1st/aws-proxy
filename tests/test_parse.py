import unittest
from aws_proxy.parse import (
    extract_access_key_from_auth,
    extract_role_from_assume_role_request,
    extract_access_key_from_assume_role_response,
    extract_role_from_caller_identity_response,
    parse
)


class TestParse(unittest.TestCase):
    def test_extract_access_key_from_auth(self):
        # Test with valid AWS authorization header
        auth_header = "AWS4-HMAC-SHA256 Credential=ASIAYBPYJ6G47IWBXSQ7Y/20250404/us-east-1/sts/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=abcdef"
        self.assertEqual(extract_access_key_from_auth(auth_header), "ASIAYBPYJ6G47IWBXSQ7Y")
        
        # Test with empty header
        self.assertIsNone(extract_access_key_from_auth(""))
        
        # Test with invalid header
        self.assertIsNone(extract_access_key_from_auth("Invalid header"))
        
    def test_extract_role_from_assume_role_request(self):
        # Test with valid AssumeRole request body
        req_body = "Action=AssumeRole&Version=2011-06-15&RoleArn=arn%3Aaws%3Aiam%3A%3A552960913849%3Arole%2FCloudFix-RightSpend-Assume-Write-Role&RoleSessionName=AssumedRoleSession"
        self.assertEqual(
            extract_role_from_assume_role_request(req_body),
            "arn:aws:iam::552960913849:role/CloudFix-RightSpend-Assume-Write-Role"
        )
        
        # Test with empty body
        self.assertIsNone(extract_role_from_assume_role_request(""))
        
        # Test with invalid body
        self.assertIsNone(extract_role_from_assume_role_request("Invalid body"))
        
    def test_extract_access_key_from_assume_role_response(self):
        # Test with valid AssumeRole response body
        resp_body = """
        <AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
            <AssumeRoleResult>
                <AssumedRoleUser>
                <AssumedRoleId>AROAYBPYJ6G45OZMMBYVL:AssumedRoleSession</AssumedRoleId>
                <Arn>arn:aws:sts::552960913849:assumed-role/CloudFix-RightSpend-Assume-Write-Role/AssumedRoleSession</Arn>
                </AssumedRoleUser>
                <Credentials>
                <AccessKeyId>ASIAYBPYJ6G47IWBXSQ7Y</AccessKeyId>
                <SecretAccessKey>OFZ8/GualoeWU23423423423423gbwV0GsFGGDfF</SecretAccessKey>
                <SessionToken>FwoGZXIvYXdzELD//////////wEaDIsigfeCzyGwoPf5ASK2123456789012DLTHSQIix8/oXlSf2PGsnKCQCaN2IAg6t9ppweJAb0UBqiI04aiybgECdL0voCBmC8ClvSlA3IUVb9K/Soyrj+BcUHbIYnG8CCO2Ymd3YpXXYoQIORrmWP3WrP3GSJGa/JtYUaIh9BBOc4HaFk3dB3lHz61qPzJ8BoOsv9sBVW66pEJHzNfVOUpb/5FEuIhUtWJBKpB+4ma02tpfqLPMDvvkj2jpaEKLbjv78GMi2LE5gwW7WQ0LIejjOs2S+brK5o4ntMxRde1xTHU+Ju+tvBs319vuQwG55OHVs=</SessionToken>
                <Expiration>2025-04-04T15:50:30Z</Expiration>
                </Credentials>
            </AssumeRoleResult>
            <ResponseMetadata>
                <RequestId>683d81f7-128f-4c8f-8261-d123456789012</RequestId>
            </ResponseMetadata>
        </AssumeRoleResponse>
        """
        self.assertEqual(extract_access_key_from_assume_role_response(resp_body), "ASIAYBPYJ6G47IWBXSQ7Y")
        
        # Test with empty body
        self.assertIsNone(extract_access_key_from_assume_role_response(""))
        
        # Test with invalid body
        self.assertIsNone(extract_access_key_from_assume_role_response("Invalid body"))
        
    def test_extract_role_from_caller_identity_response(self):
        # Test with valid GetCallerIdentity response body (assumed role)
        resp_body = """
        <GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
            <GetCallerIdentityResult>
                <Arn>arn:aws:sts::552960913849:assumed-role/CloudFix-RightSpend-Assume-Write-Role/AssumedRoleSession</Arn>
                <UserId>AROAYBPYJ6G45OZMMBYVL:AssumedRoleSession</UserId>
                <Account>552960913849</Account>
            </GetCallerIdentityResult>
            <ResponseMetadata>
                <RequestId>e4cef797-df0f-420c-b769-0bbcd1307d58</RequestId>
            </ResponseMetadata>
        </GetCallerIdentityResponse>
        """
        self.assertEqual(
            extract_role_from_caller_identity_response(resp_body),
            "arn:aws:iam::552960913849:role/CloudFix-RightSpend-Assume-Write-Role"
        )
        
        # Test with valid GetCallerIdentity response body (user)
        resp_body_user = """
        <GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
            <GetCallerIdentityResult>
                <Arn>arn:aws:iam::552960913849:user/dd</Arn>
                <UserId>AIDAYBPYJ6G47IWBXSQ7Y</UserId>
                <Account>552960913849</Account>
            </GetCallerIdentityResult>
            <ResponseMetadata>
                <RequestId>e4cef797-df0f-420c-b769-0bbcd1307d58</RequestId>
            </ResponseMetadata>
        </GetCallerIdentityResponse>
        """
        self.assertEqual(
            extract_role_from_caller_identity_response(resp_body_user),
            "arn:aws:iam::552960913849:user/dd"
        )
        
        # Test with empty body
        self.assertIsNone(extract_role_from_caller_identity_response(""))
        
        # Test with invalid body
        self.assertIsNone(extract_role_from_caller_identity_response("Invalid body"))
        
    def test_parse_assume_role(self):
        # Test parsing AssumeRole request and response
        auth_header = "AWS4-HMAC-SHA256 Credential=ASIAYBPYJ6G47IWBXSQ7Y/20250404/us-east-1/sts/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=abcdef"
        req_body = "Action=AssumeRole&Version=2011-06-15&RoleArn=arn%3Aaws%3Aiam%3A%3A552960913849%3Arole%2FCloudFix-RightSpend-Assume-Write-Role&RoleSessionName=AssumedRoleSession"
        resp_body = """
        <AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
            <AssumeRoleResult>
                <AssumedRoleUser>
                <AssumedRoleId>AROAYBPYJ6G45OZMMBYVL:AssumedRoleSession</AssumedRoleId>
                <Arn>arn:aws:sts::552960913849:assumed-role/CloudFix-RightSpend-Assume-Write-Role/AssumedRoleSession</Arn>
                </AssumedRoleUser>
                <Credentials>
                <AccessKeyId>ASIAXYZ123456789012</AccessKeyId>
                <SecretAccessKey>OFZ8/GualoeWU23423423423423gbwV0GsFGGDfF</SecretAccessKey>
                <SessionToken>FwoGZXIvYXdzELD//////////wEaDIsigfeCzyGwoPf5ASK2123456789012DLTHSQIix8/oXlSf2PGsnKCQCaN2IAg6t9ppweJAb0UBqiI04aiybgECdL0voCBmC8ClvSlA3IUVb9K/Soyrj+BcUHbIYnG8CCO2Ymd3YpXXYoQIORrmWP3WrP3GSJGa/JtYUaIh9BBOc4HaFk3dB3lHz61qPzJ8BoOsv9sBVW66pEJHzNfVOUpb/5FEuIhUtWJBKpB+4ma02tpfqLPMDvvkj2jpaEKLbjv78GMi2LE5gwW7WQ0LIejjOs2S+brK5o4ntMxRde1xTHU+Ju+tvBs319vuQwG55OHVs=</SessionToken>
                <Expiration>2025-04-04T15:50:30Z</Expiration>
                </Credentials>
            </AssumeRoleResult>
            <ResponseMetadata>
                <RequestId>683d81f7-128f-4c8f-8261-d123456789012</RequestId>
            </ResponseMetadata>
        </AssumeRoleResponse>
        """
        
        access_key, role_arn = parse(auth_header, req_body, resp_body)
        self.assertEqual(access_key, "ASIAXYZ123456789012")
        self.assertEqual(role_arn, "arn:aws:iam::552960913849:role/CloudFix-RightSpend-Assume-Write-Role")
        
    def test_parse_get_caller_identity(self):
        # Test parsing GetCallerIdentity request and response
        auth_header = "AWS4-HMAC-SHA256 Credential=ASIAYBPYJ6G47IWBXSQ7Y/20250404/us-east-1/sts/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=abcdef"
        req_body = "Action=GetCallerIdentity&Version=2011-06-15"
        resp_body = """
        <GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
            <GetCallerIdentityResult>
                <Arn>arn:aws:sts::552960913849:assumed-role/CloudFix-RightSpend-Assume-Write-Role/AssumedRoleSession</Arn>
                <UserId>AROAYBPYJ6G45OZMMBYVL:AssumedRoleSession</UserId>
                <Account>552960913849</Account>
            </GetCallerIdentityResult>
            <ResponseMetadata>
                <RequestId>e4cef797-df0f-420c-b769-0bbcd1307d58</RequestId>
            </ResponseMetadata>
        </GetCallerIdentityResponse>
        """
        
        access_key, role_arn = parse(auth_header, req_body, resp_body)
        self.assertEqual(access_key, "ASIAYBPYJ6G47IWBXSQ7Y")
        self.assertEqual(role_arn, "arn:aws:iam::552960913849:role/CloudFix-RightSpend-Assume-Write-Role")
        
    def test_parse_unknown_api(self):
        # Test parsing unknown API call
        auth_header = "AWS4-HMAC-SHA256 Credential=ASIAYBPYJ6G47IWBXSQ7Y/20250404/us-east-1/s3/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=abcdef"
        req_body = "Action=ListBuckets&Version=2011-06-15"
        resp_body = "<ListBucketsResponse>...</ListBucketsResponse>"
        
        access_key, role_arn = parse(auth_header, req_body, resp_body)
        self.assertEqual(access_key, "ASIAYBPYJ6G47IWBXSQ7Y")
        self.assertIsNone(role_arn)
        
    def test_parse_empty_inputs(self):
        # Test with empty inputs
        self.assertEqual(parse("", "", ""), (None, None))
        

if __name__ == "__main__":
    unittest.main()
