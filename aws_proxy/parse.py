import re
from typing import Tuple, Optional

def extract_access_key_from_auth(auth_header: str) -> Optional[str]:
    """
    Extract the AWS access key ID from the Authorization header.
    
    Args:
        auth_header: The Authorization header value
        
    Returns:
        The access key ID if found, None otherwise
    """
    if not auth_header:
        return None
    
    # Format: AWS4-HMAC-SHA256 Credential=ACCESS_KEY_ID/DATE/REGION/SERVICE/aws4_request, ...
    match = re.search(r'Credential=([A-Z0-9]+)/', auth_header)
    if match:
        return match.group(1)
    return None
    
def extract_role_from_assume_role_request(body: str) -> Optional[str]:
    """
    Extract the role ARN from an AssumeRole request body.
    
    Args:
        body: The request body
        
    Returns:
        The role ARN if found, None otherwise
    """
    if not body:
        return None
    
    # Format: Action=AssumeRole&...&RoleArn=ROLE_ARN&...
    match = re.search(r'RoleArn=([^&]+)', body)
    if match:
        # URL decode the role ARN
        role_arn = match.group(1).replace('%3A', ':').replace('%2F', '/')
        return role_arn
    return None
    
def extract_access_key_from_assume_role_response(body: str) -> Optional[str]:
    """
    Extract the access key ID from an AssumeRole response.
    
    Args:
        body: The response body
        
    Returns:
        The access key ID if found, None otherwise
    """
    if not body:
        return None
    
    # XML format: <AccessKeyId>ACCESS_KEY_ID</AccessKeyId>
    match = re.search(r'<AccessKeyId>([A-Z0-9]+)</AccessKeyId>', body)
    if match:
        return match.group(1)
    return None
    
def extract_role_from_caller_identity_response(body: str) -> Optional[str]:
    """
    Extract the role ARN from a GetCallerIdentity response.
    
    Args:
        body: The response body
        
    Returns:
        The role ARN if found, None otherwise
    """
    if not body:
        return None
    
    # XML format: <Arn>arn:aws:sts::ACCOUNT_ID:assumed-role/ROLE_NAME/SESSION_NAME</Arn>
    match = re.search(r'<Arn>arn:aws:sts::(\d+):assumed-role/([^/]+)/([^<]+)</Arn>', body)
    if match:
        account_id, role_name, _ = match.groups()
        # Reconstruct the full role ARN
        return f"arn:aws:iam::{account_id}:role/{role_name}"
    
    # If it's not an assumed role, it might be a user or other entity
    match = re.search(r'<Arn>([^<]+)</Arn>', body)
    if match:
        return match.group(1)
    
    return None

def parse(auth_header: str, req_body: str, resp_body: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Parse AWS request and response to extract access key and role ARN.
    
    Args:
        auth_header: The Authorization header from the request
        req_body: The request body
        resp_body: The response body
        
    Returns:
        Tuple of (access_key, role_arn) or (None, None) if not found
    """
    access_key = extract_access_key_from_auth(auth_header)
    role_arn = None
    
    if not access_key:
        return None, None
        
    # Check if this is an AssumeRole response
    if 'Action=AssumeRole' in req_body and '<AssumeRoleResponse' in resp_body:
        # Extract the role ARN from the request
        role_arn = extract_role_from_assume_role_request(req_body)
        
        # Extract the new access key from the response
        new_access_key = extract_access_key_from_assume_role_response(resp_body)
        
        if role_arn and new_access_key:
            return new_access_key, role_arn
            
    # Check if this is a GetCallerIdentity response
    elif 'Action=GetCallerIdentity' in req_body and '<GetCallerIdentityResponse' in resp_body:
        # Extract the role ARN from the response
        role_arn = extract_role_from_caller_identity_response(resp_body)
        
        if role_arn and access_key:
            return access_key, role_arn
            
    return access_key, None
