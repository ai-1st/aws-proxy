import logging
import time
from typing import Dict, Tuple, Optional
from . import parse

# Get logger specific to this module
logger = logging.getLogger(__name__)

class KeyStore:
    """
    Stores a mapping between AWS Access Keys and IAM Roles with expiration.
    Keys expire after a configurable duration.
    """

    def __init__(self, ttl_seconds: int = 3600):
        """
        Initialize the KeyStore with a specified TTL for entries.
        
        Args:
            ttl_seconds: Time-to-live in seconds for each key (default: 1 hour)
        """
        self.ttl_seconds = ttl_seconds
        # Map of access_key_id -> (role_arn, expiration_timestamp)
        self.store: Dict[str, Tuple[str, float]] = {}
        # Whitelist of allowed role ARNs (empty means all are allowed)
        self.allowed_roles: list[str] = []
        # Whether to enforce role-based access control
        self.enforce_rbac = True
        
        logger.info(f"KeyStore initialized with TTL of {ttl_seconds} seconds")
        
    def set_allowed_roles(self, roles: list[str]) -> None:
        """
        Set the list of allowed role ARNs.
        
        Args:
            roles: List of role ARNs that are allowed
        """
        self.allowed_roles = roles
        logger.info(f"Set allowed roles: {', '.join(roles) if roles else 'All roles allowed'}")
        
    def set_enforce_rbac(self, enforce: bool) -> None:
        """
        Set whether to enforce role-based access control.
        
        Args:
            enforce: True to enforce RBAC, False to only log
        """
        self.enforce_rbac = enforce
        logger.info(f"RBAC enforcement set to: {enforce}")
        
    def clean_expired(self) -> None:
        """Remove expired entries from the store."""
        current_time = time.time()
        expired_keys = [
            key for key, (_, expiration) in self.store.items()
            if expiration < current_time
        ]
        
        for key in expired_keys:
            role_arn = self.store[key][0]
            logger.info(f"Removing expired credentials for access key {key} (role: {role_arn})")
            del self.store[key]
            
        if expired_keys:
            logger.info(f"Cleaned {len(expired_keys)} expired entries")
            
    def get(self, access_key: str) -> Optional[str]:
        """
        Get the role ARN associated with an access key.
        
        Args:
            access_key: The AWS access key ID
            
        Returns:
            The role ARN if found and not expired, None otherwise
        """
        self.clean_expired()
        
        if access_key in self.store:
            role_arn, _ = self.store[access_key]
            return role_arn
        return None
        
    def put(self, access_key: str, role_arn: str) -> None:
        """
        Associate an access key with a role ARN.
        
        Args:
            access_key: The AWS access key ID
            role_arn: The IAM role ARN
        """
        expiration = time.time() + self.ttl_seconds
        self.store[access_key] = (role_arn, expiration)
        logger.info(f"Added mapping: {access_key} -> {role_arn} (expires in {self.ttl_seconds} seconds)")
        
    def is_allowed(self, role_arn: str) -> bool:
        """
        Check if a role ARN is in the allowed list.
        
        Args:
            role_arn: The IAM role ARN to check
            
        Returns:
            True if the role is allowed, False otherwise
        """
        if not self.allowed_roles:
            return True  # All roles allowed if whitelist is empty
        return role_arn in self.allowed_roles
        
    def check_authorization(self, access_key: str) -> Tuple[bool, Optional[str]]:
        """
        Check if an access key is authorized.
        
        Args:
            access_key: The AWS access key ID
            
        Returns:
            Tuple of (is_authorized, role_arn)
        """
        if not self.enforce_rbac:
            return True, None
            
        role_arn = self.get(access_key)
        if not role_arn:
            logger.warning(f"Unknown access key: {access_key}")
            return False, None
            
        is_allowed = self.is_allowed(role_arn)
        if not is_allowed:
            logger.warning(f"Access denied: Role {role_arn} is not in the allowed list")
            
        return is_allowed, role_arn
        
    def parse_and_update(self, auth_header: str, req_body: str, resp_body: str) -> None:
        """
        Parse request and response to extract and store AWS access key and role ARN mappings.
        
        Args:
            auth_header: The Authorization header from the request
            req_body: The request body
            resp_body: The response body
        """
        access_key, role_arn = parse.parse(auth_header, req_body, resp_body)
        
        if access_key and role_arn:
            self.put(access_key, role_arn)
