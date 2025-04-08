import logging
from mitm import middleware
from mitm.core import Connection
import json
from . import http
from .keystore import KeyStore
from . import parse

# Get logger specific to this module
logger = logging.getLogger(__name__)

requests = {}


class AWSLoggingMiddleware(middleware.Middleware):
    """Middleware to log AWS API requests and responses with role-based access control."""

    def __init__(self):  # pylint: disable=super-init-not-called
        self.connection: Connection = None
        # Initialize the KeyStore with a 1-hour TTL
        self.keystore = KeyStore(ttl_seconds=3600)
    
    async def mitm_started(self, host: str, port: int):
        logger.info(f"MITM server started on {host}:{port}.")
        logger.info(f"Role-based access control is {'enabled' if self.keystore.enforce_rbac else 'disabled'}.")
        if self.keystore.allowed_roles:
            logger.info(f"Allowed roles: {', '.join(self.keystore.allowed_roles)}")
        else:
            logger.info("All roles are allowed (no whitelist configured)")

    async def client_connected(self, connection: Connection):
        logger.info(f"Client {connection.client} has connected.")
    
    async def server_connected(self, connection: Connection):
        logger.info(f"Client {connection.client} has connected to server {connection.server}.")

    async def client_data(self, connection: Connection, data: bytes) -> bytes:
        try:
            parsed = http.parse_http_request(data)
            
            # Skip CONNECT requests
            if parsed['method'] == 'CONNECT':
                connection_key = f"{connection.client} -> <empty host>:"
                logger.info(f"Client {connection_key}:\n\n{json.dumps(parsed, indent=2)}\n")
                return data
                
            # Extract body as string
            try:
                parsed['body'] = parsed['body'].decode('utf-8')
            except UnicodeDecodeError:
                parsed['body'] = f"<binary data: {len(parsed['body'])} bytes>"
                
            connection_key = f"{connection.client} -> {connection.server}"
            requests[connection_key] = parsed
            
            # Log the request
            logger.info(f"Client {connection_key}:\n\n{json.dumps(parsed, indent=2)}\n")
            
            # Check if this is an AWS request that needs authorization
            auth_header = parsed['headers'].get('Authorization', '')
            access_key = parse.extract_access_key_from_auth(auth_header)
            
            if access_key and self.keystore.enforce_rbac:
                # Check if the access key is authorized
                is_authorized, role_arn = self.keystore.check_authorization(access_key)
                
                if role_arn:
                    logger.info(f"Request using access key {access_key} associated with role {role_arn}")
                    
                    # If not authorized and we're enforcing RBAC, we could deny the request here
                    if not is_authorized:
                        logger.warning(f"Access denied: Role {role_arn} is not in the allowed list")
                        # For now, we'll just log it and let the request through
                        # To deny the request, you could return a custom response here
                else:
                    # For AssumeRole requests, we'll wait for the response to update our mapping
                    if 'Action=AssumeRole' in parsed['body']:
                        role_arn = parse.extract_role_from_assume_role_request(parsed['body'])
                        if role_arn:
                            logger.info(f"AssumeRole request for role {role_arn}")
                            # We'll update the mapping when we see the response
                    else:
                        logger.warning(f"Unknown access key: {access_key}")
                        # For now, we'll let the request through and wait for a GetCallerIdentity response
            
        except Exception as e:
            logger.error(f"Failed to parse HTTP request: {e}")
        return data
    
    async def server_data(self, connection: Connection, data: bytes) -> bytes:
        try:
            parsed = http.parse_http_response(data)
            body_str = ""
            
            try:
                body_str = parsed['body'].decode('utf-8')
            except UnicodeDecodeError:
                body_str = f"<binary data: {len(parsed['body'])} bytes>"
                
            connection_key = f"{connection.client} -> {connection.server}"
            
            # Log the response
            logger.info(f"Server {connection_key}:")
            
            # Get the original request if available
            if connection_key in requests:
                req = requests[connection_key]
                auth_header = req['headers'].get('Authorization', '')
                req_body = req['body']
                logger.info(f"Client Auth: {auth_header}")
                logger.info(f"Client Body: {req_body}")
                
                # Parse the request and response to update the KeyStore
                self.keystore.parse_and_update(auth_header, req_body, body_str)
                
                # Clean up the request cache
                del requests[connection_key]
            
            logger.info(f"{body_str}\n")
            
        except Exception as e:
            logger.error(f"Failed to parse HTTP response: {e}")
        return data

    async def client_disconnected(self, connection: Connection):
        logger.info(f"Client {connection.client} has disconnected.")

    async def server_disconnected(self, connection: Connection):
        logger.info(f"Server {connection.server} has disconnected.")
