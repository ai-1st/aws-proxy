import logging
from mitm import middleware
from mitm.core import Connection
import json
from . import http

# Get logger specific to this module
logger = logging.getLogger('aws-proxy.middleware')

requests = {}


class AWSLoggingMiddleware(middleware.Middleware):
    """Middleware to log AWS API requests and responses."""

    def __init__(self):  # pylint: disable=super-init-not-called
        self.connection: Connection = None
    
    async def mitm_started(self, host: str, port: int):
        logger.info(f"MITM server started on {host}:{port}.")

    async def client_connected(self, connection: Connection):
        logger.info(f"Client {connection.client} has connected.")

    async def server_connected(self, connection: Connection):
        logger.info(f"Client {connection.client} has connected to server {connection.server}.")

    async def client_data(self, connection: Connection, data: bytes) -> bytes:
        try:
            parsed = http.parse_http_request(data)
            parsed['body'] = parsed['body'].decode('utf-8')
            connection_key = f"{connection.client} -> {connection.server}"
            requests[connection_key] = parsed
            logger.info(f"Client {connection_key}:\n\n{json.dumps(parsed, indent=2)}\n")
        except Exception as e:
            logger.error(f"Failed to parse HTTP request: {e}")
        return data

    async def server_data(self, connection: Connection, data: bytes) -> bytes:
        try:
            parsed = http.parse_http_response(data)
            body = parsed['body'].decode('utf-8')
            connection_key = f"{connection.client} -> {connection.server}"
            logger.info(f"Server {connection_key}:")
            logger.info(f"Client Auth: {requests[connection_key]['headers']['Authorization']}")
            logger.info(f"Client Body: {requests[connection_key]['body']}")
            logger.info(f"{body}\n")
            del requests[connection_key]
        except Exception as e:
            logger.error(f"Failed to parse HTTP response: {e}")
        return data

    async def client_disconnected(self, connection: Connection):
        logger.info(f"Client {connection.client} has disconnected.")

    async def server_disconnected(self, connection: Connection):
        logger.info(f"Server {connection.server} has disconnected.")
