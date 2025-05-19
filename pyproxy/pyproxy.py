import asyncio
import socket
import ssl
import logging
import argparse
import ipaddress

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

async def handle_client(reader, writer, allowed_ip_range=None):
    try:
        # Get client address
        client_addr = writer.get_extra_info('peername')[0]
        
        # Check if client IP is in allowed range
        if allowed_ip_range and not is_ip_in_range(client_addr, allowed_ip_range):
            logger.warning(f"Client {client_addr} not in allowed IP range {allowed_ip_range}")
            writer.close()
            return
            
        # Read the client request
        request = await reader.read(4096)
        if not request:
            return

        # Parse the CONNECT request
        request_line = request.decode('utf-8').split('\n')[0]
        method, target, _ = request_line.split(' ')
        if method != 'CONNECT':
            logger.warning(f"Unsupported method: {method}")
            return

        host, port = target.split(':')
        port = int(port)
        logger.info(f"Connecting to {host}:{port}")

        # Respond to client with 200 Connection Established
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()

        # Connect to the target server
        try:
            target_reader, target_writer = await asyncio.open_connection(host, port)
        except Exception as e:
            logger.error(f"Failed to connect to {host}:{port} - {e}")
            return

        # Forward data in both directions
        async def forward(source, dest, direction):
            try:
                while True:
                    data = await source.read(8192)
                    if not data:
                        break
                    dest.write(data)
                    await dest.drain()
            except Exception as e:
                logger.error(f"Error in {direction} forwarding: {e}")
            finally:
                dest.close()

        # Start bidirectional forwarding
        tasks = [
            forward(reader, target_writer, "client->server"),
            forward(target_reader, writer, "server->client")
        ]
        await asyncio.gather(*tasks)

    except Exception as e:
        logger.error(f"Error handling client: {e}")
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except:
            pass

def is_ip_in_range(ip, ip_range):
    """
    Check if an IP address is within the specified CIDR range.
    
    Args:
        ip (str): The IP address to check
        ip_range (str): CIDR notation range (e.g., '192.168.1.0/24')
        
    Returns:
        bool: True if IP is in range, False otherwise
    """
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(ip_range)
    except ValueError:
        logger.error(f"Invalid IP address or range: {ip}, {ip_range}")
        return False

async def start_proxy(host='0.0.0.0', port=8888, allowed_ip_range=None):
    server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, allowed_ip_range),
        host, port
    )
    ip_range_info = f" (allowed clients: {allowed_ip_range})" if allowed_ip_range else ""
    logger.info(f"Proxy server running on {host}:{port}{ip_range_info}")
    async with server:
        await server.serve_forever()

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='AWS Proxy Server')
    parser.add_argument('--host', default='0.0.0.0', help='Host address to bind to (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=8080, help='Port to listen on (default: 8080)')
    parser.add_argument('--allowed-ip-range', help='CIDR notation of allowed client IP range (e.g., 192.168.1.0/24)')
    args = parser.parse_args()
    
    try:
        asyncio.run(start_proxy(host=args.host, port=args.port, allowed_ip_range=args.allowed_ip_range))
    except KeyboardInterrupt:
        logger.info("Shutting down proxy server")
    except Exception as e:
        logger.error(f"Server error: {e}")

if __name__ == "__main__":
    main()