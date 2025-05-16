import asyncio
import socket
import ssl
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

async def handle_client(reader, writer):
    try:
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

async def start_proxy(host='0.0.0.0', port=8888):
    server = await asyncio.start_server(handle_client, host, port)
    logger.info(f"Proxy server running on {host}:{port}")
    async with server:
        await server.serve_forever()

def main():
    try:
        asyncio.run(start_proxy())
    except KeyboardInterrupt:
        logger.info("Shutting down proxy server")
    except Exception as e:
        logger.error(f"Server error: {e}")

if __name__ == "__main__":
    main()