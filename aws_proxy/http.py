def parse_http_response(raw_response: bytes) -> dict:
    # Split into lines
    lines = raw_response.split(b'\r\n')
    if not lines:
        raise ValueError("Empty response")

    # Parse status line
    status_line = lines[0].decode('utf-8').split(' ', 2)
    if len(status_line) < 2:
        raise ValueError("Invalid status line")
    protocol = status_line[0]
    status_code = status_line[1]
    reason = status_line[2] if len(status_line) > 2 else ''

    # Parse headers
    headers = {}
    body_start = -1
    for i, line in enumerate(lines[1:], 1):
        if not line:  # Empty line marks end of headers
            body_start = i + 1
            break
        key, value = line.decode('utf-8').split(': ', 1)
        headers[key] = value

    # Extract body
    body = b''
    if body_start != -1 and body_start < len(lines):
        body = b'\r\n'.join(lines[body_start:])

    return {
        'protocol': protocol,
        'status_code': status_code,
        'reason': reason,
        'headers': headers,
        'body': body
    }

def parse_http_request(raw_request: bytes) -> dict:
    # Split into lines
    lines = raw_request.split(b'\r\n')
    if not lines:
        raise ValueError("Empty request")

    # Parse request line
    request_line = lines[0].decode('utf-8').split(' ')
    if len(request_line) != 3:
        raise ValueError("Invalid request line")
    method, uri, protocol = request_line

    # Parse headers
    headers = {}
    body_start = -1
    for i, line in enumerate(lines[1:], 1):
        if not line:  # Empty line marks end of headers
            body_start = i + 1
            break
        key, value = line.decode('utf-8').split(': ', 1)
        headers[key] = value

    # Extract body (if any)
    body = b''
    if body_start != -1 and body_start < len(lines):
        body = b'\r\n'.join(lines[body_start:])

    return {
        'method': method,
        'uri': uri,
        'protocol': protocol,
        'headers': headers,
        'body': body
    }
