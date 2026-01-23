"""
Test helper utilities for HTTP handler testing.
"""

import io
from unittest.mock import MagicMock


def create_test_handler(server_module, path="/", method="GET", headers=None, body=None):
    """
    Create a properly initialized RequestHandler for testing.

    Args:
        server_module: The imported server module (deq.server)
        path: Request path (e.g., "/api/config")
        method: HTTP method (e.g., "GET", "POST")
        headers: Dictionary of request headers
        body: Request body as bytes (for POST requests)

    Returns:
        A RequestHandler instance with mocked I/O methods
    """
    # Create a mock request that won't trigger parse_request errors
    mock_request = MagicMock()

    # Set up makefile to return a BytesIO for both read and write
    if body:
        mock_request.makefile.return_value = io.BytesIO(body)
    else:
        mock_request.makefile.return_value = io.BytesIO(b"")

    # Create the handler
    handler = server_module.RequestHandler(mock_request, ("127.0.0.1", 8080), None)

    # Set up instance variables to avoid parse_request errors
    handler.raw_requestline = f"{method} {path} HTTP/1.1".encode()
    handler.requestline = f"{method} {path} HTTP/1.1"
    handler.command = method
    handler.path = path
    handler.request_version = "HTTP/1.1"

    # Set headers - add Content-Length if body is provided
    if headers is None:
        headers = {}
    if body and "Content-Length" not in headers:
        headers["Content-Length"] = str(len(body))

    handler.headers = headers
    handler.close_connection = True

    # Mock the I/O methods
    handler.send_response = MagicMock()
    handler.send_header = MagicMock()
    handler.end_headers = MagicMock()
    handler.wfile = MagicMock()
    handler.rfile = MagicMock()

    # Set up rfile.read to return body if provided
    if body:
        handler.rfile.read.return_value = body

    return handler
