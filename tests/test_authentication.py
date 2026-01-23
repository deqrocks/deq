"""
Comprehensive tests for authentication-related functions in server.py.

Tests include:
- is_auth_enabled (standalone function)
- RequestHandler methods: is_authenticated, send_login_page, send_json, send_html, send_file
"""

import os
import json
import pytest
from unittest.mock import patch, MagicMock, call, mock_open

from test_helpers import create_test_handler


class TestIsAuthEnabled:
    """Test is_auth_enabled function."""

    def test_auth_enabled_when_password_file_exists(self, deq_server):
        """is_auth_enabled returns True when password file exists."""
        with patch("os.path.exists") as mock_exists:
            mock_exists.return_value = True
            assert deq_server.is_auth_enabled() == True
            mock_exists.assert_called_once_with(deq_server.PASSWORD_FILE)

    def test_auth_disabled_when_password_file_missing(self, deq_server):
        """is_auth_enabled returns False when password file missing."""
        with patch("os.path.exists") as mock_exists:
            mock_exists.return_value = False
            assert deq_server.is_auth_enabled() == False
            mock_exists.assert_called_once_with(deq_server.PASSWORD_FILE)


class TestRequestHandlerAuthentication:
    """Test RequestHandler authentication methods."""

    def test_is_authenticated_auth_disabled(self, deq_server):
        """When authentication is disabled, any request is authenticated."""
        handler = create_test_handler(deq_server)
        with patch.object(deq_server, "is_auth_enabled", return_value=False):
            assert handler.is_authenticated() == True
            # verify_session_token should not be called
            # (but we can't assert that without patching it)

    def test_is_authenticated_auth_enabled_no_cookie(self, deq_server):
        """When auth enabled but no session cookie, request is not authenticated."""
        handler = create_test_handler(deq_server)
        with patch.object(deq_server, "is_auth_enabled", return_value=True):
            # Mock get_session_cookie to return None
            with patch.object(handler, "get_session_cookie", return_value=None):
                # Mock verify_session_token to return False for None token
                with patch.object(
                    deq_server, "verify_session_token", return_value=False
                ) as mock_verify:
                    result = handler.is_authenticated()
                    assert result == False
                    mock_verify.assert_called_once_with(None)

    def test_is_authenticated_auth_enabled_valid_token(self, deq_server):
        """When auth enabled and valid session token, request is authenticated."""
        handler = create_test_handler(deq_server)
        with patch.object(deq_server, "is_auth_enabled", return_value=True):
            with patch.object(
                handler, "get_session_cookie", return_value="valid:token"
            ):
                with patch.object(
                    deq_server, "verify_session_token", return_value=True
                ):
                    result = handler.is_authenticated()
                    assert result == True
                    deq_server.verify_session_token.assert_called_once_with(
                        "valid:token"
                    )

    def test_is_authenticated_auth_enabled_invalid_token(self, deq_server):
        """When auth enabled but invalid token, request is not authenticated."""
        handler = create_test_handler(deq_server)
        with patch.object(deq_server, "is_auth_enabled", return_value=True):
            with patch.object(
                handler, "get_session_cookie", return_value="invalid:token"
            ):
                with patch.object(
                    deq_server, "verify_session_token", return_value=False
                ):
                    result = handler.is_authenticated()
                    assert result == False
                    deq_server.verify_session_token.assert_called_once_with(
                        "invalid:token"
                    )

    def test_is_authenticated_malformed_token(self, deq_server):
        """Malformed token (e.g., not containing colon) should fail verification."""
        handler = create_test_handler(deq_server)
        with patch.object(deq_server, "is_auth_enabled", return_value=True):
            with patch.object(handler, "get_session_cookie", return_value="malformed"):
                with patch.object(
                    deq_server, "verify_session_token", return_value=False
                ):
                    result = handler.is_authenticated()
                    assert result == False
                    deq_server.verify_session_token.assert_called_once_with("malformed")

    def test_is_authenticated_empty_token(self, deq_server):
        """Empty token should fail verification."""
        handler = create_test_handler(deq_server)
        with patch.object(deq_server, "is_auth_enabled", return_value=True):
            with patch.object(handler, "get_session_cookie", return_value=""):
                with patch.object(
                    deq_server, "verify_session_token", return_value=False
                ):
                    result = handler.is_authenticated()
                    assert result == False
                    deq_server.verify_session_token.assert_called_once_with("")

    def test_is_authenticated_none_token(self, deq_server):
        """None token should fail verification."""
        handler = create_test_handler(deq_server)
        with patch.object(deq_server, "is_auth_enabled", return_value=True):
            with patch.object(handler, "get_session_cookie", return_value=None):
                with patch.object(
                    deq_server, "verify_session_token", return_value=False
                ):
                    result = handler.is_authenticated()
                    assert result == False
                    deq_server.verify_session_token.assert_called_once_with(None)


class TestSendLoginPage:
    """Test send_login_page method."""

    def test_send_login_page_calls_get_login_page(self, deq_server):
        """send_login_page should call get_login_page and send HTML."""
        handler = create_test_handler(deq_server)
        mock_html = "<html>login</html>"
        with patch.object(
            deq_server, "get_login_page", return_value=mock_html
        ) as mock_get:
            handler.send_login_page()
            mock_get.assert_called_once()
            # Verify response headers
            handler.send_response.assert_called_once_with(200)
            handler.send_header.assert_called_once_with("Content-Type", "text/html")
            handler.end_headers.assert_called_once()
            handler.wfile.write.assert_called_once_with(mock_html.encode())


class TestSendJson:
    """Test send_json method."""

    def test_send_json_default_status(self, deq_server):
        """send_json with default status 200."""
        handler = create_test_handler(deq_server)
        data = {"message": "test"}
        handler.send_json(data)
        handler.send_response.assert_called_once_with(200)
        handler.send_header.assert_has_calls(
            [
                call("Content-Type", "application/json"),
                call("Access-Control-Allow-Origin", "*"),
            ],
            any_order=True,
        )
        handler.end_headers.assert_called_once()
        # Verify JSON encoding
        expected_json = json.dumps(data)
        handler.wfile.write.assert_called_once_with(expected_json.encode())

    def test_send_json_custom_status(self, deq_server):
        """send_json with custom status code."""
        handler = create_test_handler(deq_server)
        data = {"error": "not found"}
        handler.send_json(data, status=404)
        handler.send_response.assert_called_once_with(404)
        handler.send_header.assert_has_calls(
            [
                call("Content-Type", "application/json"),
                call("Access-Control-Allow-Origin", "*"),
            ]
        )
        handler.end_headers.assert_called_once()
        handler.wfile.write.assert_called_once_with(json.dumps(data).encode())

    def test_send_json_empty_data(self, deq_server):
        """send_json with empty dict."""
        handler = create_test_handler(deq_server)
        handler.send_json({})
        handler.send_response.assert_called_once_with(200)
        handler.wfile.write.assert_called_once_with(b"{}")

    def test_send_json_nested_data(self, deq_server):
        """send_json with nested structures."""
        handler = create_test_handler(deq_server)
        data = {"list": [1, 2, 3], "nested": {"key": "value"}}
        handler.send_json(data)
        written = handler.wfile.write.call_args[0][0]
        parsed = json.loads(written.decode())
        assert parsed == data

    def test_send_json_list_data(self, deq_server):
        """send_json with list data (non-dict)."""
        handler = create_test_handler(deq_server)
        data = [1, 2, "three", {"four": 4}]
        handler.send_json(data)
        handler.send_response.assert_called_once_with(200)
        handler.send_header.assert_has_calls(
            [
                call("Content-Type", "application/json"),
                call("Access-Control-Allow-Origin", "*"),
            ],
            any_order=True,
        )
        handler.end_headers.assert_called_once()
        written = handler.wfile.write.call_args[0][0]
        parsed = json.loads(written.decode())
        assert parsed == data


class TestSendHtml:
    """Test send_html method."""

    def test_send_html(self, deq_server):
        """send_html sends HTML with correct headers."""
        handler = create_test_handler(deq_server)
        html_content = "<html><body>Hello</body></html>"
        handler.send_html(html_content)
        handler.send_response.assert_called_once_with(200)
        handler.send_header.assert_called_once_with("Content-Type", "text/html")
        handler.end_headers.assert_called_once()
        handler.wfile.write.assert_called_once_with(html_content.encode())

    def test_send_html_empty_string(self, deq_server):
        """send_html with empty string."""
        handler = create_test_handler(deq_server)
        handler.send_html("")
        handler.wfile.write.assert_called_once_with(b"")


class TestSendFile:
    """Test send_file method."""

    def test_send_file_string_content_with_cache(self, deq_server):
        """send_file with string content and cache enabled."""
        handler = create_test_handler(deq_server)
        content = "file content"
        content_type = "text/plain"
        handler.send_file(content, content_type, cache=True)
        handler.send_response.assert_called_once_with(200)
        handler.send_header.assert_has_calls(
            [
                call("Content-Type", content_type),
                call("Cache-Control", "public, max-age=31536000"),
            ],
            any_order=True,
        )
        handler.end_headers.assert_called_once()
        handler.wfile.write.assert_called_once_with(content.encode())

    def test_send_file_bytes_content_with_cache(self, deq_server):
        """send_file with bytes content and cache enabled."""
        handler = create_test_handler(deq_server)
        content = b"binary data"
        content_type = "application/octet-stream"
        handler.send_file(content, content_type, cache=True)
        handler.send_response.assert_called_once_with(200)
        handler.send_header.assert_has_calls(
            [
                call("Content-Type", content_type),
                call("Cache-Control", "public, max-age=31536000"),
            ],
            any_order=True,
        )
        handler.end_headers.assert_called_once()
        handler.wfile.write.assert_called_once_with(content)

    def test_send_file_string_content_no_cache(self, deq_server):
        """send_file with string content and cache disabled."""
        handler = create_test_handler(deq_server)
        content = "no cache"
        content_type = "text/plain"
        handler.send_file(content, content_type, cache=False)
        handler.send_response.assert_called_once_with(200)
        handler.send_header.assert_called_once_with("Content-Type", content_type)
        # Cache-Control header should NOT be added
        cache_calls = [
            c for c in handler.send_header.call_args_list if "Cache-Control" in c[0]
        ]
        assert len(cache_calls) == 0
        handler.end_headers.assert_called_once()
        handler.wfile.write.assert_called_once_with(content.encode())

    def test_send_file_bytes_content_no_cache(self, deq_server):
        """send_file with bytes content and cache disabled."""
        handler = create_test_handler(deq_server)
        content = b"no cache binary"
        content_type = "image/png"
        handler.send_file(content, content_type, cache=False)
        handler.send_response.assert_called_once_with(200)
        handler.send_header.assert_called_once_with("Content-Type", content_type)
        handler.end_headers.assert_called_once()
        handler.wfile.write.assert_called_once_with(content)

    def test_send_file_special_content_types(self, deq_server):
        """send_file with various content types (cache disabled)."""
        handler = create_test_handler(deq_server)
        test_cases = [
            ("application/json", "json"),
            ("text/css", "css"),
            ("application/javascript", "js"),
            ("image/svg+xml", "<svg></svg>"),
        ]
        for content_type, content_str in test_cases:
            handler.send_response.reset_mock()
            handler.send_header.reset_mock()
            handler.end_headers.reset_mock()
            handler.wfile.write.reset_mock()
            handler.send_file(content_str, content_type, cache=False)
            handler.send_header.assert_called_once_with("Content-Type", content_type)
            handler.wfile.write.assert_called_once_with(content_str.encode())

    def test_send_file_cache_header_only_when_cache_true(self, deq_server):
        """Ensure Cache-Control header is only sent when cache=True."""
        handler = create_test_handler(deq_server)
        # cache=True
        handler.send_file("test", "text/plain", cache=True)
        cache_calls = [
            c for c in handler.send_header.call_args_list if "Cache-Control" in c[0]
        ]
        assert len(cache_calls) == 1
        # cache=False
        handler.send_response.reset_mock()
        handler.send_header.reset_mock()
        handler.end_headers.reset_mock()
        handler.wfile.write.reset_mock()
        handler.send_file("test", "text/plain", cache=False)
        cache_calls = [
            c for c in handler.send_header.call_args_list if "Cache-Control" in c[0]
        ]
        assert len(cache_calls) == 0
