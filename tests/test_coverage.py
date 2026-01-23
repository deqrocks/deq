"""
Additional coverage tests for server.py.
"""

import pytest


def test_html_page(deq_server):
    """Call get_html_page to cover its massive string."""
    html = deq_server.get_html_page()
    assert isinstance(html, str)
    assert len(html) > 1000
    # Ensure it contains expected tags
    assert "<!DOCTYPE html>" in html
    assert "</html>" in html


def test_login_page(deq_server):
    """Call get_login_page."""
    html = deq_server.get_login_page()
    assert isinstance(html, str)
    assert "<!DOCTYPE html>" in html


def test_manifest_json(deq_server):
    """Call get_manifest_json."""
    manifest = deq_server.get_manifest_json()
    import json

    data = json.loads(manifest)
    assert data["name"] == "DeQ"


def test_icon_svg(deq_server):
    """Call get_icon_svg."""
    svg = deq_server.get_icon_svg()
    assert isinstance(svg, str)
    assert "<svg" in svg


def test_main_function(deq_server, monkeypatch):
    """Test main function with mocked argument parsing and HTTPServer."""
    import argparse
    import sys
    from unittest.mock import MagicMock, patch

    # Mock argparse to avoid actually starting server
    with patch.object(deq_server, "HTTPServer") as mock_server:
        mock_instance = MagicMock()
        # Make serve_forever raise KeyboardInterrupt to trigger shutdown
        mock_instance.serve_forever.side_effect = KeyboardInterrupt()
        mock_server.return_value = mock_instance
        with patch.object(deq_server, "task_scheduler") as mock_scheduler:
            with patch.object(sys, "argv", ["server.py", "--port", "5050"]):
                deq_server.main()
            mock_scheduler.start.assert_called_once()
            mock_scheduler.stop.assert_called_once()
            mock_instance.serve_forever.assert_called_once()
            mock_instance.shutdown.assert_called_once()


def test_request_handler_instantiation(deq_server):
    """Instantiate RequestHandler to cover its class definition."""
    from unittest.mock import Mock, patch

    mock_server = Mock()
    mock_request = Mock()
    mock_client_address = ("127.0.0.1", 12345)

    # Patch the handle_one_request method to avoid I/O errors
    with patch.object(deq_server.RequestHandler, "handle_one_request"):
        # Also mock rfile to avoid readline errors
        mock_request.makefile.return_value.readline.return_value = b"GET / HTTP/1.1\r\n"
        handler = deq_server.RequestHandler(
            mock_request, mock_client_address, mock_server
        )
        # Verify some attributes
        assert handler.server is mock_server
        assert handler.request is mock_request
        assert handler.client_address == mock_client_address


def test_task_scheduler_class(deq_server):
    """Create TaskScheduler instance and call some methods."""
    scheduler = deq_server.TaskScheduler()
    # Start and stop
    scheduler.start()
    scheduler.stop()
    # Check correct attributes exist
    assert hasattr(scheduler, "running")
    assert hasattr(scheduler, "thread")


def test_get_path_size_local(deq_server):
    """Test get_path_size for local host."""
    from unittest.mock import patch, MagicMock

    device = {"is_host": True}
    path = "/test/path"

    with patch("deq.server.subprocess.run") as mock_run:
        # Test successful case
        mock_run.return_value = MagicMock(returncode=0, stdout="1234567\n")
        result = deq_server.get_path_size(device, path)
        assert result == 1234567

        # Test error case (non-zero return code)
        mock_run.return_value = MagicMock(returncode=1, stdout="")
        result = deq_server.get_path_size(device, path)
        assert result is None

        # Test error case (empty stdout)
        mock_run.return_value = MagicMock(returncode=0, stdout="")
        result = deq_server.get_path_size(device, path)
        assert result is None


# Add more tests as needed
