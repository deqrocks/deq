"""
Pytest fixtures for DeQ server tests.
"""

import os
import sys
import tempfile
import shutil
import pytest

# Global variable for imported server module
_server_module = None
_server_module_imported = False


def _import_server_module():
    """Import deq.server with patched os.makedirs."""
    global _server_module, _server_module_imported
    if _server_module_imported:
        return _server_module
    # Add src directory to sys.path
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../src"))
    from unittest.mock import patch

    with patch("os.makedirs") as mock_makedirs:
        mock_makedirs.return_value = None
        import deq.server

        _server_module = deq.server
    _server_module_imported = True
    return _server_module


@pytest.fixture(scope="session")
def mock_data_dir():
    """
    Create a temporary directory for DATA_DIR.
    """
    tmpdir = tempfile.mkdtemp(prefix="deq_test_")
    yield tmpdir
    shutil.rmtree(tmpdir, ignore_errors=True)


@pytest.fixture(scope="session")
def patched_server_module(mock_data_dir):
    """
    Return the server module with constants patched to temporary directory.
    The module is imported lazily with patched os.makedirs.
    """
    global _server_module
    # Import the module (lazy, with patching)
    if _server_module is None:
        _server_module = _import_server_module()

    # Patch the constants to point to our temporary directory
    _server_module.DATA_DIR = mock_data_dir
    _server_module.CONFIG_FILE = os.path.join(mock_data_dir, "config.json")
    _server_module.PASSWORD_FILE = os.path.join(mock_data_dir, ".password")
    _server_module.SESSION_SECRET_FILE = os.path.join(mock_data_dir, ".session_secret")
    _server_module.SCRIPTS_DIR = os.path.join(mock_data_dir, "scripts")
    _server_module.TASK_LOGS_DIR = os.path.join(mock_data_dir, "task-logs")

    # Ensure directories exist
    os.makedirs(mock_data_dir, exist_ok=True)
    os.makedirs(os.path.join(mock_data_dir, "scripts"), exist_ok=True)
    os.makedirs(os.path.join(mock_data_dir, "task-logs"), exist_ok=True)

    return _server_module


@pytest.fixture
def deq_server(patched_server_module):
    """
    Return the server module and reset its global mutable state before each test.
    """
    # Reset global mutable state
    patched_server_module.transfer_jobs.clear()
    patched_server_module.device_status_cache.clear()
    patched_server_module.refresh_in_progress.clear()
    # Reset CONFIG to empty (will be loaded from file if needed)
    # We'll leave CONFIG as is; tests can write config file and call load_config.
    return patched_server_module


@pytest.fixture
def mock_config(deq_server):
    """Write a default config file and load it."""
    config = {
        "settings": {
            "theme": "dark",
            "text_color": "#e0e0e0",
            "accent_color": "#2ed573",
        },
        "links": [],
        "quick_actions": [],
        "devices": [],
        "tasks": [],
    }
    with open(deq_server.CONFIG_FILE, "w") as f:
        import json

        json.dump(config, f)
    deq_server.CONFIG = deq_server.load_config()
    return config


# Provide monkeypatch_session for session-scoped fixtures (pytest >= 3.0)
@pytest.fixture(scope="session")
def monkeypatch_session():
    from _pytest.monkeypatch import MonkeyPatch

    mp = MonkeyPatch()
    yield mp
    mp.undo()


# Hook to skip elevated tests when not root
def pytest_collection_modifyitems(config, items):
    """Skip tests marked 'elevated' if not running as root."""
    # If user explicitly asked for elevated tests, don't skip
    marker_expr = config.getoption("-m")
    if marker_expr and "elevated" in marker_expr:
        return

    import os

    # Allow environment variable to force run elevated tests
    if os.environ.get("RUN_ELEVATED") == "1":
        return

    skip_elevated = pytest.mark.skip(reason="Test requires root (sudo) privileges")
    for item in items:
        if item.get_closest_marker("elevated") and os.geteuid() != 0:
            item.add_marker(skip_elevated)
