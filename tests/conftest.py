"""
Pytest fixtures for DeQ server tests.
"""
import os
import sys
import tempfile
import shutil
import pytest


@pytest.fixture(scope='session')
def mock_data_dir():
    """
    Create a temporary directory for DATA_DIR.
    """
    tmpdir = tempfile.mkdtemp(prefix="deq_test_")
    yield tmpdir
    shutil.rmtree(tmpdir, ignore_errors=True)


@pytest.fixture(scope='session')
def patched_server_module(mock_data_dir, monkeypatch_session):
    """
    Import the server module with patched constants.
    This fixture is session-scoped; the module is imported once.
    """
    # Patch constants before import
    monkeypatch_session.setattr('server.DATA_DIR', mock_data_dir)
    monkeypatch_session.setattr('server.CONFIG_FILE', os.path.join(mock_data_dir, 'config.json'))
    monkeypatch_session.setattr('server.PASSWORD_FILE', os.path.join(mock_data_dir, '.password'))
    monkeypatch_session.setattr('server.SESSION_SECRET_FILE', os.path.join(mock_data_dir, '.session_secret'))
    monkeypatch_session.setattr('server.SCRIPTS_DIR', os.path.join(mock_data_dir, 'scripts'))
    monkeypatch_session.setattr('server.TASK_LOGS_DIR', os.path.join(mock_data_dir, 'task-logs'))
    
    # Ensure directories exist
    os.makedirs(mock_data_dir, exist_ok=True)
    os.makedirs(os.path.join(mock_data_dir, 'scripts'), exist_ok=True)
    os.makedirs(os.path.join(mock_data_dir, 'task-logs'), exist_ok=True)
    
    # Import server module
    import server
    return server


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
        "settings": {"theme": "dark", "text_color": "#e0e0e0", "accent_color": "#2ed573"},
        "links": [],
        "quick_actions": [],
        "devices": [],
        "tasks": []
    }
    with open(deq_server.CONFIG_FILE, 'w') as f:
        import json
        json.dump(config, f)
    deq_server.CONFIG = deq_server.load_config()
    return config


# Provide monkeypatch_session for session-scoped fixtures (pytest >= 3.0)
@pytest.fixture(scope='session')
def monkeypatch_session():
    from _pytest.monkeypatch import MonkeyPatch
    mp = MonkeyPatch()
    yield mp
    mp.undo()
