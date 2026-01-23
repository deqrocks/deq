"""
Tests for pure functions in server.py that have minimal dependencies.
These tests should increase coverage quickly with minimal mocking.
"""

import os
import json
import pytest
from unittest.mock import patch, mock_open, MagicMock, call, ANY


class TestPureFunctions:
    """Test pure utility functions."""

    def test_format_size(self, deq_server):
        """Test format_size function."""
        # Test various byte sizes
        assert deq_server.format_size(0) == "0 B"
        assert deq_server.format_size(512) == "512 B"
        assert deq_server.format_size(1023) == "1023 B"
        assert deq_server.format_size(1024) == "1.0 KB"
        assert deq_server.format_size(1024 * 1024) == "1.0 MB"
        assert deq_server.format_size(1024 * 1024 * 1024) == "1.0 GB"
        assert deq_server.format_size(1024 * 1024 * 1024 * 1024) == "1.0 TB"
        # Test with decimal places
        assert deq_server.format_size(1500) == "1.5 KB"
        assert deq_server.format_size(1500000) == "1.4 MB"
        # Edge cases
        assert deq_server.format_size(1024 * 1024 * 1024 * 1024 * 5) == "5.0 TB"
        # Negative bytes? Not expected but handle
        assert deq_server.format_size(-1024) == "-1024 B"

    @pytest.mark.skip(reason="parse_size function not found in current code")
    def test_parse_size(self, deq_server):
        """Test parse_size function."""
        # Valid suffixes
        assert deq_server.parse_size("1024") == 1024
        assert deq_server.parse_size("1K") == 1024
        assert deq_server.parse_size("2K") == 2048
        assert deq_server.parse_size("1M") == 1048576
        assert deq_server.parse_size("1G") == 1073741824
        assert deq_server.parse_size("1T") == 1099511627776
        # Case-insensitive
        assert deq_server.parse_size("1k") == 1024
        assert deq_server.parse_size("1m") == 1048576
        # With spaces
        assert deq_server.parse_size(" 2 K ") == 2048
        # Decimal
        assert deq_server.parse_size("1.5K") == 1536
        assert deq_server.parse_size("0.5M") == 524288
        # Invalid input returns None
        assert deq_server.parse_size("abc") is None
        assert deq_server.parse_size("") is None
        assert deq_server.parse_size(None) is None
        # Edge: overflow? Python int can handle large numbers
        assert deq_server.parse_size("1000000T") == 1000000 * 1099511627776

    def test_is_auth_enabled(self, deq_server):
        """Test is_auth_enabled function."""
        with patch("os.path.exists") as mock_exists:
            mock_exists.return_value = True
            assert deq_server.is_auth_enabled() == True
        with patch("os.path.exists") as mock_exists:
            mock_exists.return_value = False
            assert deq_server.is_auth_enabled() == False

    def test_get_session_secret(self, deq_server):
        """Test get_session_secret function."""
        # Mock file read
        secret_content = "test-secret-key"
        with patch("builtins.open", mock_open(read_data=secret_content)):
            with patch("os.path.exists", return_value=True):
                secret = deq_server.get_session_secret()
                assert secret == secret_content
        # File does not exist -> generate random secret and save
        with patch("os.path.exists", return_value=False):
            with patch("deq.server.secrets.token_hex", return_value="randomhex"):
                with patch("builtins.open", mock_open()) as mock_file:
                    with patch("os.chmod") as mock_chmod:
                        secret = deq_server.get_session_secret()
                        assert secret == "randomhex"
                        # Ensure file was written
                        mock_file.assert_called()
                        # Ensure chmod called with correct file path
                        mock_chmod.assert_called_once_with(
                            deq_server.SESSION_SECRET_FILE, 0o600
                        )

    def test_create_and_verify_session_token(self, deq_server):
        """Test create_session_token and verify_session_token."""
        secret = "test-secret"
        # Mock get_session_secret to return our secret
        with patch("deq.server.get_session_secret", return_value=secret):
            # Mock time.time for deterministic timestamp
            with patch("deq.server.time.time", return_value=1234567890):
                token = deq_server.create_session_token()
                assert isinstance(token, str)
                # Token should be timestamp:signature
                assert token.count(":") == 1
                timestamp, signature = token.split(":")
                assert timestamp == "1234567890"
                # Verify valid token
                assert deq_server.verify_session_token(token) == True
                # Verify invalid token
                assert deq_server.verify_session_token("invalid") == False
                # Verify malformed token
                assert deq_server.verify_session_token("abc:def:ghi") == False
                # Verify with wrong secret (different get_session_secret)
                with patch("deq.server.get_session_secret", return_value="wrong"):
                    assert deq_server.verify_session_token(token) == False

    def test_verify_password(self, deq_server):
        """Test verify_password function."""
        # Mock is_auth_enabled to return True (password file exists)
        with patch("os.path.exists", return_value=True):
            # Mock file content: salt:key hex
            salt_hex = "aaaaaaaa"
            key_hex = "bbbbbbbb"
            file_content = f"{salt_hex}:{key_hex}"
            with patch("builtins.open", mock_open(read_data=file_content)):
                # Mock hashlib.scrypt to return known key bytes
                with patch("hashlib.scrypt") as mock_scrypt:
                    # Return bytes matching key_hex
                    mock_scrypt.return_value = bytes.fromhex(key_hex)
                    # Mock secrets.compare_digest to return True
                    with patch(
                        "secrets.compare_digest", return_value=True
                    ) as mock_compare:
                        assert deq_server.verify_password("password") == True
                        mock_compare.assert_called_once()
                        # Ensure scrypt called with correct salt
                        mock_scrypt.assert_called_once()
                # Test wrong password: compare_digest returns False
                with patch("hashlib.scrypt") as mock_scrypt:
                    mock_scrypt.return_value = bytes.fromhex("cccccccc")
                    with patch("secrets.compare_digest", return_value=False):
                        assert deq_server.verify_password("wrong") == False
        # No auth enabled (password file does not exist) -> returns True regardless
        with patch("os.path.exists", return_value=False):
            assert deq_server.verify_password("anything") == True
        # File read error -> returns False
        with patch("os.path.exists", return_value=True):
            with patch("builtins.open", side_effect=Exception):
                assert deq_server.verify_password("anything") == False

    def test_load_config(self, deq_server):
        """Test load_config function."""
        # When config file exists, merge with defaults and ensure host device
        config_data = {"auth": {"enabled": True}}
        expected = deq_server.DEFAULT_CONFIG.copy()
        expected.update(config_data)  # auth added
        # Ensure host device inserted (since no device with is_host)
        if not any(d.get("is_host") for d in expected.get("devices", [])):
            expected["devices"].insert(0, deq_server.DEFAULT_HOST_DEVICE.copy())
        with patch("builtins.open", mock_open(read_data=json.dumps(config_data))):
            with patch("os.path.exists", return_value=True):
                config = deq_server.load_config()
                assert config == expected
        # File does not exist -> returns DEFAULT_CONFIG with empty devices list plus host device
        with patch("os.path.exists", return_value=False):
            config = deq_server.load_config()
            expected = deq_server.DEFAULT_CONFIG.copy()
            expected["devices"] = []
            expected["devices"].insert(0, deq_server.DEFAULT_HOST_DEVICE.copy())
            assert config == expected
        # JSON decode error raises JSONDecodeError
        with patch("builtins.open", mock_open(read_data="invalid json")):
            with patch("os.path.exists", return_value=True):
                with pytest.raises(json.JSONDecodeError):
                    deq_server.load_config()

    def test_save_config(self, deq_server):
        """Test save_config function."""
        config_data = {"auth": {"enabled": True}}
        with patch("builtins.open", mock_open()) as mock_file:
            deq_server.save_config(config_data)
            mock_file.assert_called_once_with(deq_server.CONFIG_FILE, "w")
            handle = mock_file()
            # Collect all writes (json.dump with indent may write multiple chunks)
            written = "".join(call[0][0] for call in handle.write.call_args_list)
            assert json.loads(written) == config_data

    def test_is_valid_container_name(self, deq_server):
        """Test is_valid_container_name function."""
        # Valid names
        assert deq_server.is_valid_container_name("test") == True
        assert deq_server.is_valid_container_name("test123") == True
        assert deq_server.is_valid_container_name("test-123") == True
        assert deq_server.is_valid_container_name("test_123") == True
        assert deq_server.is_valid_container_name("test.123") == True
        assert deq_server.is_valid_container_name("a") == True
        # Invalid names
        assert deq_server.is_valid_container_name("") == False
        assert deq_server.is_valid_container_name(None) == False
        assert deq_server.is_valid_container_name("Test@") == False
        assert deq_server.is_valid_container_name("test!") == False
        assert deq_server.is_valid_container_name("test/") == False
        assert deq_server.is_valid_container_name("test\\") == False
        # Length > 128
        long_name = "a" * 129
        assert deq_server.is_valid_container_name(long_name) == False
        # Length exactly 128
        long_name = "a" * 128
        assert deq_server.is_valid_container_name(long_name) == True
        # First character must be alphanumeric
        assert deq_server.is_valid_container_name("-test") == False
        assert deq_server.is_valid_container_name("_test") == False
        assert deq_server.is_valid_container_name(".test") == False

    def test_calculate_next_run(self, deq_server):
        """Test calculate_next_run function."""
        from datetime import datetime, timedelta

        # Mock datetime.now to a fixed time for deterministic tests
        fixed_now = datetime(2025, 1, 23, 12, 30, 0)  # Thursday (weekday 3)
        with patch("deq.server.datetime") as mock_dt:
            mock_dt.now.return_value = fixed_now
            mock_dt.side_effect = lambda *args, **kw: datetime(*args, **kw)

            # Task disabled
            task = {"enabled": False}
            assert deq_server.calculate_next_run(task) is None

            # No schedule defaults to daily at 03:00
            task = {"enabled": True}
            # Since now is 12:30, next run is today at 03:00? Actually 03:00 already passed, so tomorrow
            # Let's compute expected: replace hour=3, minute=0, second=0, microsecond=0
            expected = datetime(2025, 1, 24, 3, 0, 0).isoformat()
            assert deq_server.calculate_next_run(task) == expected

            # Hourly schedule
            task = {"enabled": True, "schedule": {"type": "hourly", "time": "15:30"}}
            # Next run at minute 30 of next hour (since 12:30 < 12:30? Actually 12:30 already passed minute 30? Wait hourly runs at minute 30 each hour.
            # If now is 12:30, next run should be 13:30 (since 12:30 <= now? Actually we replace minute=30, second=0, microsecond=0. That gives 12:30:00 which is <= now? Yes equal, so add 1 hour.
            expected = datetime(2025, 1, 23, 13, 30, 0).isoformat()
            assert deq_server.calculate_next_run(task) == expected

            # Daily schedule with time
            task = {"enabled": True, "schedule": {"type": "daily", "time": "18:45"}}
            # Next run today at 18:45 (since 12:30 < 18:45)
            expected = datetime(2025, 1, 23, 18, 45, 0).isoformat()
            assert deq_server.calculate_next_run(task) == expected

            # Daily schedule with time already passed
            task = {"enabled": True, "schedule": {"type": "daily", "time": "10:15"}}
            # Next run tomorrow at 10:15
            expected = datetime(2025, 1, 24, 10, 15, 0).isoformat()
            assert deq_server.calculate_next_run(task) == expected

            # Weekly schedule (day 0 = Sunday, but Python weekday Monday=0)
            task = {
                "enabled": True,
                "schedule": {"type": "weekly", "day": 0, "time": "09:00"},
            }
            # Today is Thursday (weekday 3), Sunday is day 6 (Python weekday Sunday=6)
            # days_ahead = 6 - 3 = 3, since days_ahead > 0, next_run = next Sunday at 09:00
            expected = datetime(2025, 1, 26, 9, 0, 0).isoformat()
            assert deq_server.calculate_next_run(task) == expected

            # Weekly schedule with day already passed this week
            task = {
                "enabled": True,
                "schedule": {"type": "weekly", "day": 2, "time": "09:00"},
            }  # Tuesday (Python weekday 1)
            # Tuesday already passed this week (Jan 21), so next Tuesday is Jan 28
            expected = datetime(2025, 1, 28, 9, 0, 0).isoformat()
            assert deq_server.calculate_next_run(task) == expected

            # Monthly schedule with date 1
            task = {
                "enabled": True,
                "schedule": {"type": "monthly", "date": 1, "time": "12:00"},
            }
            # Today is Jan 23, date 1 already passed, so next month Feb 1 at 12:00
            expected = datetime(2025, 2, 1, 12, 0, 0).isoformat()
            assert deq_server.calculate_next_run(task) == expected

            # Monthly schedule with date later this month
            task = {
                "enabled": True,
                "schedule": {"type": "monthly", "date": 25, "time": "12:00"},
            }
            # Jan 25 at 12:00 (still future)
            expected = datetime(2025, 1, 25, 12, 0, 0).isoformat()
            assert deq_server.calculate_next_run(task) == expected

            # Monthly schedule with date 30 (valid in January)
            task = {
                "enabled": True,
                "schedule": {"type": "monthly", "date": 30, "time": "12:00"},
            }
            # Jan 30 is after now, so returns Jan 30
            expected = datetime(2025, 1, 30, 12, 0, 0).isoformat()
            assert deq_server.calculate_next_run(task) == expected

            # Edge: invalid schedule type returns None
            task = {"enabled": True, "schedule": {"type": "invalid"}}
            assert deq_server.calculate_next_run(task) is None

            # Test invalid date skipping (Feb 30)
            with patch("deq.server.datetime") as mock_dt_feb:
                feb_now = datetime(2025, 2, 1, 12, 30, 0)
                mock_dt_feb.now.return_value = feb_now
                mock_dt_feb.side_effect = lambda *args, **kw: datetime(*args, **kw)
                task = {
                    "enabled": True,
                    "schedule": {"type": "monthly", "date": 30, "time": "12:00"},
                }
                # Feb 30 is invalid, skip to March 30
                expected = datetime(2025, 3, 30, 12, 0, 0).isoformat()
                assert deq_server.calculate_next_run(task) == expected

    def test_get_login_page(self, deq_server):
        """Test get_login_page function."""
        html = deq_server.get_login_page()
        assert isinstance(html, str)
        assert "<!DOCTYPE html>" in html
        assert "<title>DeQ</title>" in html
        assert "background: #000" in html

    def test_get_html_page(self, deq_server):
        """Test get_html_page function."""
        html = deq_server.get_html_page()
        assert isinstance(html, str)
        assert "<!DOCTYPE html>" in html
        assert "<title>DeQ</title>" in html
        assert "manifest" in html

    def test_get_manifest_json(self, deq_server):
        """Test get_manifest_json function."""
        import json as json_module

        manifest = deq_server.get_manifest_json()
        assert isinstance(manifest, str)
        parsed = json_module.loads(manifest)
        assert parsed["name"] == "DeQ"
        assert parsed["short_name"] == "DeQ"
        assert parsed["display"] == "standalone"

    def test_get_icon_svg(self, deq_server):
        """Test get_icon_svg function."""
        svg = deq_server.get_icon_svg()
        assert isinstance(svg, str)
        assert "<svg xmlns=" in svg
        assert 'viewBox="0 0 512 512"' in svg

    def test_get_default_ssh_user(self, deq_server):
        """Test get_default_ssh_user function."""
        # Mock os.listdir to return some home directories
        with patch("os.listdir") as mock_listdir:
            mock_listdir.return_value = ["alice", "bob", ".hidden"]
            # Mock os.path.isdir to return True for all (including hidden)
            with patch("os.path.isdir") as mock_isdir:

                def isdir_side_effect(path):
                    # Only return True for directories we want to consider
                    # The function calls isdir on "/home/alice", "/home/bob", "/home/.hidden"
                    return True

                mock_isdir.side_effect = isdir_side_effect
                user = deq_server.get_default_ssh_user()
                # Should return first alphabetical non-hidden directory
                assert user == "alice"
        # No valid home directories (hidden only) -> root
        with patch("os.listdir") as mock_listdir:
            mock_listdir.return_value = [".hidden", ".cache"]
            with patch("os.path.isdir", return_value=True):
                user = deq_server.get_default_ssh_user()
                assert user == "root"
        # Exception -> root
        with patch("os.listdir", side_effect=PermissionError):
            user = deq_server.get_default_ssh_user()
            assert user == "root"
        # Empty list -> root
        with patch("os.listdir", return_value=[]):
            user = deq_server.get_default_ssh_user()
            assert user == "root"

    def test_get_config_with_defaults(self, deq_server):
        """Test get_config_with_defaults function."""
        # Mock CONFIG global
        original_config = deq_server.CONFIG
        try:
            deq_server.CONFIG = {
                "devices": [{"id": "dev1", "alerts": {"cpu": True}}, {"id": "dev2"}]
            }
            result = deq_server.get_config_with_defaults()
            assert "devices" in result
            assert len(result["devices"]) == 2
            # Check that alerts are merged with defaults
            dev1 = result["devices"][0]
            assert "cpu" in dev1["alerts"]
            # Ensure default alerts are present
            assert "online" in dev1["alerts"]
            assert "ram" in dev1["alerts"]
            assert "cpu_temp" in dev1["alerts"]
            assert "disk_usage" in dev1["alerts"]
            assert "disk_temp" in dev1["alerts"]
            assert "smart" in dev1["alerts"]
            # Second device should have default alerts
            dev2 = result["devices"][1]
            assert dev2["alerts"] == deq_server.DEFAULT_ALERTS
        finally:
            deq_server.CONFIG = original_config

    def test_get_cached_status(self, deq_server):
        """Test get_cached_status function."""
        # Initially empty
        assert deq_server.get_cached_status("test") is None
        # Set status via set_cached_status
        deq_server.set_cached_status("test", {"online": True})
        # Retrieve
        status = deq_server.get_cached_status("test")
        assert status == {"online": True}
        # Different device ID
        assert deq_server.get_cached_status("other") is None

    def test_set_cached_status(self, deq_server):
        """Test set_cached_status function."""
        # Ensure cache is empty
        deq_server.device_status_cache.clear()
        deq_server.set_cached_status("dev1", {"online": True})
        assert deq_server.device_status_cache["dev1"] == {"online": True}
        # Update existing
        deq_server.set_cached_status("dev1", {"online": False})
        assert deq_server.device_status_cache["dev1"] == {"online": False}
        # Thread safety is not tested here (lock is internal)

    def test_get_path_size(self, deq_server):
        """Test get_path_size function."""
        # Local host success
        device = {"is_host": True}
        path = "/some/path"
        with patch("deq.server.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="12345\n")
            size = deq_server.get_path_size(device, path)
            assert size == 12345
            # Verify command
            mock_run.assert_called_once()
            call_args = mock_run.call_args[0]
            assert "du -sb" in call_args[0]

        # Remote host success
        device = {
            "is_host": False,
            "ssh": {"user": "testuser", "port": 22},
            "ip": "192.168.1.1",
        }
        with patch("deq.server.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="67890\n")
            size = deq_server.get_path_size(device, path)
            assert size == 67890
            # Verify SSH command
            mock_run.assert_called_once()
            call_args = mock_run.call_args[0]
            assert call_args[0][0] == "ssh"
            assert "testuser@192.168.1.1" in call_args[0]

        # Command failure (returncode != 0)
        with patch("deq.server.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="")
            size = deq_server.get_path_size(device, path)
            assert size is None

        # Parse error (invalid output)
        with patch("deq.server.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="not-a-number")
            size = deq_server.get_path_size(device, path)
            assert size is None

        # Exception handling
        with patch("deq.server.subprocess.run", side_effect=Exception("error")):
            size = deq_server.get_path_size(device, path)
            assert size is None

        # Missing user for remote host
        device_no_user = {"is_host": False, "ssh": {}, "ip": "192.168.1.1"}
        size = deq_server.get_path_size(device_no_user, path)
        assert size is None

    def test_get_free_space(self, deq_server):
        """Test get_free_space function."""
        # Local host free space (shutil.disk_usage)
        device = {"is_host": True}
        path = "/some/path"
        with patch("shutil.disk_usage") as mock_disk:
            mock_disk.return_value = MagicMock(free=1234567890)
            free = deq_server.get_free_space(device, path)
            assert free == 1234567890
            mock_disk.assert_called_once_with(path)

        # Remote host free space via df
        device = {
            "is_host": False,
            "ssh": {"user": "testuser", "port": 22},
            "ip": "192.168.1.1",
        }
        with patch("deq.server.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="987654321\n")
            free = deq_server.get_free_space(device, path)
            assert free == 987654321
            mock_run.assert_called_once()
            call_args = mock_run.call_args[0]
            assert call_args[0][0] == "ssh"
            assert "df -B1" in " ".join(call_args[0])

        # df command failure
        with patch("deq.server.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="")
            free = deq_server.get_free_space(device, path)
            assert free is None

        # Parse error
        with patch("deq.server.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="not-a-number")
            free = deq_server.get_free_space(device, path)
            assert free is None

        # Exception handling
        with patch("deq.server.subprocess.run", side_effect=Exception("error")):
            free = deq_server.get_free_space(device, path)
            assert free is None

        # Missing user for remote host
        device_no_user = {"is_host": False, "ssh": {}, "ip": "192.168.1.1"}
        free = deq_server.get_free_space(device_no_user, path)
        assert free is None

    def test_ensure_dirs(self, deq_server):
        """Test ensure_dirs function."""
        with patch("os.makedirs") as mock_makedirs:
            deq_server.ensure_dirs()
            # Should be called with each directory and exist_ok=True
            expected_calls = [
                call(deq_server.DATA_DIR, exist_ok=True),
                call(deq_server.SCRIPTS_DIR, exist_ok=True),
                call(deq_server.TASK_LOGS_DIR, exist_ok=True),
            ]
            mock_makedirs.assert_has_calls(expected_calls, any_order=True)
            assert mock_makedirs.call_count == 3

        # Test permission error (should raise due to lack of catch)
        with patch("os.makedirs", side_effect=PermissionError):
            with pytest.raises(PermissionError):
                deq_server.ensure_dirs()

    def test_refresh_device_status_async(self, deq_server):
        """Test refresh_device_status_async function."""
        device = {"id": "dev1", "is_host": True}
        # Mock threading.Thread to capture target
        with patch("threading.Thread") as mock_thread_class:
            mock_thread = MagicMock()
            mock_thread_class.return_value = mock_thread
            deq_server.refresh_device_status_async(device)
            # Verify thread created with correct target
            mock_thread_class.assert_called_once_with(target=ANY, daemon=True)
            # Verify thread started
            mock_thread.start.assert_called_once()
            # Verify refresh_in_progress set
            assert "dev1" in deq_server.refresh_in_progress
            # Execute target to verify behavior
            target_func = mock_thread_class.call_args[1]["target"]
            # Mock dependencies inside target
            with patch("deq.server.get_all_container_statuses") as mock_get_containers:
                with patch("deq.server.get_local_stats") as mock_local_stats:
                    with patch("deq.server.set_cached_status") as mock_set_cache:
                        mock_get_containers.return_value = []
                        mock_local_stats.return_value = {"cpu": 10}
                        target_func()
                        mock_set_cache.assert_called_once_with(
                            "dev1",
                            {"online": True, "stats": {"cpu": 10}, "containers": []},
                        )
                        assert "dev1" not in deq_server.refresh_in_progress

        # Remote device with ping
        device = {
            "id": "dev2",
            "is_host": False,
            "ip": "192.168.1.1",
            "ssh": {"user": "user"},
        }
        with patch("threading.Thread") as mock_thread_class:
            mock_thread = MagicMock()
            mock_thread_class.return_value = mock_thread
            deq_server.refresh_device_status_async(device)
            target_func = mock_thread_class.call_args[1]["target"]
            with patch("deq.server.get_all_container_statuses") as mock_get_containers:
                with patch("deq.server.ping_host") as mock_ping:
                    with patch("deq.server.get_remote_stats") as mock_remote_stats:
                        with patch("deq.server.set_cached_status") as mock_set_cache:
                            mock_get_containers.return_value = []
                            mock_ping.return_value = True
                            mock_remote_stats.return_value = {"cpu": 20}
                            target_func()
                            mock_set_cache.assert_called_once_with(
                                "dev2",
                                {
                                    "online": True,
                                    "stats": {"cpu": 20},
                                    "containers": [],
                                },
                            )

        # Ensure refresh_in_progress is cleared even on exception
        with patch("threading.Thread") as mock_thread_class:
            mock_thread = MagicMock()
            mock_thread_class.return_value = mock_thread
            deq_server.refresh_device_status_async(device)
            target_func = mock_thread_class.call_args[1]["target"]
            with patch("deq.server.get_all_container_statuses", side_effect=Exception):
                with pytest.raises(Exception):
                    target_func()
                # Verify refresh_in_progress cleared by finally block
                assert "dev2" not in deq_server.refresh_in_progress

    def test_get_disk_smart_info(self, deq_server):
        """Test get_disk_smart_info function."""
        # Mock lsblk output with disks
        with patch("deq.server.subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout="sda disk\nsdb disk\n"),
                MagicMock(returncode=0, stdout="SMART PASSED\nTemperature - 45 C"),
                MagicMock(returncode=0, stdout="SMART FAILED\nTemperature - 50 C"),
            ]
            disks = deq_server.get_disk_smart_info()
            assert "sda" in disks
            assert "sdb" in disks
            assert disks["sda"]["smart"] == "ok"
            assert disks["sda"]["temp"] == 45
            assert disks["sdb"]["smart"] == "failed"
            assert disks["sdb"]["temp"] == 50

        # lsblk failure -> empty dict
        with patch("deq.server.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="")
            disks = deq_server.get_disk_smart_info()
            assert disks == {}

        # smartctl not installed (returncode != 0)
        with patch("deq.server.subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout="sda disk\n"),
                MagicMock(returncode=1, stdout=""),
            ]
            disks = deq_server.get_disk_smart_info()
            assert disks["sda"]["smart"] is None
            assert disks["sda"]["temp"] is None

        # Exception handling
        with patch("deq.server.subprocess.run", side_effect=Exception):
            disks = deq_server.get_disk_smart_info()
            assert disks == {}

    def test_get_container_stats(self, deq_server):
        """Test get_container_stats function."""
        # Docker running with containers
        with patch("deq.server.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="container1:10.5%:20.3%\ncontainer2:5.0%:15.0%\n"
            )
            stats = deq_server.get_container_stats()
            assert "container1" in stats
            assert stats["container1"]["cpu"] == 10.5
            assert stats["container1"]["mem"] == 20.3
            assert stats["container2"]["cpu"] == 5.0
            assert stats["container2"]["mem"] == 15.0

        # Docker not running (returncode != 0)
        with patch("deq.server.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="")
            stats = deq_server.get_container_stats()
            assert stats == {}

        # Parse error (invalid line)
        with patch("deq.server.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="invalid")
            stats = deq_server.get_container_stats()
            assert stats == {}

        # Exception handling
        with patch("deq.server.subprocess.run", side_effect=Exception):
            stats = deq_server.get_container_stats()
            assert stats == {}
