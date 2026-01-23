import shutil
import json
import os
from unittest.mock import patch, MagicMock, call


class TestRunBackupTask:
    """Test run_backup_task function."""

    def test_device_not_found(self, deq_server, mock_config):
        """Source or destination device not found in CONFIG."""
        # No devices added to CONFIG
        task = {
            "id": "task1",
            "source": {"device": "dev1", "path": "/src"},
            "dest": {"device": "dev2", "path": "/dest"},
        }
        result = deq_server.run_backup_task(task)
        assert result["success"] == False
        assert "device not found" in result["error"].lower()

    def test_path_not_specified(self, deq_server, mock_config):
        """Source or destination path not specified."""
        # Add devices
        deq_server.CONFIG["devices"].extend(
            [
                {
                    "id": "dev1",
                    "ip": "192.168.1.1",
                    "ssh": {"user": "root", "port": 22},
                    "is_host": False,
                },
                {
                    "id": "dev2",
                    "ip": "192.168.1.2",
                    "ssh": {"user": "root", "port": 22},
                    "is_host": False,
                },
            ]
        )
        # Missing source path
        task = {
            "id": "task1",
            "source": {"device": "dev1", "path": ""},
            "dest": {"device": "dev2", "path": "/dest"},
        }
        result = deq_server.run_backup_task(task)
        assert result["success"] == False
        assert "path not specified" in result["error"].lower()
        # Missing dest path
        task = {
            "id": "task1",
            "source": {"device": "dev1", "path": "/src"},
            "dest": {"device": "dev2", "path": ""},
        }
        result = deq_server.run_backup_task(task)
        assert result["success"] == False
        assert "path not specified" in result["error"].lower()

    def test_source_offline(self, deq_server, mock_config):
        """Source device offline (ping_host returns False, returns skipped)."""
        deq_server.CONFIG["devices"].extend(
            [
                {
                    "id": "dev1",
                    "ip": "192.168.1.1",
                    "ssh": {"user": "root", "port": 22},
                    "is_host": False,
                },
                {
                    "id": "dev2",
                    "ip": "192.168.1.2",
                    "ssh": {"user": "root", "port": 22},
                    "is_host": False,
                },
            ]
        )
        task = {
            "id": "task1",
            "source": {"device": "dev1", "path": "/src"},
            "dest": {"device": "dev2", "path": "/dest"},
        }
        with patch("deq.server.ping_host", return_value=False):
            result = deq_server.run_backup_task(task)
        assert result["success"] == False
        assert result.get("skipped") == True
        assert "source offline" in result["error"].lower()

    def test_source_host_backup_success(self, deq_server, mock_config):
        """Source is host (local) backup success."""
        deq_server.CONFIG["devices"].extend(
            [
                {"id": "dev1", "is_host": True},
                {
                    "id": "dev2",
                    "ip": "192.168.1.2",
                    "ssh": {"user": "root", "port": 22},
                    "is_host": False,
                },
            ]
        )
        task = {
            "id": "task1",
            "source": {"device": "dev1", "path": "/src"},
            "dest": {"device": "dev2", "path": "/dest"},
        }
        with (
            patch("deq.server.ping_host", return_value=True),
            patch("deq.server.subprocess.run") as mock_run,
            patch("deq.server.os.makedirs") as mock_makedirs,
        ):
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "Total file size: 1,234,567 bytes"
            result = deq_server.run_backup_task(task)
            mock_run.assert_called_once()
            args, kwargs = mock_run.call_args
            cmd = args[0]
            assert cmd[0] == "rsync"
            # Should have -e flag for remote destination
            assert "-e" in cmd
            # Destination remote, should have SSH
            assert "ssh" in " ".join(cmd)
            # os.makedirs not called because dest is remote
            mock_makedirs.assert_not_called()
            assert result["success"] == True
            assert result["size"] == "1MB"  # parsed size

    def test_source_remote_dest_host_backup_success(self, deq_server, mock_config):
        """Source remote, destination host backup success."""
        deq_server.CONFIG["devices"].extend(
            [
                {
                    "id": "dev1",
                    "ip": "192.168.1.1",
                    "ssh": {"user": "root", "port": 22},
                    "is_host": False,
                },
                {"id": "dev2", "is_host": True},
            ]
        )
        task = {
            "id": "task1",
            "source": {"device": "dev1", "path": "/src"},
            "dest": {"device": "dev2", "path": "/dest"},
        }
        with (
            patch("deq.server.ping_host", return_value=True),
            patch("deq.server.subprocess.run") as mock_run,
            patch("deq.server.os.makedirs") as mock_makedirs,
        ):
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "Total file size: 2,500,000 bytes"
            result = deq_server.run_backup_task(task)
            mock_run.assert_called_once()
            args, kwargs = mock_run.call_args
            cmd = args[0]
            assert cmd[0] == "rsync"
            # Should have -e flag for source remote
            assert "-e" in cmd
            # os.makedirs called for dest host
            mock_makedirs.assert_called_once_with("/dest", exist_ok=True)
            assert result["success"] == True
            assert result["size"] == "2MB"

    def test_both_remote_backup_success(self, deq_server, mock_config):
        """Both remote backup success."""
        deq_server.CONFIG["devices"].extend(
            [
                {
                    "id": "dev1",
                    "ip": "192.168.1.1",
                    "ssh": {"user": "root", "port": 22},
                    "is_host": False,
                },
                {
                    "id": "dev2",
                    "ip": "192.168.1.2",
                    "ssh": {"user": "root", "port": 22},
                    "is_host": False,
                },
            ]
        )
        task = {
            "id": "task1",
            "source": {"device": "dev1", "path": "/src"},
            "dest": {"device": "dev2", "path": "/dest"},
        }
        with (
            patch("deq.server.ping_host", return_value=True),
            patch("deq.server.subprocess.run") as mock_run,
            patch("deq.server.os.makedirs") as mock_makedirs,
        ):
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "Total file size: 9,876,543,210 bytes"
            result = deq_server.run_backup_task(task)
            mock_run.assert_called_once()
            # Should have -e flag (SSH) for both remote
            args, kwargs = mock_run.call_args
            cmd = args[0]
            assert "-e" in cmd
            # os.makedirs not called because dest remote
            mock_makedirs.assert_not_called()
            assert result["success"] == True
            assert result["size"] == "9.9GB"  # 9,876,543,210 bytes ~ 9.9 GB

    def test_rsync_failure(self, deq_server, mock_config):
        """Rsync failure (returncode non-zero)."""
        deq_server.CONFIG["devices"].extend(
            [
                {"id": "dev1", "is_host": True},
                {"id": "dev2", "is_host": True},
            ]
        )
        task = {
            "id": "task1",
            "source": {"device": "dev1", "path": "/src"},
            "dest": {"device": "dev2", "path": "/dest"},
        }
        with (
            patch("deq.server.ping_host", return_value=True),
            patch("deq.server.subprocess.run") as mock_run,
            patch("deq.server.os.makedirs") as mock_makedirs,
        ):
            mock_run.return_value.returncode = 1
            mock_run.return_value.stderr = "Permission denied"
            result = deq_server.run_backup_task(task)
            assert result["success"] == False
            assert "Permission denied" in result["error"]

    def test_rsync_timeout(self, deq_server, mock_config):
        """Rsync timeout (subprocess.TimeoutExpired)."""
        deq_server.CONFIG["devices"].extend(
            [
                {"id": "dev1", "is_host": True},
                {"id": "dev2", "is_host": True},
            ]
        )
        task = {
            "id": "task1",
            "source": {"device": "dev1", "path": "/src"},
            "dest": {"device": "dev2", "path": "/dest"},
        }
        with (
            patch("deq.server.ping_host", return_value=True),
            patch(
                "deq.server.subprocess.run",
                side_effect=deq_server.subprocess.TimeoutExpired("rsync", 3600),
            ),
            patch("deq.server.os.makedirs") as mock_makedirs,
        ):
            result = deq_server.run_backup_task(task)
            assert result["success"] == False
            assert "timeout" in result["error"].lower()

    def test_rsync_success_with_size_parsing(self, deq_server, mock_config):
        """Rsync success with size parsing (Total file size)."""
        deq_server.CONFIG["devices"].extend(
            [
                {"id": "dev1", "is_host": True},
                {"id": "dev2", "is_host": True},
            ]
        )
        task = {
            "id": "task1",
            "source": {"device": "dev1", "path": "/src"},
            "dest": {"device": "dev2", "path": "/dest"},
        }
        with (
            patch("deq.server.ping_host", return_value=True),
            patch("deq.server.subprocess.run") as mock_run,
            patch("deq.server.os.makedirs") as mock_makedirs,
        ):
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "Total file size: 5,000,000,000 bytes"
            result = deq_server.run_backup_task(task)
            assert result["success"] == True
            assert result["size"] == "5.0GB"

    def test_rsync_success_without_size_parsing(self, deq_server, mock_config):
        """Rsync success without size parsing."""
        deq_server.CONFIG["devices"].extend(
            [
                {"id": "dev1", "is_host": True},
                {"id": "dev2", "is_host": True},
            ]
        )
        task = {
            "id": "task1",
            "source": {"device": "dev1", "path": "/src"},
            "dest": {"device": "dev2", "path": "/dest"},
        }
        with (
            patch("deq.server.ping_host", return_value=True),
            patch("deq.server.subprocess.run") as mock_run,
            patch("deq.server.os.makedirs") as mock_makedirs,
        ):
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "some other output"
            result = deq_server.run_backup_task(task)
            assert result["success"] == True
            assert result["size"] == ""  # empty string when no size parsed

    def test_delete_option(self, deq_server, mock_config):
        """Delete option in task['options'] adds --delete flag."""
        deq_server.CONFIG["devices"].extend(
            [
                {"id": "dev1", "is_host": True},
                {"id": "dev2", "is_host": True},
            ]
        )
        task = {
            "id": "task1",
            "source": {"device": "dev1", "path": "/src"},
            "dest": {"device": "dev2", "path": "/dest"},
            "options": {"delete": True},
        }
        with (
            patch("deq.server.ping_host", return_value=True),
            patch("deq.server.subprocess.run") as mock_run,
            patch("deq.server.os.makedirs") as mock_makedirs,
        ):
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = ""
            result = deq_server.run_backup_task(task)
            mock_run.assert_called_once()
            args, kwargs = mock_run.call_args
            cmd = args[0]
            assert "--delete" in cmd

    def test_ssh_control_opts(self, deq_server, mock_config):
        """SSH control opts (SSH_CONTROL_STR constant) included in SSH command."""
        deq_server.CONFIG["devices"].extend(
            [
                {
                    "id": "dev1",
                    "ip": "192.168.1.1",
                    "ssh": {"user": "root", "port": 22},
                    "is_host": False,
                },
                {"id": "dev2", "is_host": True},
            ]
        )
        task = {
            "id": "task1",
            "source": {"device": "dev1", "path": "/src"},
            "dest": {"device": "dev2", "path": "/dest"},
        }
        with (
            patch("deq.server.ping_host", return_value=True),
            patch("deq.server.subprocess.run") as mock_run,
            patch("deq.server.os.makedirs") as mock_makedirs,
        ):
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = ""
            result = deq_server.run_backup_task(task)
            mock_run.assert_called_once()
            args, kwargs = mock_run.call_args
            cmd = " ".join(args[0])
            # SSH_CONTROL_STR contains "-o ControlMaster=auto ..."
            assert "ControlMaster=auto" in cmd
            assert "ControlPath=/tmp/deq-ssh" in cmd
            assert "ControlPersist=60" in cmd

    def test_size_parsing_with_commas(self, deq_server, mock_config):
        """Size parsing with commas/thousands separators."""
        deq_server.CONFIG["devices"].extend(
            [
                {"id": "dev1", "is_host": True},
                {"id": "dev2", "is_host": True},
            ]
        )
        task = {
            "id": "task1",
            "source": {"device": "dev1", "path": "/src"},
            "dest": {"device": "dev2", "path": "/dest"},
        }
        with (
            patch("deq.server.ping_host", return_value=True),
            patch("deq.server.subprocess.run") as mock_run,
            patch("deq.server.os.makedirs") as mock_makedirs,
        ):
            mock_run.return_value.returncode = 0
            # Different formats: comma thousands separator
            mock_run.return_value.stdout = "Total file size: 1,234,567 bytes"
            result = deq_server.run_backup_task(task)
            assert result["success"] == True
            assert (
                result["size"] == "1MB"
            )  # 1,234,567 bytes -> 1.2 MB? Wait, the function rounds to nearest MB? Let's compute: 1,234,567 bytes ~ 1.2 MB but they do int division? Let's examine actual conversion: bytes_val >= 1e9 -> GB, >= 1e6 -> MB, else KB. For 1,234,567 bytes, bytes_val >= 1e6, so size = f"{bytes_val / 1e6:.0f}MB". .0f rounds to nearest whole number. 1,234,567 / 1e6 = 1.234567 -> .0f gives "1MB". That's correct.
            # Additional test with dot separator (some locales use dot)
            mock_run.return_value.stdout = "Total file size: 2.500.000 bytes"
            result = deq_server.run_backup_task(task)
            assert result["success"] == True
            assert result["size"] == "2MB"

    def test_size_parsing_edge_cases(self, deq_server, mock_config):
        """Size parsing edge cases: invalid numbers."""
        deq_server.CONFIG["devices"].extend(
            [
                {"id": "dev1", "is_host": True},
                {"id": "dev2", "is_host": True},
            ]
        )
        task = {
            "id": "task1",
            "source": {"device": "dev1", "path": "/src"},
            "dest": {"device": "dev2", "path": "/dest"},
        }
        with (
            patch("deq.server.ping_host", return_value=True),
            patch("deq.server.subprocess.run") as mock_run,
            patch("deq.server.os.makedirs") as mock_makedirs,
        ):
            mock_run.return_value.returncode = 0
            # Non-numeric after colon
            mock_run.return_value.stdout = "Total file size: abc bytes"
            result = deq_server.run_backup_task(task)
            assert result["success"] == True
            assert result["size"] == "abc"  # parsing fails, returns raw string
            # Missing colon
            mock_run.return_value.stdout = "Total file size 1234567 bytes"
            result = deq_server.run_backup_task(task)
            assert result["success"] == True
            assert result["size"] == ""  # No colon, size remains empty string
