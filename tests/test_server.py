"""
Tests for server.py
"""
import os
import json
import tempfile
import pytest
from unittest.mock import patch, MagicMock, call


class TestAuthentication:
    """Test authentication functions."""
    
    def test_is_auth_enabled_no_password_file(self, deq_server):
        """When password file doesn't exist, auth is disabled."""
        # Ensure password file does not exist
        if os.path.exists(deq_server.PASSWORD_FILE):
            os.unlink(deq_server.PASSWORD_FILE)
        assert deq_server.is_auth_enabled() == False
    
    def test_is_auth_enabled_with_password_file(self, deq_server):
        """When password file exists, auth is enabled."""
        # Create empty password file
        with open(deq_server.PASSWORD_FILE, 'w') as f:
            f.write('')
        assert deq_server.is_auth_enabled() == True
    
    def test_verify_password_auth_disabled(self, deq_server):
        """When auth is disabled, any password passes."""
        # Remove password file to disable auth
        if os.path.exists(deq_server.PASSWORD_FILE):
            os.unlink(deq_server.PASSWORD_FILE)
        # verify_password checks is_auth_enabled internally
        assert deq_server.verify_password('anypass') == True
    
    def test_verify_password_auth_enabled_incorrect(self, deq_server):
        """When auth enabled but password wrong, verification fails."""
        # Create a dummy password file with invalid format
        with open(deq_server.PASSWORD_FILE, 'w') as f:
            f.write('salt:key')
        # Should fail to parse and return False
        assert deq_server.verify_password('wrong') == False
    
    def test_session_token_creation_and_verification(self, deq_server):
        """Test that a created session token can be verified."""
        token = deq_server.create_session_token()
        assert deq_server.verify_session_token(token) == True
        assert deq_server.verify_session_token('invalid:token') == False
        assert deq_server.verify_session_token('') == False
        assert deq_server.verify_session_token(None) == False
    
    def test_get_session_secret_creates_file(self, deq_server):
        """get_session_secret should create file if missing."""
        if os.path.exists(deq_server.SESSION_SECRET_FILE):
            os.unlink(deq_server.SESSION_SECRET_FILE)
        secret = deq_server.get_session_secret()
        assert isinstance(secret, str)
        assert len(secret) == 64  # 32 bytes hex
        assert os.path.exists(deq_server.SESSION_SECRET_FILE)
        # File permissions should be 0o600
        import stat
        st = os.stat(deq_server.SESSION_SECRET_FILE)
        assert st.st_mode & 0o777 == 0o600


class TestFormatSize:
    """Test format_size function."""
    
    def test_format_size_bytes(self, deq_server):
        assert deq_server.format_size(0) == '0 B'
        assert deq_server.format_size(1) == '1 B'
        assert deq_server.format_size(1023) == '1023 B'
    
    def test_format_size_kb(self, deq_server):
        assert deq_server.format_size(1024) == '1.0 KB'
        assert deq_server.format_size(1536) == '1.5 KB'
        assert deq_server.format_size(1024 * 10) == '10.0 KB'
    
    def test_format_size_mb(self, deq_server):
        assert deq_server.format_size(1024 * 1024) == '1.0 MB'
        assert deq_server.format_size(1024 * 1024 * 2.5) == '2.5 MB'
    
    def test_format_size_gb(self, deq_server):
        assert deq_server.format_size(1024 * 1024 * 1024) == '1.0 GB'
    
    def test_format_size_tb(self, deq_server):
        assert deq_server.format_size(1024 * 1024 * 1024 * 1024) == '1.0 TB'
        # large number
        assert 'TB' in deq_server.format_size(1024 * 1024 * 1024 * 1024 * 5)


class TestConfig:
    """Test config loading and saving."""
    
    def test_load_config_no_file(self, deq_server):
        """When config file doesn't exist, load_config returns default config with host device."""
        # Ensure config file does not exist
        if os.path.exists(deq_server.CONFIG_FILE):
            os.unlink(deq_server.CONFIG_FILE)
        config = deq_server.load_config()
        assert 'devices' in config
        # Should have host device inserted
        host_devices = [d for d in config['devices'] if d.get('is_host')]
        assert len(host_devices) == 1
        assert host_devices[0]['id'] == 'host'
    
    def test_save_config(self, deq_server):
        """Saving config should write to file."""
        config = {'devices': [], 'settings': {}}
        deq_server.save_config(config)
        with open(deq_server.CONFIG_FILE, 'r') as f:
            saved = json.load(f)
        assert saved == config
    
    def test_get_config_with_defaults(self, deq_server):
        """Test merging device alerts with defaults."""
        # We need to set CONFIG global
        deq_server.CONFIG = {
            'devices': [
                {'id': 'dev1', 'alerts': {'cpu': 80}},
                {'id': 'dev2'}
            ]
        }
        result = deq_server.get_config_with_defaults()
        # Should have merged alerts
        dev1 = next(d for d in result['devices'] if d['id'] == 'dev1')
        assert dev1['alerts']['cpu'] == 80
        assert dev1['alerts']['online'] == True  # default
        dev2 = next(d for d in result['devices'] if d['id'] == 'dev2')
        assert dev2['alerts'] == deq_server.DEFAULT_ALERTS
    
    def test_ensure_dirs(self, deq_server):
        """ensure_dirs creates necessary directories."""
        import shutil
        # Remove directories if they exist
        for d in [deq_server.DATA_DIR, deq_server.SCRIPTS_DIR, deq_server.TASK_LOGS_DIR]:
            if os.path.exists(d):
                shutil.rmtree(d)
        deq_server.ensure_dirs()
        assert os.path.exists(deq_server.DATA_DIR)
        assert os.path.exists(deq_server.SCRIPTS_DIR)
        assert os.path.exists(deq_server.TASK_LOGS_DIR)


class TestDeviceStatusCache:
    """Test device status caching."""
    
    def test_get_set_cached_status(self, deq_server):
        deq_server.set_cached_status('dev1', {'online': True})
        assert deq_server.get_cached_status('dev1') == {'online': True}
        assert deq_server.get_cached_status('dev2') is None
    
    def test_refresh_device_status_async(self, deq_server):
        """refresh_device_status_async should start a thread."""
        with patch('server.threading.Thread') as mock_thread:
            mock_device = {'id': 'dev1', 'is_host': True}
            deq_server.refresh_device_status_async(mock_device)
            # Should start a thread
            assert mock_thread.called
            # Thread should be daemon
            mock_thread.assert_called_once()
            args, kwargs = mock_thread.call_args
            assert kwargs.get('daemon', False) == True


class TestQuickActions:
    """Test script discovery and execution."""
    
    def test_discover_scripts_no_dir(self, deq_server):
        """If SCRIPTS_DIR doesn't exist, return empty list."""
        import shutil
        if os.path.exists(deq_server.SCRIPTS_DIR):
            shutil.rmtree(deq_server.SCRIPTS_DIR)
        scripts = deq_server.discover_scripts()
        assert scripts == []
    
    def test_discover_scripts_with_executable(self, deq_server):
        """Find executable scripts."""
        # Create a dummy script
        script_path = os.path.join(deq_server.SCRIPTS_DIR, 'test.sh')
        with open(script_path, 'w') as f:
            f.write('#!/bin/sh\necho hello')
        os.chmod(script_path, 0o755)
        scripts = deq_server.discover_scripts()
        assert len(scripts) == 1
        assert scripts[0]['name'] == 'test.sh'
        assert scripts[0]['path'] == 'test.sh'
    
    def test_execute_quick_action_valid(self, deq_server):
        """Execute a script."""
        script_path = os.path.join(deq_server.SCRIPTS_DIR, 'test.sh')
        with open(script_path, 'w') as f:
            f.write('#!/bin/sh\necho hello')
        os.chmod(script_path, 0o755)
        with patch('server.subprocess.Popen') as mock_popen:
            mock_popen.return_value = MagicMock()
            result = deq_server.execute_quick_action('test.sh')
            assert result['success'] == True
            mock_popen.assert_called_once_with(
                [script_path],
                cwd=deq_server.SCRIPTS_DIR,
                stdout=deq_server.subprocess.DEVNULL,
                stderr=deq_server.subprocess.DEVNULL
            )
    
    def test_execute_quick_action_nonexistent(self, deq_server):
        """Script not found."""
        result = deq_server.execute_quick_action('nonexistent.sh')
        assert result['success'] == False
        assert 'not found' in result['error'].lower()
    
    def test_execute_quick_action_not_executable(self, deq_server):
        """Script not executable."""
        script_path = os.path.join(deq_server.SCRIPTS_DIR, 'test.sh')
        with open(script_path, 'w') as f:
            f.write('')
        os.chmod(script_path, 0o644)
        result = deq_server.execute_quick_action('test.sh')
        assert result['success'] == False
        assert 'executable' in result['error'].lower()


class TestPingHost:
    """Test ping_host function."""
    
    def test_ping_host_success(self, deq_server):
        """Mock successful ping."""
        with patch('server.subprocess.run') as mock_run:
            mock_run.return_value.returncode = 0
            assert deq_server.ping_host('192.168.1.1') == True
            mock_run.assert_called_once()
            args, _ = mock_run.call_args
            cmd = args[0]
            assert cmd[0] == 'ping'
            assert '-c' in cmd
            assert '192.168.1.1' in cmd
    
    def test_ping_host_failure(self, deq_server):
        """Mock failed ping."""
        with patch('server.subprocess.run') as mock_run:
            mock_run.return_value.returncode = 1
            assert deq_server.ping_host('192.168.1.1') == False
    
    def test_ping_host_timeout(self, deq_server):
        """Mock timeout."""
        with patch('server.subprocess.run', side_effect=deq_server.subprocess.TimeoutExpired('ping', 1)):
            # Should return False on timeout
            assert deq_server.ping_host('192.168.1.1') == False


class TestContainerNameValidation:
    """Test is_valid_container_name."""
    
    def test_valid_names(self, deq_server):
        assert deq_server.is_valid_container_name('my-container')
        assert deq_server.is_valid_container_name('my_container')
        assert deq_server.is_valid_container_name('mycontainer123')
        assert deq_server.is_valid_container_name('my.container')
        assert deq_server.is_valid_container_name('a')
        # max length? 128 characters
        assert deq_server.is_valid_container_name('a' * 128)
    
    def test_invalid_names(self, deq_server):
        assert not deq_server.is_valid_container_name('')
        assert not deq_server.is_valid_container_name('a' * 129)
        assert not deq_server.is_valid_container_name('MyContainer!')
        assert not deq_server.is_valid_container_name('my container')
        assert not deq_server.is_valid_container_name('my/container')
        assert not deq_server.is_valid_container_name('.startswithdot')
        assert not deq_server.is_valid_container_name('-startswithdash')


class TestSendWOL:
    """Test Wake-on-LAN function."""
    
    def test_send_wol_valid(self, deq_server):
        """Valid MAC address."""
        with patch('server.socket.socket') as mock_socket:
            mock_sock = MagicMock()
            mock_socket.return_value = mock_sock
            result = deq_server.send_wol('00:11:22:33:44:55')
            assert result['success'] == True
            # Check socket calls
            mock_sock.setsockopt.assert_called_once()
            mock_sock.sendto.assert_called_once()
            mock_sock.close.assert_called_once()
    
    def test_send_wol_invalid_mac(self, deq_server):
        """Invalid MAC address."""
        result = deq_server.send_wol('invalid')
        assert result['success'] == False
        assert 'Invalid MAC' in result['error']
    
    def test_send_wol_exception(self, deq_server):
        """Socket exception."""
        with patch('server.socket.socket', side_effect=Exception('socket error')):
            result = deq_server.send_wol('00:11:22:33:44:55')
            assert result['success'] == False
            assert 'socket error' in result['error']


class TestFileOperations:
    """Test file operations (minimal mocking)."""
    
    def test_browse_folder_local_nonexistent(self, deq_server):
        """Browse non-existent local directory."""
        device = {'is_host': True}
        result = deq_server.browse_folder(device, '/nonexistent')
        assert result['success'] == False
        assert 'Not a directory' in result['error']
    
    def test_browse_folder_local_success(self, deq_server, tmpdir):
        """Browse local directory."""
        # Create a temporary directory with subdirectories
        import tempfile
        tmp = tempfile.mkdtemp(dir=str(tmpdir))
        os.makedirs(os.path.join(tmp, 'sub1'))
        os.makedirs(os.path.join(tmp, 'sub2'))
        device = {'is_host': True}
        result = deq_server.browse_folder(device, tmp)
        assert result['success'] == True
        assert 'sub1' in result['folders']
        assert 'sub2' in result['folders']
        assert result['path'] == tmp
    
    def test_browse_folder_remote_no_ssh(self, deq_server):
        """Remote device without SSH config."""
        device = {'is_host': False, 'ip': '192.168.1.1'}
        result = deq_server.browse_folder(device, '/')
        assert result['success'] == False
        assert 'SSH not configured' in result['error']
    
    # More file operation tests would require extensive mocking of SSH.
    # We'll skip for now.


class TestTransferJobs:
    """Test transfer job tracking."""
    
    def test_start_transfer_job(self, deq_server):
        """Start a transfer job."""
        with patch('server.threading.Thread') as mock_thread:
            device = {'is_host': True}
            dest_device = {'is_host': True}
            job_id = deq_server.start_transfer_job(
                device, ['/src'], dest_device, '/dest', 'copy'
            )
            assert job_id.startswith('transfer_')
            # Should create job entry
            assert job_id in deq_server.transfer_jobs
            job = deq_server.transfer_jobs[job_id]
            assert job['status'] == 'running'
            assert job['phase'] == 1
            assert job['phases'] == 1
            # Thread should be started
            assert mock_thread.called
    
    def test_update_job_progress(self, deq_server):
        """Update job progress."""
        deq_server.transfer_jobs['test_job'] = {'progress': 0}
        deq_server.update_job_progress('test_job', 50, speed='10 MB/s', eta='01:00')
        assert deq_server.transfer_jobs['test_job']['progress'] == 50
        assert deq_server.transfer_jobs['test_job']['speed'] == '10 MB/s'
        assert deq_server.transfer_jobs['test_job']['eta'] == '01:00'
    
    def test_complete_job(self, deq_server):
        """Mark job as complete."""
        deq_server.transfer_jobs['test_job'] = {'status': 'running'}
        deq_server.complete_job('test_job')
        assert deq_server.transfer_jobs['test_job']['status'] == 'complete'
        assert 'completed_at' in deq_server.transfer_jobs['test_job']
    
    def test_complete_job_with_error(self, deq_server):
        """Mark job as failed."""
        deq_server.transfer_jobs['test_job'] = {'status': 'running'}
        deq_server.complete_job('test_job', error='Something went wrong')
        assert deq_server.transfer_jobs['test_job']['status'] == 'error'
        assert deq_server.transfer_jobs['test_job']['error'] == 'Something went wrong'
    
    def test_get_job_status(self, deq_server):
        """Get job status."""
        deq_server.transfer_jobs['test_job'] = {'status': 'running', 'progress': 30}
        status = deq_server.get_job_status('test_job')
        assert status['status'] == 'running'
        assert status['progress'] == 30
    
    def test_get_job_status_not_found(self, deq_server):
        """Job not found."""
        status = deq_server.get_job_status('nonexistent')
        assert status['status'] == 'not_found'
    
    def test_cleanup_old_jobs(self, deq_server):
        """Remove old completed jobs."""
        import time
        deq_server.transfer_jobs['old'] = {
            'status': 'complete',
            'completed_at': time.time() - 400  # older than max_age (300)
        }
        deq_server.transfer_jobs['recent'] = {
            'status': 'complete',
            'completed_at': time.time() - 100
        }
        deq_server.transfer_jobs['running'] = {
            'status': 'running',
            'started_at': time.time() - 200
        }
        deq_server.cleanup_old_jobs()
        assert 'old' not in deq_server.transfer_jobs
        assert 'recent' in deq_server.transfer_jobs
        assert 'running' in deq_server.transfer_jobs


# TODO: Add more tests for:
# - get_path_size, get_free_space (mock subprocess)
# - run_rsync_with_progress (mock subprocess and fcntl)
# - list_files, file_operation (mock subprocess and SSH)
# - get_remote_stats (mock SSH)
# - get_local_stats (mock file reads)
# - get_health_status
# - remote_docker_action
# - scan_docker_containers
# - TaskScheduler class
# - RequestHandler class

if __name__ == '__main__':
    pytest.main([__file__])
