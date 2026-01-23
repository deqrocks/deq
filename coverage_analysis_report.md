# DeQ Server.py Test Coverage Analysis
Generated: analyze_coverage.py
Total functions analyzed: 79

## Overall Statistics
- Total functions: 79
- Total lines in functions: 2818
- Covered lines in functions: 990
- Overall function coverage: 35.1%
- High priority (0% coverage): 0 functions
- Medium priority (1-50% coverage): 42 functions
- Low priority (51-99% coverage): 37 functions
- Fully covered (100% coverage): 0 functions

## High Priority Functions (0% Coverage)
These functions have no test coverage and should be addressed first:
## Security Critical Functions
These functions handle authentication, authorization, or sensitive operations:
- `is_auth_enabled()`: 40.0% coverage (MEDIUM priority)
- `verify_password()`: 58.8% coverage (LOW priority)
- `get_session_secret()`: 75.0% coverage (LOW priority)
- `create_session_token()`: 44.4% coverage (MEDIUM priority)
- `verify_session_token()`: 50.0% coverage (LOW priority)
- `run_rsync_with_progress()`: 65.7% coverage (LOW priority)
- `start_transfer_job()`: 50.0% coverage (LOW priority)
- `run_transfer_job()`: 50.0% coverage (LOW priority)
- `load_config()`: 40.0% coverage (MEDIUM priority)
- `save_config()`: 60.0% coverage (LOW priority)
- `get_config_with_defaults()`: 80.0% coverage (LOW priority)
- `execute_quick_action()`: 47.6% coverage (MEDIUM priority)
- `get_remote_stats()`: 45.3% coverage (MEDIUM priority)
- `list_files()`: 20.6% coverage (MEDIUM priority)
- `file_operation()`: 50.0% coverage (LOW priority)
- `run_local()`: 50.0% coverage (LOW priority)
- `run_remote()`: 5.0% coverage (MEDIUM priority)
- `get_file_for_download()`: 46.8% coverage (MEDIUM priority)
- `upload_file()`: 43.6% coverage (MEDIUM priority)
- `remote_docker_action()`: 35.8% coverage (MEDIUM priority)
- `get_default_ssh_user()`: 8.3% coverage (MEDIUM priority)
- `ssh_shutdown()`: 28.6% coverage (MEDIUM priority)
- `ssh_suspend()`: 30.3% coverage (MEDIUM priority)
- `run_task_async()`: 1.8% coverage (MEDIUM priority)
- `run_task()`: 5.3% coverage (MEDIUM priority)
- `run_backup_task()`: 1.0% coverage (MEDIUM priority)
- `run_wake_task()`: 3.6% coverage (MEDIUM priority)
- `run_shutdown_task()`: 2.9% coverage (MEDIUM priority)
- `run_suspend_task()`: 3.8% coverage (MEDIUM priority)
- `run_script_task()`: 12.5% coverage (MEDIUM priority)
- `calculate_next_run()`: 67.7% coverage (LOW priority)
- `_run()`: 5.9% coverage (MEDIUM priority)
- `_update_next_runs()`: 4.5% coverage (MEDIUM priority)
- `_check_and_run_tasks()`: 3.3% coverage (MEDIUM priority)
- `send_file()`: 81.8% coverage (LOW priority)
- `get_session_cookie()`: 77.8% coverage (LOW priority)
- `is_authenticated()`: 71.4% coverage (LOW priority)

## Complex Functions (>50 lines)
These functions are large and may benefit from refactoring:
- `run_rsync_with_progress()`: 70 lines, 65.7% coverage (LOW priority)
- `get_local_stats()`: 75 lines, 54.7% coverage (LOW priority)
- `get_remote_stats()`: 170 lines, 45.3% coverage (MEDIUM priority)
- `browse_folder()`: 86 lines, 33.7% coverage (MEDIUM priority)
- `list_files()`: 189 lines, 20.6% coverage (MEDIUM priority)
- `upload_file()`: 55 lines, 43.6% coverage (MEDIUM priority)
- `get_health_status()`: 95 lines, 1.1% coverage (MEDIUM priority)
- `remote_docker_action()`: 67 lines, 35.8% coverage (MEDIUM priority)
- `scan_network()`: 132 lines, 0.8% coverage (MEDIUM priority)
- `get_all_container_statuses()`: 65 lines, 1.5% coverage (MEDIUM priority)
- `run_task_async()`: 55 lines, 1.8% coverage (MEDIUM priority)
- `run_backup_task()`: 104 lines, 1.0% coverage (MEDIUM priority)
- `calculate_next_run()`: 65 lines, 67.7% coverage (LOW priority)
- `do_GET()`: 369 lines, 54.2% coverage (LOW priority)
- `do_POST()`: 223 lines, 51.6% coverage (LOW priority)

## Testing Recommendations
### Phase 1: Security & Core Infrastructure
1. Test authentication functions (`verify_password`, `create_session_token`, `verify_session_token`)
2. Test SSH/remote operation functions
3. Test file transfer engine functions

### Phase 2: Business Logic
1. Test file operations (`file_operation`, `list_files`, `browse_folder`)
2. Test system monitoring functions (`get_local_stats`, `get_remote_stats`)
3. Test Docker/container management functions

### Phase 3: Edge Cases & Integration
1. Test error handling paths
2. Test concurrent operations
3. Add integration tests for complete workflows