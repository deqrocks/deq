# DeQ Test Coverage Analysis and Improvement Plan

## Current Coverage Status
- **Overall coverage**: 17% (306/1845 statements)
- **Total lines in server.py**: 8893
- **Missing lines**: 1539
- **Target coverage**: 80%

## Key Findings

### 1. File Structure Analysis
The `server.py` file (8893 lines) contains:
- **Python logic (lines 1-2708)**: 2708 lines (30.5%)
- **HTML/JS frontend (lines 2709-8893)**: 6185 lines (69.5%)

### 2. Coverage Distribution
- **HTML/JS code**: 99.9% covered (only 5 missing lines)
- **Python logic**: 20.6% covered (2149 missing lines out of 2708)

**Conclusion**: The HTML/JS frontend code is almost fully covered, but the core Python logic is severely undertested.

## Already Tested Functions (from tests/test_server.py)

### Authentication (TestAuthentication)
- `is_auth_enabled()` - ✓
- `verify_password()` - ✓ (partial - missing scrypt path)
- `get_session_secret()` - ✓
- `create_session_token()` - ✓
- `verify_session_token()` - ✓

### Utility Functions (TestFormatSize)
- `format_size()` - ✓

### Configuration (TestConfig)
- `load_config()` - ✓
- `save_config()` - ✓
- `get_config_with_defaults()` - ✓
- `ensure_dirs()` - ✓

### Device Status Cache (TestDeviceStatusCache)
- `get_cached_status()` - ✓
- `set_cached_status()` - ✓
- `refresh_device_status_async()` - ✓ (mocked)

### Quick Actions (TestQuickActions)
- `discover_scripts()` - ✓
- `execute_quick_action()` - ✓

### Network Operations (TestPingHost)
- `ping_host()` - ✓

### Container Validation (TestContainerNameValidation)
- `is_valid_container_name()` - ✓

### Wake-on-LAN (TestSendWOL)
- `send_wol()` - ✓

### File Operations (TestFileOperations)
- `browse_folder()` - ✓ (basic cases)

### Transfer Jobs (TestTransferJobs)
- `start_transfer_job()` - ✓ (mocked)
- `update_job_progress()` - ✓
- `complete_job()` - ✓
- `get_job_status()` - ✓
- `cleanup_old_jobs()` - ✓

### Path Size (TestPathSize)
- `get_path_size()` - ✓

### Free Space (TestFreeSpace)
- `get_free_space()` - ✓

## Major Untested Functions and Classes

### **CRITICAL BUSINESS LOGIC (HIGH PRIORITY)**

#### 1. File Transfer Operations
- `run_rsync_with_progress()` (lines 154-214) - Core transfer logic with progress tracking
- `run_transfer_job()` (lines 286-384) - Main transfer job execution
- `file_operation()` (lines 957-1179) - File operations (copy, move, delete, rename)
- `get_file_for_download()` (lines 1182-1217) - File download handling
- `upload_file()` (lines 1220-1260) - File upload handling

#### 2. SSH and Remote Operations
- `get_remote_stats()` (lines 641-744) - Get remote system statistics via SSH
- `remote_docker_action()` (lines 1380-1421) - Docker operations on remote hosts
- `ssh_shutdown()` (lines 1682-1693) - Remote shutdown via SSH
- `ssh_suspend()` (lines 1695-1708) - Remote suspend via SSH

#### 3. Docker Operations
- `scan_docker_containers()` (lines 1423-1476) - Discover Docker containers
- `get_all_container_statuses()` (lines 1603-1653) - Get container statuses
- `docker_action()` (lines 1658-1680) - Local Docker operations

#### 4. System Monitoring
- `get_disk_smart_info()` (lines 490-525) - Disk SMART information
- `get_container_stats()` (lines 527-552) - Container statistics
- `get_local_stats()` (lines 554-609) - Local system statistics
- `get_health_status()` (lines 1274-1350) - System health check

#### 5. Network Scanning
- `scan_network()` (lines 1489-1601) - Network device discovery

#### 6. Task System
- `log_task()` (lines 1712-1725) - Task logging
- `run_task_async()` (lines 1730-1782) - Async task execution
- `run_task()` (lines 1785-1801) - Task execution
- `run_backup_task()` (lines 1803-1887) - Backup task
- `run_wake_task()` (lines 1889-1910) - Wake task
- `run_shutdown_task()` (lines 1913-1943) - Shutdown task
- `run_suspend_task()` (lines 1945-1966) - Suspend task
- `run_script_task()` (lines 1968-1973) - Script task
- `calculate_next_run()` (lines 1977-2039) - Task scheduling

### **CORE CLASSES (MEDIUM PRIORITY)**

#### 1. `TaskScheduler` class (lines 2042-2131)
- Complete scheduler implementation untested

#### 2. `RequestHandler` class (lines 2138-2666)
- HTTP request handling completely untested
- All API endpoints (/api/* routes)
- Authentication middleware
- Static file serving

### **UTILITY FUNCTIONS (LOW PRIORITY)**
- `get_default_ssh_user()` (lines 1478-1487)
- `list_files()` (lines 810-954) - More complex file listing

## Coverage Gap Patterns

### 1. **External Command Execution** (High Risk)
Functions that call `subprocess.run()` or `subprocess.Popen()` are largely untested:
- SSH commands
- Docker commands
- System commands (df, du, ping, etc.)
- Rsync transfers

### 2. **Error Handling Paths**
Most exception handling branches are untested:
- Network timeouts
- Permission errors
- Invalid input handling
- File system errors

### 3. **Complex Business Logic**
- Multi-phase file transfers
- Progress tracking
- Concurrent job management
- Task scheduling

### 4. **Integration Points**
- SSH authentication and connection handling
- Docker API interactions
- File system operations across different devices

## Prioritized Test Implementation Plan

### **PHASE 1: CRITICAL BUSINESS LOGIC (Target: +30% coverage)**

#### Week 1: File Transfer Operations
1. **`run_rsync_with_progress()`** - Mock subprocess and test progress parsing
2. **`run_transfer_job()`** - Test transfer job execution with mocked SSH
3. **`file_operation()`** - Test copy, move, delete, rename operations
4. **`get_file_for_download()` / `upload_file()`** - Test file up/download

#### Week 2: SSH and Remote Operations
1. **`get_remote_stats()`** - Mock SSH commands for system stats
2. **`remote_docker_action()`** - Test remote Docker operations
3. **`ssh_shutdown()` / `ssh_suspend()`** - Test remote power management

#### Week 3: Docker Operations
1. **`scan_docker_containers()`** - Mock Docker CLI output
2. **`get_all_container_statuses()`** - Test container status aggregation
3. **`docker_action()`** - Test local Docker commands

### **PHASE 2: SYSTEM MONITORING & TASKS (Target: +20% coverage)**

#### Week 4: System Monitoring
1. **`get_disk_smart_info()`** - Mock smartctl output
2. **`get_container_stats()`** - Mock Docker stats
3. **`get_local_stats()`** - Mock system file reads
4. **`get_health_status()`** - Test health check aggregation

#### Week 5: Task System
1. **`log_task()`** - Test task logging
2. **`run_task_async()` / `run_task()`** - Test task execution
3. **Task runners** (`run_backup_task`, `run_wake_task`, etc.)
4. **`calculate_next_run()`** - Test task scheduling logic

### **PHASE 3: HTTP API & CLASSES (Target: +13% coverage)**

#### Week 6: HTTP Request Handler
1. **`RequestHandler` class** - Test API endpoints
   - `/api/config` - Configuration endpoints
   - `/api/devices` - Device management
   - `/api/files` - File operations
   - `/api/tasks` - Task management
   - `/api/docker` - Docker operations
2. **Authentication middleware** - Test auth flow

#### Week 7: Task Scheduler
1. **`TaskScheduler` class** - Test scheduling logic
2. **Integration tests** - Combined operations

## Technical Approach Recommendations

### 1. **Mocking Strategy**
- Use `unittest.mock` to mock `subprocess.run()` and `subprocess.Popen()`
- Mock `socket` for network operations
- Mock file system operations with `tempfile` and `mock_open`
- Use `patch` decorators for external dependencies

### 2. **Test Organization**
- Group tests by functional area (mirroring existing structure)
- Use pytest fixtures for common setup (already in place)
- Create shared mocking utilities for SSH, Docker, etc.

### 3. **Test Data**
- Create realistic mock responses for system commands
- Use sample Docker output from real systems
- Create test files and directories in temp locations

### 4. **Integration Testing**
- Test complete workflows (e.g., file transfer with progress)
- Test error recovery paths
- Test concurrent operations

## Estimated Coverage Impact

### Current State:
- Python logic: 559/2708 lines covered (20.6%)
- Need for 80% overall: 1476/1845 statements

### After Phase 1 (+30%):
- Python logic: ~1350/2708 lines covered (~50%)
- Overall: ~50% coverage

### After Phase 2 (+20%):
- Python logic: ~1890/2708 lines covered (~70%)
- Overall: ~70% coverage

### After Phase 3 (+13%):
- Python logic: ~2166/2708 lines covered (~80%)
- Overall: ~83% coverage

## Risk Areas

### 1. **Complex Mocking Requirements**
- SSH command chaining
- Docker CLI output parsing
- Rsync progress parsing
- Concurrent thread management

### 2. **Stateful Operations**
- Transfer job tracking
- Task scheduler state
- Device status caching

### 3. **External Dependencies**
- System command availability
- File system permissions
- Network connectivity assumptions

## Quick Wins (Highest ROI)

1. **`run_rsync_with_progress()`** - Core transfer logic, affects file operations
2. **`file_operation()`** - Used by UI for all file operations
3. **`get_remote_stats()`** - Core monitoring function
4. **`RequestHandler.do_GET()`/`do_POST()`** - All HTTP API endpoints

## Monitoring Progress

1. **Daily**: Run coverage report after adding tests
2. **Weekly**: Review coverage gaps and adjust priorities
3. **Milestone**: Each phase completion (30%, 50%, 80%)

## Success Metrics
- Reach 80% statement coverage
- All critical business logic functions tested
- Error handling paths covered
- Integration tests for key workflows