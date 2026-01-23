# DeQ Security Issues (Supplement)
## Executive Summary

This document supplements the existing `Recommendations.md` file (which contains 62 security issues identified by static analysis) with newly discovered command injection and privilege escalation vulnerabilities. The line numbers in this report reflect the current location of `server.py` in the `src/deq/` directory after project restructuring.

**Key Findings:**
1. **Critical command injection vulnerabilities** in remote file browsing and download functions
2. **Path traversal** in file upload functionality  
3. **Privilege escalation risks** from extensive sudo usage without proper constraints
4. **Network exposure** from binding to all interfaces (0.0.0.0)

These vulnerabilities are particularly dangerous because:
- They allow authenticated users to execute arbitrary commands on remote devices
- Attackers can escalate privileges to root through sudo-enabled commands
- The application binds to all network interfaces by default, increasing attack surface

## Newly Identified Vulnerabilities

### DEQ-001: Command Injection in browse_folder
- **Severity**: Critical
- **Location**: `src/deq/server.py`, lines 1011, 1032 (function `browse_folder`)
- **Description**: The `path` parameter is directly interpolated into shell commands with single quotes, but no validation prevents injection of malicious shell metacharacters. An attacker can break out of the single quotes and execute arbitrary commands on remote devices.
- **Proof of Concept**: For remote device browsing, send `path='$(id > /tmp/pwned)'` to execute the `id` command. The resulting command becomes: `find '$(id > /tmp/pwned)' -maxdepth 1 ...` which when evaluated by the shell executes the command substitution.
- **Impact**: Arbitrary command execution as the SSH user on remote devices, potentially leading to complete compromise of connected systems.
- **Recommendation**: Use `shlex.quote()` on the path before interpolation, or better, avoid shell=True and use list-based subprocess calls. Validate path input to prevent directory traversal.

### DEQ-002: Command Injection in list_files
- **Severity**: Critical
- **Location**: `src/deq/server.py`, line 1108 (function `list_files`)
- **Description**: The `path` parameter is directly interpolated into `ls -la` command with single quotes. Similar to DEQ-001, this allows command injection through shell metacharacters.
- **Proof of Concept**: Send `path='$(cat /etc/passwd > /tmp/passwd)'` to exfiltrate system files.
- **Impact**: Arbitrary command execution on remote devices, potentially leading to credential theft and lateral movement.
- **Recommendation**: Use `shlex.quote()` and consider using Python's native file listing functions for local paths. For remote paths, implement proper input validation and escape shell arguments.

### DEQ-003: Command Injection in get_file_for_download
- **Severity**: Critical
- **Location**: `src/deq/server.py`, line 1575 (function `get_file_for_download`)
- **Description**: The `file_path` parameter is directly interpolated into a `cat` command with single quotes. An attacker can inject shell commands to read arbitrary files or execute commands.
- **Proof of Concept**: Request download of file `'; cat /etc/shadow; #` to read sensitive system files.
- **Impact**: Arbitrary file read and command execution on remote devices, potentially exposing credentials and sensitive configuration.
- **Recommendation**: Use `shlex.quote()` on file_path. Consider using `scp` or `sftp` for secure file transfer instead of `cat` over SSH.

### DEQ-004: Path Traversal & SCP Injection in upload_file
- **Severity**: High
- **Location**: `src/deq/server.py`, lines 1596, 1630 (function `upload_file`)
- **Description**: The `dest_path` and `filename` parameters are concatenated without validation, allowing path traversal via `../` sequences. Additionally, the SCP command concatenates user inputs directly without proper sanitization.
- **Proof of Concept**: Upload a file with filename `../../../etc/cron.d/deq_exploit` to write to system directories. The `full_path` becomes `/dest/path/../../../etc/cron.d/deq_exploit`, leading to traversal.
- **Impact**: Arbitrary file write on remote devices, potentially leading to remote code execution via cron jobs, SSH key injection, or configuration modification.
- **Recommendation**: Validate that resolved paths stay within allowed directories. Use `os.path.normpath()` and check for `..` components. Consider using `scp` with `--` separator and proper argument handling.

### DEQ-005: Privilege Escalation Risk
- **Severity**: High
- **Location**: Multiple locations throughout `src/deq/server.py` (lines 636, 925, 1778-1913, 2183, 2211, 2478, 2504, 2957, 2980)
- **Description**: The application uses `sudo` for various operations (SMART monitoring, docker commands, shutdown, suspend) without proper constraints. If an attacker gains command injection (as in DEQ-001 through DEQ-003), they can execute arbitrary commands with root privileges.
- **Proof of Concept**: Combine DEQ-001 with `sudo` usage: `path='$(sudo id > /tmp/root_id)'` to execute commands as root.
- **Impact**: Complete system compromise through privilege escalation to root.
- **Recommendation**: Implement principle of least privilege:
  1. Create a dedicated sudoers configuration with specific allowed commands
  2. Remove `NOPASSWD` where possible
  3. Consider using Linux capabilities instead of full root access
  4. Run DeQ with a dedicated user account with limited privileges

### DEQ-006: Network Exposure
- **Severity**: Medium
- **Location**: `src/deq/server.py`, line 3366 (server startup)
- **Description**: The HTTP server binds to `0.0.0.0` (all network interfaces) by default, exposing the web interface to all network interfaces instead of just localhost.
- **Proof of Concept**: Default installation exposes port 5050 to the entire network, making the application accessible to anyone on the local network.
- **Impact**: Increased attack surface. Combined with authentication weaknesses or other vulnerabilities, this could allow unauthorized access from other machines on the network.
- **Recommendation**: Change default binding to `127.0.0.1` (localhost) and provide configuration option for binding to specific interfaces. Document the security implications of network exposure.

## Recommendations

**Immediate Actions (Priority 1):**
1. **Fix command injection vulnerabilities** (DEQ-001 through DEQ-004) by implementing proper input validation and using `shlex.quote()` or moving away from shell=True.
2. **Restrict sudo usage** (DEQ-005) by creating a least-privilege sudoers configuration.
3. **Change default network binding** (DEQ-006) to localhost and document network exposure risks.

**Long-term Improvements:**
1. **Implement comprehensive input validation** for all user-supplied parameters.
2. **Use Python's built-in file operations** instead of shell commands where possible.
3. **Add security-focused testing** to detect command injection and path traversal vulnerabilities.
4. **Implement proper error handling** to avoid information disclosure.

**Defense in Depth:**
1. Run DeQ in a container or dedicated VM to limit blast radius.
2. Use network segmentation to isolate DeQ from critical infrastructure.
3. Implement rate limiting and authentication logging.
4. Regular security audits of the codebase.

## References

- [Recommendations.md](./Recommendations.md) - Original security analysis with 62 identified issues (note: line numbers may be outdated after moving `server.py` to `src/deq/`)
- DeQ repository structure and current code at `src/deq/server.py`
- Security testing results and vulnerability demonstration scripts

---
**Report Generated:** 2026-01-22  
**Target Version:** DeQ `server.py` at `src/deq/server.py`  
**Analysis Method:** Manual code review focused on command injection and privilege escalation vulnerabilities