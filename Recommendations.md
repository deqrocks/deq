# DeQ Security and Architecture Analysis
## Recommendations and Improvements

**Date:** 2026-01-12
**Analyzed Version:** `server.py` (356,605 bytes, ~8,894 lines)
**Security Scanner:** skylos v? (62 security issues found)

---

## Executive Summary

DeQ is a single-file Python web application designed for homelab management via SSH. The project's
philosophy emphasizes simplicity, zero dependencies, and ease of deployment. The security model is
**"trusted tool on a trusted network"** – intended to run behind a VPN and not exposed to the public
internet.

**Key Findings:**

1. **62 security issues** identified by static analysis, including critical shell injection risks
   (SKY-D212), threading concerns (SKY-D216), bare exception handling (SKY-D215), and subprocess
   timeouts (SKY-D209).
2. **Root requirement is mostly justified** for SMART monitoring, shutdown/suspend, and WoL, but can be
   reduced via fine-grained sudoers configurations.
3. **Directory structure is inflexible** – hardcoded `/opt/deq` limits portability and user‑installations.
4. **Code quality issues** – pervasive bare `except:` statements, `shell=True` usage, and minimal error
   handling.
5. **Single‑file concept tradeoffs** – excellent deployment simplicity at the cost of maintainability,
   testability, and security auditing.

**Overall Risk Assessment:** **Medium‑High** for exposed deployments, **Low‑Medium** for isolated VPN
environments with proper sudoers restrictions.

**Immediate Actions:**
1. Address critical shell injection risks (SKY‑D212).
2. Replace bare `except:` with specific exception handling.
3. Make `/opt/deq` configurable via environment variable.
4. Provide a non‑root installation option for user‑level testing.

---

## 1. Security Issues and Mitigations

### 1.1 Shell Injection (SKY‑D212 – Critical)
**Lines:** 110, 159, 339, 350, 371, 970 (and duplicates)
**Description:** `subprocess.run(…, shell=True)` with variable interpolation, even when `shlex.quote()` is
used, creates unnecessary attack surface. While `shlex.quote()` prevents command injection, `shell=True`
is still discouraged because it expands shell metacharacters and exposes the command to shell
interpretation.

**Risk:** If any unquoted variable slips into the command string, arbitrary code execution is
possible. Additionally, `shell=True` may interfere with signal handling and error reporting.

**Recommendations:**
- **Short‑term:** Keep `shlex.quote()` but replace `shell=True` with `shell=False` and list‑based commands
  where possible (e.g., `["rm", "-rf", cleanup_path]`).
- **Long‑term:** Refactor `run_rsync_with_progress()` to accept argument lists instead of shell strings,
  eliminating `shell=True` entirely.
- **Example fix for `rm -rf`:**
  ```python
  # Instead of:
  subprocess.run(f"rm -rf {shlex.quote(cleanup_path)}", shell=True)
  # Use:
  subprocess.run(["rm", "-rf", cleanup_path])  # No shell=True needed
  ```

### 1.2 Threading and Locking (SKY‑D216 – Critical)
**Lines:** 269, 459
**Description:** Potential threading issues around shared resources (transfer jobs cache, device status
cache). The current implementation uses `threading.Lock()` but may have race conditions during cache
updates or job cleanup.

**Risk:** Concurrent modifications could lead to inconsistent state, missed jobs, or corrupted data.

**Recommendations:**
- Review locking strategy for `transfer_jobs` and `device_status_cache`. Ensure all accesses (reads
  and writes) are protected.
- Consider using `threading.RLock` if nested locking is required.
- Add unit tests that simulate concurrent job creation and status updates.

### 1.3 Bare Exception Handling (SKY‑D215 – High)
**Lines:** 61, 89, 127, 151, 501, 522, 548, 550, 678, 693, 695, 724, 726, 739, 741, 1271, 1485,
1531, 1572, 1587, 1624, 1644, 1878, 2095, 2122 (plus many in test files)

**Description:** Empty `except:` clauses catch **all** exceptions, including `KeyboardInterrupt`,
`SystemExit`, and low‑level system errors. This makes debugging difficult and can leave the
application in an undefined state.

**Risk:** Silent failure, hidden bugs, and inability to gracefully shut down via SIGINT.

**Recommendations:**
- Replace every bare `except:` with `except Exception:` at minimum.
- Better: catch specific exceptions (`subprocess.TimeoutExpired`, `OSError`, `ValueError`, etc.) and
  handle each appropriately.
- Log the exception (with `logging.exception()`) before returning a generic error message.
- **Critical sections:** Ensure `KeyboardInterrupt` and `SystemExit` propagate where appropriate.

### 1.4 Subprocess Timeouts (SKY‑D209 – High)
**Lines:** 110, 159, 339, 350, 359, 371, 970, 1026
**Description:** Some `subprocess.run()` calls lack explicit `timeout=` parameter, relying on the
default (no timeout). This can lead to hung processes if a command blocks indefinitely.

**Risk:** Resource exhaustion, unresponsive web interface, and denial of service.

**Recommendations:**
- Add reasonable timeouts to **all** subprocess calls (e.g., `timeout=300` for long‑running
  operations, `timeout=30` for quick commands).
- Consider using `asyncio.create_subprocess_exec()` with `asyncio.wait_for()` for more granular
  control.

### 1.5 File Permissions
**Observation:** `config.json` contains SSH credentials and device configurations but is created
with default permissions (0644). Session secret and password files are correctly set to 0600.

**Risk:** Local users on the same system may read SSH credentials and other sensitive data.

**Recommendations:**
- Set `config.json` permissions to 0600 (owner read/write only).
- Ensure all files under `/opt/deq` are owned by root:root (or a dedicated `deq` user) with
  restrictive permissions (0700 for directories, 0600 for files).

### 1.6 Input Validation and Sanitization
**Observation:** User‑provided paths, device names, and SSH parameters are used in commands and file
operations. While `shlex.quote()` is used in many places, not all inputs are validated for path
traversal (e.g., `../../../etc/passwd`).

**Risk:** Directory traversal attacks could read/write arbitrary files on the host or remote
systems.

**Recommendations:**
- Normalize paths with `os.path.normpath()` and ensure they stay within allowed directories.
- For file operations, verify that the resolved path starts with an allowed base directory.
- Reject paths containing `..` components unless explicitly allowed.

---

## 2. Root Requirement Analysis

### 2.1 Operations That Actually Need Root
| Operation | Why Root? | Alternative |
|-----------|-----------|-------------|
| SMART data (`smartctl -A -H /dev/…`) | Requires direct hardware access | Configure `sudoers` with `NOPASSWD` for `/usr/sbin/smartctl` |
| System shutdown/suspend (`systemctl poweroff`, `shutdown -h`) | Power management | `sudoers` for `/usr/bin/systemctl poweroff`, `/usr/bin/systemctl suspend`, `/usr/sbin/shutdown` |
| Wake‑on‑LAN (raw sockets) | Requires raw socket privileges | Linux capabilities: `CAP_NET_RAW` (setcap) |
| Writing to `/opt/deq` | Directory ownership | Use user‑writable location (XDG, `/var/lib/deq`) |
| Systemd service installation | `/etc/systemd/system` | User systemd (`systemctl --user`) or install to `/usr/local/lib/systemd/system` with appropriate group permissions |
| SSH key access to `/root/.ssh` | Root’s SSH keys | Use a dedicated user account with its own SSH keys |

### 2.2 Recommendations
1. **Provide a `sudoers` template** (already documented) that grants only the necessary commands:
   ```
   deq_user ALL=(ALL) NOPASSWD: /usr/sbin/smartctl, /usr/bin/systemctl poweroff, /usr/bin/systemctl suspend, /usr/sbin/shutdown
   ```
2. **Offer a non‑root installation mode** that:
   - Uses `~/.local/share/deq` or `/var/lib/deq` (owned by a dedicated `deq` user).
   - Relies on user‑level systemd (`systemctl --user`).
   - Requires the user to manually configure sudoers for SMART and shutdown.
3. **Consider Linux capabilities** for WoL: ``` sudo setcap cap_net_raw+ep /usr/bin/python3.13 # Or
   the DeQ launcher script ``` (Note: setting capabilities on the Python interpreter is a security
   trade‑off.)

---

## 3. Directory Structure and Portability

### 3.1 Current Hardcoded Paths
- `DATA_DIR = "/opt/deq"`
- `SCRIPTS_DIR = DATA_DIR + "/scripts"`
- `FONTS_DIR = DATA_DIR + "/fonts"`
- `HISTORY_DIR = DATA_DIR + "/history"`

### 3.2 Issues
1. **Not all Unix systems have `/opt`** (e.g., BSD, older Linux distributions).
2. **Root‑only installation** prevents non‑privileged users from testing or running DeQ.
3. **No configuration flexibility** – cannot relocate data directory for space or policy reasons.

### 3.3 Recommendations
1. **Make `DATA_DIR` configurable** via environment variable (`DEQ_DATA_DIR`) with fallback to
   `/opt/deq`.
2. **Support XDG Base Directory Specification** as an alternative:
   - `~/.local/share/deq` (user installation)
   - `/var/lib/deq` (system installation)
3. **Update `install.sh`** to detect the preferred location and adjust ownership/permissions
   accordingly.
4. **Add a `--data-dir` argument** to `server.py` for explicit override.

**Minimal change example:**
```python
import os
DATA_DIR = os.environ.get('DEQ_DATA_DIR', '/opt/deq')
```

---

## 4. Code Quality and Reliability

### 4.1 Exception Handling (Already Covered)
- Replace bare `except:` with specific exception types.
- Add logging for unexpected errors.

### 4.2 Subprocess Security
- Prefer list‑based arguments over `shell=True`.
- Validate and sanitize all external inputs.
- Use `timeout=` on every subprocess call.

### 4.3 Thread Safety
- Audit all shared mutable state (`transfer_jobs`, `device_status_cache`, `script_cache`).
- Ensure locks are held for the shortest possible time.
- Consider using `concurrent.futures.ThreadPoolExecutor` for managed parallelism.

### 4.4 Configuration Management
- `config.json` is loaded and saved as a whole; concurrent writes could corrupt the file.
- **Recommendation:** Use file locking (`fcntl.flock`) or atomic write (write to temp file, then
  `os.rename()`).

### 4.5 Testing
- The existing pytest suite (48 tests) is a good start but covers only ~17% of `server.py`.
- **Recommendation:** Increase coverage for error paths, edge cases, and concurrent operations.
- Use `unittest.mock` to simulate SSH failures, disk full, and network timeouts.

---

## 5. Deployment and Operations

### 5.1 Service Management
**Current:** Systemd service runs as root, installed to `/etc/systemd/system/deq.service`.

**Alternatives:**
- **User systemd:** `systemctl --user enable deq` (requires user‑level service file).
- **Non‑systemd init:** Provide examples for OpenRC, runit, supervisor.

**Recommendation:** Keep the current systemd service as the default, but document alternatives for
non‑systemd distributions.

### 5.2 Backup and Migration
- All state is in `config.json`; backup is straightforward.
- **Recommendation:** Document the backup procedure and include a `deq-backup` script that also
  preserves scripts, fonts, and extensions.

### 5.3 Upgrade Path
- `install.sh` overwrites `server.py` but preserves `config.json`.
- **Risk:** Breaking changes in `server.py` may require manual migration of `config.json`.
- **Recommendation:** Add a version field to `config.json` and implement migration helpers in
  `install.sh`.

### 5.4 Monitoring and Logging
- DeQ logs to stdout/journalctl; errors are often swallowed by bare `except:`.
- **Recommendation:** Integrate with `logging` module, provide log rotation, and alert on critical
  errors (e.g., SSH key failures, disk full).

---

## 6. Single‑File Concept Tradeoffs

### 6.1 Advantages
- **Zero‑dependency deployment** – just `python3 server.py`.
- **Easy auditing** – all code in one file (though 8,894 lines is challenging).
- **Version consistency** – no mismatch between HTML templates, CSS, JS, and Python.

### 6.2 Disadvantages
- **Maintainability** – navigating a 350 KB file is difficult; changes risk breaking unrelated
  functionality.
- **Testing** – unit testing individual functions requires importing the entire monolithic module.
- **Security auditing** – static analysis tools may struggle with mixed HTML/JS/CSS inside Python
  strings.
- **Performance** – loading and parsing the entire file each time (though mitigated by Python
  bytecode caching).

### 6.3 Mitigation Strategies
- **Keep the single‑file distribution** but adopt a **build‑time concatenation** approach: develop
  separate modules (`core.py`, `web.py`, `ssh.py`) and bundle them into `server.py` for release.
- **Use a lightweight templating system** (e.g., Jinja2) for HTML/CSS/JS, but still embed templates
  as strings in the final bundle.
- **Maintain a `src/` directory** for development, with a build script that generates the monolithic
  `server.py`.

**Recommendation:** Preserve the single‑file philosophy for end‑users, but improve the development
experience with modular source code.

---

## 7. Summary of Critical Actions

### Priority 1 (Security – Must Fix)
1. **Replace bare `except:`** with specific exception handling.
2. **Add timeouts** to all subprocess calls.
3. **Secure `config.json`** with 0600 permissions.
4. **Review and fix shell injection** (SKY‑D212) by eliminating `shell=True` where possible.

### Priority 2 (Usability – Should Fix)
1. **Make `DATA_DIR` configurable** via environment variable.
2. **Provide a non‑root installation option** for testing and user‑level deployments.
3. **Improve error logging** to help diagnose SSH and command failures.
4. **Document sudoers configuration** more prominently.

### Priority 3 (Maintainability – Could Fix)
1. **Modularize source code** while preserving single‑file distribution.
2. **Increase test coverage** to at least 50% of `server.py`.
3. **Add configuration migration** for future upgrades.
4. **Create a security checklist** for deployers.

---

## 8. Conclusion

DeQ is a clever, pragmatic tool that fills a real need for homelab management. Its “trusted network”
security model is appropriate for its target audience, but the current implementation carries
unnecessary risks that can be mitigated with relatively small changes.

The most urgent issues are **shell injection** and **bare exception handling** – both of which can
be fixed without breaking the single‑file architecture. Making the data directory configurable and
supporting non‑root installations would greatly improve portability and user choice.

By addressing these recommendations, DeQ can maintain its simplicity while becoming more robust,
secure, and widely adoptable.

---

**Appendix A: skylos Issue Summary**
- **SKY‑D212 (Critical)**: Shell injection – 7 unique locations.
- **SKY‑D216 (Critical)**: Threading concerns – 2 locations.
- **SKY‑D215 (High)**: Bare exception handling – 24 locations in `server.py`, plus many in test files.
- **SKY‑D209 (High)**: Missing subprocess timeout – 9 locations.

**Appendix B: Root‑Required Commands**
- `smartctl -A -H /dev/*`
- `systemctl poweroff`
- `systemctl suspend`
- `shutdown -h now`
- `docker` (if user not in docker group)
- Raw socket for WoL (requires `CAP_NET_RAW` or root)

**Appendix C: Suggested sudoers.d/deq File**
```
deq_user ALL=(ALL) NOPASSWD: /usr/sbin/smartctl, /usr/bin/systemctl poweroff, /usr/bin/systemctl suspend, /usr/sbin/shutdown
```
