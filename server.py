#!/usr/bin/env python3
"""
DeQ - Alles schläft, einer wacht.
USE BEHIND VPN ONLY! DO NOT EXPOSE TO PUBLIC INTERNET!

"""

import subprocess
import json
import os
import socket
import time
import threading
import argparse
import re
import glob
import shutil
import random
import shlex
import hashlib
import secrets
import hmac
from datetime import datetime, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from http.cookies import SimpleCookie
# === CONFIGURATION ===
DEFAULT_PORT = 5050
DATA_DIR = "/opt/deq"
CONFIG_FILE = f"{DATA_DIR}/config.json"
SCRIPTS_DIR = f"{DATA_DIR}/scripts"
PASSWORD_FILE = f"{DATA_DIR}/.password"
SESSION_SECRET_FILE = f"{DATA_DIR}/.session_secret"
SESSION_COOKIE_NAME = "deq_session"
VERSION = "0.9.12"

# SSH ControlMaster for connection reuse (reduces overhead when File Manager makes many SSH calls)
SSH_CONTROL_OPTS = ["-o", "ControlMaster=auto", "-o", "ControlPath=/tmp/deq-ssh-%r@%h:%p", "-o", "ControlPersist=60", "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=2"]
SSH_CONTROL_STR = "-o ControlMaster=auto -o ControlPath=/tmp/deq-ssh-%r@%h:%p -o ControlPersist=60 -o ServerAliveInterval=10 -o ServerAliveCountMax=2"

# Transfer job tracking (in-memory, lost on restart)
transfer_jobs = {}
transfer_jobs_lock = threading.Lock()

# === AUTHENTICATION ===
def is_auth_enabled():
    """Check if authentication is enabled (password file exists)."""
    return os.path.exists(PASSWORD_FILE)

def verify_password(password):
    """Verify password against stored hash."""
    if not is_auth_enabled():
        return True
    try:
        with open(PASSWORD_FILE, 'r') as f:
            stored = f.read().strip()
        salt_hex, key_hex = stored.split(':')
        salt = bytes.fromhex(salt_hex)
        key = hashlib.scrypt(password.encode('utf-8'), salt=salt, n=16384, r=8, p=1, dklen=32)
        return secrets.compare_digest(key.hex(), key_hex)
    except:
        return False

def get_session_secret():
    """Get or create session signing secret."""
    if os.path.exists(SESSION_SECRET_FILE):
        with open(SESSION_SECRET_FILE, 'r') as f:
            return f.read().strip()
    secret = secrets.token_hex(32)
    with open(SESSION_SECRET_FILE, 'w') as f:
        f.write(secret)
    os.chmod(SESSION_SECRET_FILE, 0o600)
    return secret

def create_session_token():
    """Create signed session token."""
    timestamp = str(int(time.time()))
    signature = hmac.new(get_session_secret().encode(), timestamp.encode(), 'sha256').hexdigest()
    return f"{timestamp}:{signature}"

def verify_session_token(token):
    """Verify session token signature."""
    if not token:
        return False
    try:
        timestamp, signature = token.split(':')
        expected = hmac.new(get_session_secret().encode(), timestamp.encode(), 'sha256').hexdigest()
        return secrets.compare_digest(signature, expected)
    except:
        return False

def format_size(bytes_val):
    """Format bytes as human-readable string."""
    if bytes_val < 1024:
        return f"{bytes_val} B"
    elif bytes_val < 1024 * 1024:
        return f"{bytes_val / 1024:.1f} KB"
    elif bytes_val < 1024 * 1024 * 1024:
        return f"{bytes_val / (1024 * 1024):.1f} MB"
    elif bytes_val < 1024 * 1024 * 1024 * 1024:
        return f"{bytes_val / (1024 * 1024 * 1024):.1f} GB"
    else:
        return f"{bytes_val / (1024 * 1024 * 1024 * 1024):.1f} TB"

def get_path_size(device, path):
    """Get size of path in bytes via du -sb. Returns int or None on error."""
    try:
        safe_path = shlex.quote(path)
        if device.get('is_host', False):
            result = subprocess.run(f"du -sb {safe_path} 2>/dev/null | cut -f1",
                                    shell=True, capture_output=True, text=True, timeout=60)
        else:
            ssh_config = device.get('ssh', {})
            user = ssh_config.get('user')
            port = ssh_config.get('port', 22)
            ip = device.get('ip')
            if not user:
                return None
            result = subprocess.run(
                ["ssh"] + SSH_CONTROL_OPTS + ["-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
                 "-p", str(port), f"{user}@{ip}", f"du -sb {safe_path} 2>/dev/null | cut -f1"],
                capture_output=True, text=True, timeout=60
            )
        if result.returncode == 0 and result.stdout.strip():
            return int(result.stdout.strip())
        return None
    except:
        return None

def get_free_space(device, path):
    """Get free space at path in bytes. Returns int or None on error."""
    try:
        safe_path = shlex.quote(path)
        if device.get('is_host', False):
            return shutil.disk_usage(path).free
        else:
            ssh_config = device.get('ssh', {})
            user = ssh_config.get('user')
            port = ssh_config.get('port', 22)
            ip = device.get('ip')
            if not user:
                return None
            result = subprocess.run(
                ["ssh"] + SSH_CONTROL_OPTS + ["-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
                 "-p", str(port), f"{user}@{ip}", f"df -B1 {safe_path} 2>/dev/null | tail -1 | awk '{{print $4}}'"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0 and result.stdout.strip():
                return int(result.stdout.strip())
            return None
    except:
        return None

def run_rsync_with_progress(cmd, progress_callback, idle_timeout=60):
    """Run rsync and call progress_callback(percent, speed, eta) on updates.
    Returns (success: bool, error: str or None). Timeout only on idle (no progress)."""
    try:
        import fcntl
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        # Set non-blocking
        fd = process.stdout.fileno()
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

        last_progress_time = time.time()
        buffer = ""
        last_error = ""

        while True:
            try:
                chunk = process.stdout.read(4096)
                if chunk:
                    buffer += chunk.decode('utf-8', errors='replace')
                    last_progress_time = time.time()
            except (BlockingIOError, IOError):
                pass

            # Process complete lines
            while '\r' in buffer or '\n' in buffer:
                r_pos = buffer.find('\r')
                n_pos = buffer.find('\n')
                if r_pos == -1: r_pos = len(buffer)
                if n_pos == -1: n_pos = len(buffer)
                pos = min(r_pos, n_pos)

                line = buffer[:pos]
                buffer = buffer[pos+1:]

                if not line.strip():
                    continue

                match = re.search(r'(\d+)%\s+([\d.,]+\s*\w+/s)\s+(\d+:\d+(?::\d+)?)', line)
                if match:
                    percent = int(match.group(1))
                    speed = match.group(2)
                    eta = match.group(3)
                    progress_callback(percent, speed, eta)
                elif 'error' in line.lower() or 'failed' in line.lower():
                    last_error = line.strip()

            if process.poll() is not None:
                break

            if time.time() - last_progress_time > idle_timeout:
                process.kill()
                return False, "Transfer stalled (no output for 60 seconds)"

            time.sleep(0.1)

        process.wait()
        return process.returncode == 0, last_error if process.returncode != 0 else None
    except Exception as e:
        return False, str(e)

def start_transfer_job(device, paths, dest_device, dest_path, operation, cleanup_path=None):
    """Start a transfer job in background thread. Returns job_id."""
    job_id = f"transfer_{int(time.time())}_{random.randint(1000, 9999)}"

    is_host = device.get('is_host', False)
    dest_is_host = dest_device.get('is_host', False)
    phases = 2 if (not is_host and not dest_is_host) else 1

    with transfer_jobs_lock:
        transfer_jobs[job_id] = {
            "status": "running",
            "progress": 0,
            "phase": 1,
            "phases": phases,
            "speed": None,
            "eta": None,
            "error": None,
            "started_at": time.time()
        }

    thread = threading.Thread(
        target=run_transfer_job,
        args=(job_id, device, paths, dest_device, dest_path, operation, cleanup_path)
    )
    thread.daemon = True
    thread.start()

    return job_id

def update_job_progress(job_id, progress, speed=None, eta=None, phase=None):
    """Update job progress."""
    with transfer_jobs_lock:
        if job_id in transfer_jobs:
            transfer_jobs[job_id]["progress"] = progress
            if speed:
                transfer_jobs[job_id]["speed"] = speed
            if eta:
                transfer_jobs[job_id]["eta"] = eta
            if phase:
                transfer_jobs[job_id]["phase"] = phase

def complete_job(job_id, error=None):
    """Mark job as complete or failed."""
    with transfer_jobs_lock:
        if job_id in transfer_jobs:
            transfer_jobs[job_id]["status"] = "error" if error else "complete"
            transfer_jobs[job_id]["error"] = error
            transfer_jobs[job_id]["completed_at"] = time.time()

def get_job_status(job_id):
    """Get current job status."""
    cleanup_old_jobs()
    with transfer_jobs_lock:
        job = transfer_jobs.get(job_id)
        if not job:
            return {"status": "not_found"}
        return job.copy()

def cleanup_old_jobs(max_age=300):
    """Remove completed jobs older than max_age seconds."""
    now = time.time()
    with transfer_jobs_lock:
        to_remove = [
            jid for jid, job in transfer_jobs.items()
            if job["status"] in ("complete", "error")
            and job.get("completed_at", 0) + max_age < now
        ]
        for jid in to_remove:
            del transfer_jobs[jid]

def run_transfer_job(job_id, device, paths, dest_device, dest_path, operation, cleanup_path=None):
    """Execute transfer in background thread."""
    try:
        ssh_config = device.get('ssh', {})
        user = ssh_config.get('user')
        port = ssh_config.get('port', 22)
        ip = device.get('ip')
        is_host = device.get('is_host', False)

        dest_ssh = dest_device.get('ssh', {})
        dest_user = dest_ssh.get('user')
        dest_port = dest_ssh.get('port', 22)
        dest_ip = dest_device.get('ip')
        dest_is_host = dest_device.get('is_host', False)

        for src_path in paths:
            safe_src = shlex.quote(src_path)
            safe_dest = shlex.quote(dest_path)

            def progress_callback(percent, speed, eta):
                update_job_progress(job_id, percent, speed, eta)

            if is_host and dest_is_host:
                cmd = f"rsync -a --progress {safe_src} {safe_dest}/"
                success, err = run_rsync_with_progress(cmd, progress_callback)

            elif is_host and not dest_is_host:
                cmd = f"rsync -a --progress -e 'ssh {SSH_CONTROL_STR} -o StrictHostKeyChecking=no -p {dest_port}' {safe_src} {dest_user}@{dest_ip}:{safe_dest}/"
                success, err = run_rsync_with_progress(cmd, progress_callback)

            elif not is_host and dest_is_host:
                cmd = f"rsync -a --progress -e 'ssh {SSH_CONTROL_STR} -o StrictHostKeyChecking=no -p {port}' {user}@{ip}:{safe_src} {safe_dest}/"
                success, err = run_rsync_with_progress(cmd, progress_callback)

            elif device.get('id') == dest_device.get('id'):
                # Same remote device - run rsync directly on remote
                ssh_cmd = ["ssh"] + SSH_CONTROL_OPTS + ["-o", "StrictHostKeyChecking=no", "-p", str(port), f"{user}@{ip}",
                           f"rsync -a {safe_src} {safe_dest}/"]
                result = subprocess.run(ssh_cmd, capture_output=True, text=True)
                success = result.returncode == 0
                err = result.stderr.strip() if not success else None

            else:
                # Remote to remote (two phases, via host)
                temp_path = f"/tmp/deq_transfer_{job_id}"
                safe_temp = shlex.quote(temp_path)

                # Phase 1: Remote to Host
                update_job_progress(job_id, 0, phase=1)
                cmd1 = f"rsync -a --progress -e 'ssh {SSH_CONTROL_STR} -o StrictHostKeyChecking=no -p {port}' {user}@{ip}:{safe_src} {safe_temp}/"
                success, err = run_rsync_with_progress(cmd1, progress_callback)

                if not success:
                    subprocess.run(f"rm -rf {safe_temp}", shell=True)
                    complete_job(job_id, f"Download failed: {err}")
                    return

                # Phase 2: Host to Remote
                update_job_progress(job_id, 0, phase=2)
                src_name = src_path.rstrip('/').split('/')[-1]
                safe_temp_src = shlex.quote(f"{temp_path}/{src_name}")
                cmd2 = f"rsync -a --progress -e 'ssh {SSH_CONTROL_STR} -o StrictHostKeyChecking=no -p {dest_port}' {safe_temp_src} {dest_user}@{dest_ip}:{safe_dest}/"
                success, err = run_rsync_with_progress(cmd2, progress_callback)

                subprocess.run(f"rm -rf {safe_temp}", shell=True)

            if not success:
                complete_job(job_id, f"Failed to {operation} {src_path}: {err}")
                return

            # For move: delete source after successful copy
            if operation == 'move':
                if is_host:
                    subprocess.run(f"rm -rf {safe_src}", shell=True)
                else:
                    subprocess.run(
                        ["ssh"] + SSH_CONTROL_OPTS + ["-o", "StrictHostKeyChecking=no",
                         "-p", str(port), f"{user}@{ip}", f"rm -rf {safe_src}"],
                        capture_output=True
                    )

        # Cleanup temp directory if specified (used by extract cross-device)
        if cleanup_path:
            is_host = device.get('is_host', False)
            if is_host:
                subprocess.run(f"rm -rf {shlex.quote(cleanup_path)}", shell=True)
            else:
                ssh_config = device.get('ssh', {})
                subprocess.run(
                    ["ssh"] + SSH_CONTROL_OPTS + ["-o", "StrictHostKeyChecking=no",
                     "-p", str(ssh_config.get('port', 22)), f"{ssh_config.get('user')}@{device.get('ip')}",
                     f"rm -rf {shlex.quote(cleanup_path)}"],
                    capture_output=True
                )

        complete_job(job_id)

    except Exception as e:
        complete_job(job_id, str(e))

# === DEFAULT CONFIG ===
DEFAULT_ALERTS = {"online": True, "cpu": 90, "ram": 90, "cpu_temp": 80, "disk_usage": 90, "disk_temp": 60, "smart": True}

DEFAULT_HOST_DEVICE = {
    "id": "host",
    "name": "DeQ Host",
    "ip": "localhost",
    "icon": "cpu",
    "is_host": True
}

DEFAULT_CONFIG = {
    "settings": {
        "theme": "dark",
        "text_color": "#e0e0e0",
        "accent_color": "#2ed573",
        "section_order": ["devices", "links", "quick_actions", "tasks"]
    },
    "links": [],
    "quick_actions": [],
    "devices": [],
    "tasks": []
}

# === DATA MANAGEMENT ===
TASK_LOGS_DIR = f"{DATA_DIR}/task-logs"

def ensure_dirs():
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(SCRIPTS_DIR, exist_ok=True)
    os.makedirs(TASK_LOGS_DIR, exist_ok=True)

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            cfg = json.load(f)
            # Merge with defaults for missing keys
            for key in DEFAULT_CONFIG:
                if key not in cfg:
                    cfg[key] = DEFAULT_CONFIG[key]
            # Merge settings with defaults
            for key in DEFAULT_CONFIG.get('settings', {}):
                if key not in cfg.get('settings', {}):
                    cfg['settings'][key] = DEFAULT_CONFIG['settings'][key]
    else:
        cfg = DEFAULT_CONFIG.copy()
        cfg["devices"] = []

    # Ensure host device exists
    host_exists = any(d.get("is_host") for d in cfg.get("devices", []))
    if not host_exists:
        cfg["devices"].insert(0, DEFAULT_HOST_DEVICE.copy())

    return cfg

def save_config(config):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)

def get_config_with_defaults():
    cfg = CONFIG.copy()
    cfg['devices'] = []
    for dev in CONFIG.get('devices', []):
        d = dev.copy()
        d['alerts'] = {**DEFAULT_ALERTS, **dev.get('alerts', {})}
        cfg['devices'].append(d)
    return cfg

ensure_dirs()
CONFIG = load_config()

# === DEVICE STATUS CACHE ===
device_status_cache = {}
cache_lock = threading.Lock()
refresh_in_progress = set()

def get_cached_status(device_id):
    with cache_lock:
        return device_status_cache.get(device_id)

def set_cached_status(device_id, status):
    with cache_lock:
        device_status_cache[device_id] = status

def refresh_device_status_async(device):
    dev_id = device.get('id')
    if dev_id in refresh_in_progress:
        return
    refresh_in_progress.add(dev_id)

    def do_refresh():
        try:
            container_statuses = get_all_container_statuses(device)
            if device.get('is_host'):
                stats = get_local_stats()
                status = {"online": True, "stats": stats, "containers": container_statuses}
            else:
                online = ping_host(device.get('ip', ''))
                stats = None
                if online and device.get('ssh', {}).get('user'):
                    stats = get_remote_stats(device['ip'], device['ssh']['user'], device['ssh'].get('port', 22))
                status = {"online": online, "stats": stats, "containers": container_statuses}
            set_cached_status(dev_id, status)
        finally:
            refresh_in_progress.discard(dev_id)

    threading.Thread(target=do_refresh, daemon=True).start()

# === SYSTEM STATS (LOCAL) ===
def get_disk_smart_info():
    """Get SMART info and temps for all disks. Returns dict keyed by device name."""
    disks = {}
    try:
        result = subprocess.run(["lsblk", "-d", "-n", "-o", "NAME,TYPE"],
                                capture_output=True, text=True, timeout=5)
        for line in result.stdout.strip().split('\n'):
            parts = line.split()
            if len(parts) >= 2 and parts[1] == 'disk':
                dev_name = parts[0]
                disks[dev_name] = {"temp": None, "smart": None}
    except:
        pass

    for dev_name in disks:
        try:
            result = subprocess.run(["sudo", "smartctl", "-A", "-H", f"/dev/{dev_name}"],
                                    capture_output=True, text=True, timeout=10)
            output = result.stdout

            if "PASSED" in output:
                disks[dev_name]["smart"] = "ok"
            elif "FAILED" in output:
                disks[dev_name]["smart"] = "failed"

            for line in output.split('\n'):
                if 'Temperature' in line and '-' in line:
                    after_dash = line.split('-')[-1].strip()
                    first_num = after_dash.split()[0] if after_dash else ''
                    if first_num.isdigit() and 0 < int(first_num) < 100:
                        disks[dev_name]["temp"] = int(first_num)
                        break
        except:
            pass

    return disks

def get_container_stats():
    """Get CPU and RAM stats for all running containers."""
    containers = {}
    try:
        result = subprocess.run(
            ["docker", "stats", "--no-stream", "--format", "{{.Name}}:{{.CPUPerc}}:{{.MemPerc}}"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            for line in result.stdout.strip().split('\n'):
                if ':' in line:
                    parts = line.split(':')
                    if len(parts) >= 3:
                        name = parts[0]
                        cpu = parts[1].replace('%', '').strip()
                        mem = parts[2].replace('%', '').strip()
                        try:
                            containers[name] = {
                                "cpu": float(cpu),
                                "mem": float(mem)
                            }
                        except:
                            pass
    except:
        pass
    return containers

def get_local_stats():
    """Get stats for the device running DeQ."""
    stats = {"cpu": 0, "ram_used": 0, "ram_total": 0, "temp": None, "disks": [], "uptime": "", "disk_smart": {}, "container_stats": {}}

    try:
        with open('/proc/loadavg', 'r') as f:
            load = float(f.read().split()[0])
            cpu_count = os.cpu_count() or 1
            stats["cpu"] = min(100, int(load / cpu_count * 100))

        with open('/proc/meminfo', 'r') as f:
            meminfo = {}
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    meminfo[parts[0].rstrip(':')] = int(parts[1]) * 1024
            stats["ram_total"] = meminfo.get("MemTotal", 0)
            stats["ram_used"] = stats["ram_total"] - meminfo.get("MemAvailable", 0)

        thermal_zones = ["/sys/class/thermal/thermal_zone0/temp"]
        for zone in thermal_zones:
            if os.path.exists(zone):
                with open(zone, 'r') as f:
                    stats["temp"] = int(f.read().strip()) // 1000
                break

        result = subprocess.run(["df", "-B1", "--output=source,target,size,used"],
                                capture_output=True, text=True, timeout=5)
        for line in result.stdout.strip().split('\n')[1:]:
            parts = line.split()
            if len(parts) >= 4:
                source = parts[0]
                mount = parts[1]
                if mount in ['/', '/home'] or mount.startswith(('/mnt', '/media', '/srv')):
                    if int(parts[2]) > 1e9:
                        dev_name = source.split('/')[-1].rstrip('0123456789')
                        stats["disks"].append({
                            "mount": mount,
                            "total": int(parts[2]),
                            "used": int(parts[3]),
                            "device": dev_name
                        })

        with open('/proc/uptime', 'r') as f:
            uptime_seconds = float(f.read().split()[0])
            days = int(uptime_seconds // 86400)
            hours = int((uptime_seconds % 86400) // 3600)
            stats["uptime"] = f"{days}d {hours}h" if days > 0 else f"{hours}h"

        stats["disk_smart"] = get_disk_smart_info()
        stats["container_stats"] = get_container_stats()

    except Exception as e:
        print(f"Error getting local stats: {e}")

    return stats

# === QUICK ACTIONS (Script Execution) ===
def discover_scripts():
    """Find all executable scripts in SCRIPTS_DIR recursively."""
    scripts = []
    if not os.path.exists(SCRIPTS_DIR):
        return scripts
    for root, dirs, files in os.walk(SCRIPTS_DIR):
        for f in files:
            full_path = os.path.join(root, f)
            if os.access(full_path, os.X_OK):
                rel_path = os.path.relpath(full_path, SCRIPTS_DIR)
                scripts.append({"path": rel_path, "name": f})
    return sorted(scripts, key=lambda x: x["path"])

def execute_quick_action(script_path):
    """Start a script in the background."""
    full_path = os.path.join(SCRIPTS_DIR, script_path)
    if not os.path.realpath(full_path).startswith(os.path.realpath(SCRIPTS_DIR)):
        return {"success": False, "error": "Invalid script path"}
    if not os.path.exists(full_path):
        return {"success": False, "error": "Script not found"}
    if not os.access(full_path, os.X_OK):
        return {"success": False, "error": "Script not executable"}
    try:
        subprocess.Popen([full_path], cwd=SCRIPTS_DIR, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}

# === REMOTE STATS (SSH) ===
def get_remote_stats(ip, user, port=22):
    """Get stats from remote device via SSH."""
    stats = {"cpu": 0, "ram_used": 0, "ram_total": 0, "temp": None, "disks": [], "uptime": "", "disk_smart": {}, "container_stats": {}}
    ssh_base = ["ssh"] + SSH_CONTROL_OPTS + ["-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=3", "-o", "BatchMode=yes", "-p", str(port), f"{user}@{ip}"]

    # Basic stats (required)
    try:
        cmd = "nproc; echo '---'; cat /proc/loadavg; echo '---'; cat /proc/meminfo | head -10; echo '---'; cat /sys/class/thermal/thermal_zone*/temp 2>/dev/null | head -1; echo '---'; cat /proc/uptime"
        result = subprocess.run(ssh_base + [cmd], capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            return None
        parts = result.stdout.split('---')

        cpu_count = int(parts[0].strip()) if parts[0].strip().isdigit() else 4
        load = float(parts[1].strip().split()[0])
        stats["cpu"] = min(100, int(load / cpu_count * 100))

        meminfo = {}
        for line in parts[2].strip().split('\n'):
            if ':' in line:
                key, val = line.split(':')
                meminfo[key.strip()] = int(val.split()[0]) * 1024
        stats["ram_total"] = meminfo.get("MemTotal", 0)
        if "MemAvailable" in meminfo:
            stats["ram_used"] = stats["ram_total"] - meminfo["MemAvailable"]
        else:
            free = meminfo.get("MemFree", 0) + meminfo.get("Buffers", 0) + meminfo.get("Cached", 0)
            stats["ram_used"] = stats["ram_total"] - free

        temp_str = parts[3].strip()
        if temp_str.isdigit():
            stats["temp"] = int(temp_str) // 1000

        uptime_seconds = float(parts[4].strip().split()[0])
        days = int(uptime_seconds // 86400)
        hours = int((uptime_seconds % 86400) // 3600)
        stats["uptime"] = f"{days}d {hours}h" if days > 0 else f"{hours}h"
    except:
        return None

    # Disks (optional)
    try:
        result = subprocess.run(ssh_base + ["df -B1 --output=source,target,size,used 2>/dev/null || df -B1"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            for line in result.stdout.strip().split('\n')[1:]:
                cols = line.split()
                if len(cols) >= 4:
                    source, mount = cols[0], cols[1]
                    if mount in ['/', '/home'] or mount.startswith(('/mnt', '/media', '/srv')):
                        try:
                            if int(cols[2]) > 1e9:
                                stats["disks"].append({"mount": mount, "total": int(cols[2]), "used": int(cols[3])})
                        except:
                            pass
    except:
        pass

    # SMART (optional)
    try:
        result = subprocess.run(ssh_base + ["lsblk -d -n -o NAME,TYPE 2>/dev/null"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            disk_names = []
            for line in result.stdout.strip().split('\n'):
                cols = line.split()
                if len(cols) >= 2 and cols[1] == 'disk':
                    disk_names.append(cols[0])
                    stats["disk_smart"][cols[0]] = {"temp": None, "smart": None}

            for dev in disk_names:
                try:
                    result = subprocess.run(ssh_base + [f"sudo smartctl -A -H /dev/{dev} 2>/dev/null"], capture_output=True, text=True, timeout=5)
                    output = result.stdout
                    if "PASSED" in output:
                        stats["disk_smart"][dev]["smart"] = "ok"
                    elif "FAILED" in output:
                        stats["disk_smart"][dev]["smart"] = "failed"
                    for line in output.split('\n'):
                        if 'Temperature' in line and '-' in line:
                            after_dash = line.split('-')[-1].strip()
                            first_num = after_dash.split()[0] if after_dash else ''
                            if first_num.isdigit() and 0 < int(first_num) < 100:
                                stats["disk_smart"][dev]["temp"] = int(first_num)
                                break
                except:
                    pass
    except:
        pass

    # Docker stats (optional)
    try:
        result = subprocess.run(ssh_base + ["docker stats --no-stream --format '{{.Name}}:{{.CPUPerc}}:{{.MemPerc}}' 2>/dev/null"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            for line in result.stdout.strip().split('\n'):
                if ':' in line:
                    cols = line.split(':')
                    if len(cols) >= 3:
                        try:
                            stats["container_stats"][cols[0]] = {"cpu": float(cols[1].replace('%', '')), "mem": float(cols[2].replace('%', ''))}
                        except:
                            pass
    except:
        pass

    return stats

# === FOLDER BROWSING ===
def browse_folder(device, path="/"):
    """List folders in a directory on a device (local or remote via SSH)."""
    try:
        # Normalize path
        path = path.rstrip('/') or '/'

        if device.get('is_host'):
            # Local browsing
            if not os.path.isdir(path):
                return {"success": False, "error": f"Not a directory: {path}"}

            folders = []
            try:
                for entry in os.listdir(path):
                    full_path = os.path.join(path, entry)
                    if os.path.isdir(full_path) and not entry.startswith('.'):
                        folders.append(entry)
            except PermissionError:
                return {"success": False, "error": "Permission denied"}

            folders.sort(key=str.lower)
            return {"success": True, "path": path, "folders": folders}

        else:
            # Remote browsing via SSH
            ssh_config = device.get('ssh', {})
            user = ssh_config.get('user')
            port = ssh_config.get('port', 22)
            ip = device.get('ip')

            if not user:
                return {"success": False, "error": "SSH not configured for this device"}

            # Use find to list only directories, exclude hidden
            cmd = f"find '{path}' -maxdepth 1 -mindepth 1 -type d ! -name '.*' -printf '%f\\n' 2>/dev/null | sort -f"
            result = subprocess.run(
                ["ssh"] + SSH_CONTROL_OPTS + ["-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
                 "-p", str(port), f"{user}@{ip}", cmd],
                capture_output=True, text=True, timeout=15
            )

            if result.returncode != 0 and not result.stdout:
                # Check if path exists
                check_cmd = f"test -d '{path}' && echo 'exists' || echo 'notfound'"
                check_result = subprocess.run(
                    ["ssh"] + SSH_CONTROL_OPTS + ["-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
                     "-p", str(port), f"{user}@{ip}", check_cmd],
                    capture_output=True, text=True, timeout=10
                )
                if "notfound" in check_result.stdout:
                    return {"success": False, "error": f"Path not found: {path}"}
                return {"success": False, "error": "Permission denied or SSH error"}

            folders = [f for f in result.stdout.strip().split('\n') if f]
            return {"success": True, "path": path, "folders": folders}

    except subprocess.TimeoutExpired:
        return {"success": False, "error": "SSH timeout"}
    except Exception as e:
        return {"success": False, "error": str(e)}


# === FILE MANAGER ===
def list_files(device, path="/"):
    """List files and folders with size and date."""
    try:
        path = path.rstrip('/') or '/'
        files = []

        if device.get('is_host'):
            # Local listing
            if not os.path.isdir(path):
                return {"success": False, "error": f"Not a directory: {path}"}

            try:
                for entry in os.listdir(path):
                    if entry.startswith('.'):
                        continue
                    full_path = os.path.join(path, entry)
                    try:
                        stat = os.stat(full_path)
                        is_dir = os.path.isdir(full_path)
                        files.append({
                            "name": entry,
                            "is_dir": is_dir,
                            "size": stat.st_size if not is_dir else 0,
                            "mtime": int(stat.st_mtime)
                        })
                    except (PermissionError, OSError):
                        continue
            except PermissionError:
                return {"success": False, "error": "Permission denied"}

        else:
            # Remote listing via SSH
            ssh_config = device.get('ssh', {})
            user = ssh_config.get('user')
            port = ssh_config.get('port', 22)
            ip = device.get('ip')

            if not user:
                return {"success": False, "error": "SSH not configured"}

            # Use ls -la (works on BusyBox/Synology too)
            # Format: drwxr-xr-x 2 user group 4096 Dec  3 10:30 filename
            cmd = f"ls -la '{path}' 2>/dev/null"
            result = subprocess.run(
                ["ssh"] + SSH_CONTROL_OPTS + ["-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
                 "-p", str(port), f"{user}@{ip}", cmd],
                capture_output=True, text=True, timeout=30
            )

            if result.returncode != 0:
                return {"success": False, "error": "Failed to list directory"}

            for line in result.stdout.strip().split('\n'):
                if not line or line.startswith('total'):
                    continue
                parts = line.split()
                if len(parts) < 9:
                    continue

                perms = parts[0]
                size = int(parts[4]) if parts[4].isdigit() else 0
                # Parse date: "Dec 3 10:30" or "Dec 3 2023"
                month = parts[5]
                day = parts[6]
                time_or_year = parts[7]
                name = ' '.join(parts[8:])

                if name in ('.', '..') or name.startswith('.'):
                    continue

                # Convert to timestamp (approximate)
                try:
                    months = {'Jan':1,'Feb':2,'Mar':3,'Apr':4,'May':5,'Jun':6,
                              'Jul':7,'Aug':8,'Sep':9,'Oct':10,'Nov':11,'Dec':12}
                    mon = months.get(month, 1)
                    d = int(day)
                    now = datetime.now()
                    if ':' in time_or_year:
                        # This year
                        yr = now.year
                    else:
                        yr = int(time_or_year)
                    mtime = int(datetime(yr, mon, d).timestamp())
                except Exception:
                    mtime = 0

                is_dir = perms.startswith('d')
                files.append({
                    "name": name,
                    "is_dir": is_dir,
                    "size": size if not is_dir else 0,
                    "mtime": mtime
                })

        # Sort: folders first, then by name
        files.sort(key=lambda f: (not f['is_dir'], f['name'].lower()))

        # Get disk space for current path
        storage = None
        try:
            if device.get('is_host'):
                stat = os.statvfs(path)
                total = stat.f_blocks * stat.f_frsize
                free = stat.f_bavail * stat.f_frsize
                used = total - free
                storage = {
                    "total": total,
                    "used": used,
                    "free": free,
                    "percent": round((used / total) * 100) if total > 0 else 0
                }
            else:
                # Remote via SSH - use df for the path
                ssh_config = device.get('ssh', {})
                user = ssh_config.get('user')
                port = ssh_config.get('port', 22)
                ip = device.get('ip')
                if user:
                    cmd = f"df -B1 '{path}' 2>/dev/null | tail -1"
                    result = subprocess.run(
                        ["ssh"] + SSH_CONTROL_OPTS + ["-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
                         "-p", str(port), f"{user}@{ip}", cmd],
                        capture_output=True, text=True, timeout=10
                    )
                    if result.returncode == 0 and result.stdout.strip():
                        parts = result.stdout.strip().split()
                        if len(parts) >= 4:
                            total = int(parts[1]) if parts[1].isdigit() else 0
                            used = int(parts[2]) if parts[2].isdigit() else 0
                            free = int(parts[3]) if parts[3].isdigit() else 0
                            storage = {
                                "total": total,
                                "used": used,
                                "free": free,
                                "percent": round((used / total) * 100) if total > 0 else 0
                            }
        except Exception:
            pass  # Storage info is optional

        return {"success": True, "path": path, "files": files, "storage": storage}

    except subprocess.TimeoutExpired:
        return {"success": False, "error": "SSH timeout"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def file_operation(device, operation, paths, dest_device=None, dest_path=None, new_name=None):
    """Execute file operations: copy, move, rename, delete, zip."""
    try:
        ssh_config = device.get('ssh', {})
        user = ssh_config.get('user')
        port = ssh_config.get('port', 22)
        ip = device.get('ip')
        is_host = device.get('is_host', False)

        if not is_host and not user:
            return {"success": False, "error": "SSH not configured"}

        def run_local(cmd):
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
            return result.returncode == 0, result.stderr

        def run_remote(cmd):
            result = subprocess.run(
                ["ssh"] + SSH_CONTROL_OPTS + ["-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
                 "-p", str(port), f"{user}@{ip}", cmd],
                capture_output=True, text=True, timeout=300
            )
            return result.returncode == 0, result.stderr

        run_cmd = run_local if is_host else run_remote

        if operation == 'delete':
            for p in paths:
                safe_path = shlex.quote(p)
                success, err = run_cmd(f"rm -rf {safe_path}")
                if not success:
                    return {"success": False, "error": f"Failed to delete {p}: {err}"}
            return {"success": True}

        elif operation == 'rename':
            if len(paths) != 1 or not new_name:
                return {"success": False, "error": "Rename requires exactly one file and new name"}
            old_path = shlex.quote(paths[0])
            parent = '/'.join(paths[0].rstrip('/').split('/')[:-1]) or '/'
            new_path = shlex.quote(f"{parent}/{new_name}")
            success, err = run_cmd(f"mv {old_path} {new_path}")
            if not success:
                return {"success": False, "error": f"Failed to rename: {err}"}
            return {"success": True}

        elif operation == 'mkdir':
            if not new_name:
                return {"success": False, "error": "Folder name required"}
            if '/' in new_name or '\x00' in new_name:
                return {"success": False, "error": "Invalid folder name"}
            parent = paths[0] if paths else '/'
            folder_path = shlex.quote(f"{parent.rstrip('/')}/{new_name}")
            success, err = run_cmd(f"mkdir {folder_path}")
            if not success:
                return {"success": False, "error": f"Failed to create folder: {err}"}
            return {"success": True}

        elif operation == 'zip':
            if not paths:
                return {"success": False, "error": "No files selected"}

            # Determine output path (in same directory as first file)
            first_path = paths[0].rstrip('/')
            parent = '/'.join(first_path.split('/')[:-1]) or '/'
            base_name = first_path.split('/')[-1]

            # Check if zip is available, else use tar
            check_zip = "which zip > /dev/null 2>&1 && echo 'zip' || echo 'tar'"
            if is_host:
                result = subprocess.run(check_zip, shell=True, capture_output=True, text=True)
                use_zip = 'zip' in result.stdout
            else:
                result = subprocess.run(
                    ["ssh"] + SSH_CONTROL_OPTS + ["-o", "StrictHostKeyChecking=no", "-p", str(port), f"{user}@{ip}", check_zip],
                    capture_output=True, text=True, timeout=10
                )
                use_zip = 'zip' in result.stdout

            if len(paths) == 1:
                archive_name = f"{base_name}.zip" if use_zip else f"{base_name}.tar.gz"
            else:
                archive_name = f"archive_{int(time.time())}.zip" if use_zip else f"archive_{int(time.time())}.tar.gz"

            archive_path = f"{parent}/{archive_name}"

            # Build file list for command
            rel_names = ' '.join([shlex.quote(p.split('/')[-1]) for p in paths])
            safe_parent = shlex.quote(parent)
            safe_archive = shlex.quote(archive_name)

            if use_zip:
                cmd = f"cd {safe_parent} && zip -r {safe_archive} {rel_names}"
            else:
                cmd = f"cd {safe_parent} && tar -czf {safe_archive} {rel_names}"

            success, err = run_cmd(cmd)
            if not success:
                return {"success": False, "error": f"Failed to create archive: {err}"}
            return {"success": True, "archive": archive_path}

        elif operation == 'extract':
            if len(paths) != 1:
                return {"success": False, "error": "Select exactly one archive"}
            if not dest_path:
                return {"success": False, "error": "Destination path required"}

            archive = paths[0]
            name = archive.split('/')[-1].lower()
            safe_archive = shlex.quote(archive)

            # Determine extract command based on format
            if name.endswith('.zip'):
                extract_cmd = lambda dest: f"unzip -o {safe_archive} -d {shlex.quote(dest)}"
            elif name.endswith(('.tar.gz', '.tgz')):
                extract_cmd = lambda dest: f"tar -xzf {safe_archive} -C {shlex.quote(dest)}"
            elif name.endswith(('.tar.bz2', '.tbz2')):
                extract_cmd = lambda dest: f"tar -xjf {safe_archive} -C {shlex.quote(dest)}"
            elif name.endswith(('.tar.xz', '.txz')):
                extract_cmd = lambda dest: f"tar -xJf {safe_archive} -C {shlex.quote(dest)}"
            elif name.endswith('.tar'):
                extract_cmd = lambda dest: f"tar -xf {safe_archive} -C {shlex.quote(dest)}"
            else:
                return {"success": False, "error": "Unsupported archive format"}

            # Same device: extract directly to dest_path
            if not dest_device or dest_device.get('id') == device.get('id'):
                success, err = run_cmd(extract_cmd(dest_path))
                if not success:
                    if 'unzip' in err.lower() or 'not found' in err.lower():
                        return {"success": False, "error": "unzip not installed"}
                    return {"success": False, "error": f"Extract failed: {err}"}
                return {"success": True}

            # Cross device: extract to temp, then transfer
            temp_dir = f"/tmp/deq_extract_{int(time.time())}"
            run_cmd(f"mkdir -p {shlex.quote(temp_dir)}")
            success, err = run_cmd(extract_cmd(temp_dir))
            if not success:
                run_cmd(f"rm -rf {shlex.quote(temp_dir)}")
                if 'unzip' in err.lower() or 'not found' in err.lower():
                    return {"success": False, "error": "unzip not installed"}
                return {"success": False, "error": f"Extract failed: {err}"}

            # Get list of extracted items
            if is_host:
                items = [f"{temp_dir}/{f}" for f in os.listdir(temp_dir)]
            else:
                result = subprocess.run(
                    ["ssh"] + SSH_CONTROL_OPTS + ["-o", "StrictHostKeyChecking=no", "-p", str(port), f"{user}@{ip}",
                     f"ls -1 {shlex.quote(temp_dir)}"],
                    capture_output=True, text=True, timeout=30
                )
                items = [f"{temp_dir}/{f}" for f in result.stdout.strip().split('\n') if f]

            if not items:
                run_cmd(f"rm -rf {shlex.quote(temp_dir)}")
                return {"success": False, "error": "Archive was empty"}

            # Start transfer job (will clean up temp_dir when done)
            job_id = start_transfer_job(device, items, dest_device, dest_path, 'copy', cleanup_path=temp_dir)
            return {"success": True, "job_id": job_id, "transfer": True}

        elif operation == 'preflight':
            if not paths:
                return {"ok": False, "error": "No paths specified"}
            if not dest_device or not dest_path:
                return {"ok": False, "error": "Destination required"}

            dest_is_host = dest_device.get('is_host', False)

            # Get total source size (all selected items)
            src_size = 0
            for p in paths:
                size = get_path_size(device, p)
                if size is None:
                    return {"ok": False, "error": f"Cannot determine size of {p}"}
                src_size += size

            # Check destination space
            dest_free = get_free_space(dest_device, dest_path)
            if dest_free is None:
                return {"ok": False, "error": "Cannot check destination space"}

            if src_size > dest_free:
                return {"ok": False, "error": f"Not enough space on destination (need {format_size(src_size)}, have {format_size(dest_free)})"}

            # Remote-to-Remote: Check host space (but not if same device)
            same_device = device.get('id') == dest_device.get('id')
            needs_host = not is_host and not dest_is_host and not same_device
            host_free = None

            if needs_host:
                host_free = shutil.disk_usage("/tmp").free
                if src_size > host_free:
                    return {"ok": False, "error": f"Not enough space on host for transfer (need {format_size(src_size)}, have {format_size(host_free)})"}

            return {
                "ok": True,
                "src_size": src_size,
                "dest_free": dest_free,
                "host_free": host_free,
                "needs_host_transfer": needs_host
            }

        elif operation in ('copy', 'move'):
            if not dest_device or not dest_path:
                return {"success": False, "error": "Destination required"}

            dest_is_host = dest_device.get('is_host', False)
            if not dest_is_host and not dest_device.get('ssh', {}).get('user'):
                return {"success": False, "error": "Destination SSH not configured"}

            # Start async transfer job
            job_id = start_transfer_job(device, paths, dest_device, dest_path, operation)
            return {"success": True, "job_id": job_id}

        else:
            return {"success": False, "error": f"Unknown operation: {operation}"}

    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Operation timeout"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def get_file_for_download(device, file_path):
    """Get file content for download. Returns (content_bytes, filename, error)."""
    try:
        if device.get('is_host'):
            if not os.path.isfile(file_path):
                return None, None, "Not a file"
            with open(file_path, 'rb') as f:
                content = f.read()
            filename = os.path.basename(file_path)
            return content, filename, None
        else:
            ssh_config = device.get('ssh', {})
            user = ssh_config.get('user')
            port = ssh_config.get('port', 22)
            ip = device.get('ip')

            if not user:
                return None, None, "SSH not configured"

            # Use cat to get file content
            result = subprocess.run(
                ["ssh"] + SSH_CONTROL_OPTS + ["-o", "StrictHostKeyChecking=no", "-p", str(port),
                 f"{user}@{ip}", f"cat '{file_path}'"],
                capture_output=True, timeout=60
            )

            if result.returncode != 0:
                return None, None, "Failed to read file"

            filename = file_path.rstrip('/').split('/')[-1]
            return result.stdout, filename, None

    except subprocess.TimeoutExpired:
        return None, None, "Timeout"
    except Exception as e:
        return None, None, str(e)


def upload_file(device, dest_path, filename, content):
    """Upload file content to device. Returns {"success": bool, "error": str}."""
    try:
        full_path = os.path.join(dest_path, filename)

        if device.get('is_host'):
            # Direct write for host
            with open(full_path, 'wb') as f:
                f.write(content)
            return {"success": True}
        else:
            # Remote: write temp file, then SCP
            ssh_config = device.get('ssh', {})
            user = ssh_config.get('user')
            port = ssh_config.get('port', 22)
            ip = device.get('ip')

            if not user:
                return {"success": False, "error": "SSH not configured"}

            # Write to temp file
            import tempfile
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                tmp.write(content)
                tmp_path = tmp.name

            try:
                # SCP to remote
                result = subprocess.run(
                    ["scp", "-o", "StrictHostKeyChecking=no", "-P", str(port),
                     tmp_path, f"{user}@{ip}:{full_path}"],
                    capture_output=True, timeout=600
                )
                if result.returncode != 0:
                    return {"success": False, "error": result.stderr.decode().strip() or "SCP failed"}
                return {"success": True}
            finally:
                os.unlink(tmp_path)

    except Exception as e:
        return {"success": False, "error": str(e)}


# === DEVICE OPERATIONS ===
def ping_host(ip, timeout=1):
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", str(timeout), ip],
            capture_output=True, timeout=timeout + 2
        )
        return result.returncode == 0
    except:
        return False

def get_health_status():
    """Get health status for all devices and containers (for mobile app polling)."""
    devices = []
    containers_running = 0
    containers_stopped = 0

    for dev in CONFIG.get('devices', []):
        dev_id = dev.get('id')
        cached = get_cached_status(dev_id)
        refresh_device_status_async(dev)

        online = cached.get('online') if cached else None
        stats = cached.get('stats') if cached else None
        container_statuses = cached.get('containers', {}) if cached else {}

        device_alerts = dev.get('alerts', {})
        alerts = {**DEFAULT_ALERTS, **device_alerts}

        # Add container alerts from actual container statuses (all enabled by default)
        # Merge with any user-configured container alerts
        if container_statuses:
            default_container_alerts = {name: True for name in container_statuses.keys()}
            user_container_alerts = alerts.get('containers', {})
            alerts['containers'] = {**default_container_alerts, **user_container_alerts}

        device_info = {
            "id": dev_id,
            "name": dev.get('name', 'Unknown'),
            "online": online,
            "alerts": alerts,
            "is_host": dev.get('is_host', False)
        }

        if stats:
            device_info["cpu"] = stats.get("cpu", 0)
            device_info["ram"] = int(stats.get("ram_used", 0) / max(stats.get("ram_total", 1), 1) * 100)
            device_info["temp"] = stats.get("temp")
            # Disk usage - max usage across all disks
            disks = stats.get("disks", [])
            if disks:
                max_disk_usage = max(int(d.get("used", 0) / max(d.get("total", 1), 1) * 100) for d in disks)
                device_info["disk"] = max_disk_usage
            # SMART status and disk temp
            disk_smart = stats.get("disk_smart", {})
            smart_failed = any(s.get("smart") == "failed" for s in disk_smart.values())
            if smart_failed:
                device_info["smart_failed"] = True
            disk_temps = [s.get("temp") for s in disk_smart.values() if s.get("temp") is not None]
            if disk_temps:
                device_info["disk_temp"] = max(disk_temps)

        # Container statuses for this device
        device_containers = {}
        for name, state in container_statuses.items():
            device_containers[name] = state
            if state == 'running':
                containers_running += 1
            else:
                containers_stopped += 1
        if device_containers:
            device_info["containers"] = device_containers

        devices.append(device_info)

    # Task statuses - include all tasks with enabled status
    tasks = []
    for task in CONFIG.get('tasks', []):
        tasks.append({
            "id": task.get('id'),
            "name": task.get('name', 'Unknown'),
            "status": task.get('last_status'),
            "error": task.get('last_error'),
            "last_run": task.get('last_run'),
            "enabled": task.get('enabled', True)
        })

    return {
        "devices": devices,
        "containers": {
            "running": containers_running,
            "stopped": containers_stopped
        },
        "tasks": tasks,
        "timestamp": int(time.time()),
        "extensions": get_extension_sections_html()
    }

def send_wol(mac, broadcast="255.255.255.255"):
    try:
        mac = mac.replace(":", "").replace("-", "").upper()
        if len(mac) != 12:
            return {"success": False, "error": "Invalid MAC address"}
        magic = b'\xff' * 6 + bytes.fromhex(mac) * 16
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.sendto(magic, (broadcast, 9))
        sock.close()
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}

def is_valid_container_name(name):
    """Validate docker container name to prevent shell injection."""
    if not name or len(name) > 128:
        return False
    return bool(re.match(r'^[a-zA-Z0-9][a-zA-Z0-9_.-]*$', name))

def remote_docker_action(ip, user, port, container, action, use_sudo=False):
    """Execute docker command on remote host via SSH."""
    if not is_valid_container_name(container):
        return {"success": False, "error": "Invalid container name"}

    docker_cmd = "sudo docker" if use_sudo else "docker"

    if action == "status":
        ssh_cmd = f"{docker_cmd} inspect -f '{{{{.State.Status}}}}' '{container}'"
    elif action in ("start", "stop"):
        ssh_cmd = f"{docker_cmd} {action} '{container}'"
    else:
        return {"success": False, "error": "Unknown action"}

    try:
        result = subprocess.run(
            ["ssh"] + SSH_CONTROL_OPTS + ["-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
             "-p", str(port), f"{user}@{ip}", f'bash -lc "{ssh_cmd}"'],
            capture_output=True, text=True, timeout=60
        )

        output = (result.stdout + result.stderr).lower()

        if "permission denied" in output:
            if not use_sudo:
                return remote_docker_action(ip, user, port, container, action, use_sudo=True)
            return {"success": False, "error": "Docker permission denied"}

        if result.returncode == 0:
            if action == "status":
                status = result.stdout.strip()
                return {"success": True, "status": status, "running": status == "running"}
            return {"success": True}

        if action == "status":
            return {"success": False, "error": "Container not found"}
        return {"success": False, "error": result.stderr.strip()[:100] if result.stderr else f"docker {action} failed"}

    except subprocess.TimeoutExpired:
        return {"success": False, "error": "SSH timeout"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def scan_docker_containers(device):
    """Scan for docker containers on device (local or remote)."""
    is_host = device.get('is_host', False)

    if is_host:
        try:
            result = subprocess.run(
                ["docker", "ps", "-a", "--format", "{{.Names}}"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0:
                return {"success": False, "error": "Docker not available"}
            names = [n.strip() for n in result.stdout.strip().split('\n') if n.strip()]
            return {"success": True, "containers": names}
        except Exception as e:
            return {"success": False, "error": str(e)}
    else:
        ssh_config = device.get('ssh', {})
        user = ssh_config.get('user')
        port = ssh_config.get('port', 22)
        ip = device.get('ip')

        if not user:
            return {"success": False, "error": "SSH not configured. Add SSH user to scan for containers."}

        def try_scan(use_sudo=False):
            docker_cmd = "sudo docker" if use_sudo else "docker"
            ssh_cmd = f'{docker_cmd} ps -a --format "{{{{.Names}}}}"'
            result = subprocess.run(
                ["ssh"] + SSH_CONTROL_OPTS + ["-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
                 "-p", str(port), f"{user}@{ip}", f'bash -lc "{ssh_cmd}"'],
                capture_output=True, text=True, timeout=15
            )
            return result, use_sudo

        try:
            result, used_sudo = try_scan(False)
            output = (result.stdout + result.stderr).lower()
            if result.returncode != 0 or "permission denied" in output:
                if not used_sudo:
                    result, used_sudo = try_scan(True)
                    output = (result.stdout + result.stderr).lower()

            if result.returncode != 0:
                error = result.stderr.strip() if result.stderr else "Docker not available"
                return {"success": False, "error": error}
            if "permission denied" in output:
                return {"success": False, "error": "Docker permission denied. Add user to docker group or configure passwordless sudo."}
            names = [n.strip() for n in result.stdout.strip().split('\n') if n.strip()]
            return {"success": True, "containers": names}
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "SSH timeout"}
        except Exception as e:
            return {"success": False, "error": str(e)}

def get_default_ssh_user():
    """Get default SSH user from /home/ directory."""
    try:
        home_dirs = [d for d in os.listdir('/home') if os.path.isdir(f'/home/{d}')]
        home_dirs = [d for d in home_dirs if not d.startswith('.')]
        if home_dirs:
            return sorted(home_dirs)[0]
    except:
        pass
    return "root"

def scan_network():
    """Scan for devices via Tailscale and ARP cache."""
    devices = []
    source = "none"
    default_ssh_user = get_default_ssh_user()

    # Try Tailscale first
    try:
        result = subprocess.run(
            ["tailscale", "status", "--json"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            data = json.loads(result.stdout)
            source = "tailscale"

            # Ping online peers to fill ARP cache
            for peer in data.get('Peer', {}).values():
                if peer.get('Online'):
                    ts_ips = peer.get('TailscaleIPs', [])
                    if ts_ips:
                        ping_host(ts_ips[0], timeout=0.2)

            # Re-fetch tailscale status after pings (CurAddr may be populated now)
            result = subprocess.run(
                ["tailscale", "status", "--json"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)

            # Read ARP cache after pings
            arp_cache = {}
            try:
                with open('/proc/net/arp', 'r') as f:
                    for line in f.readlines()[1:]:
                        parts = line.split()
                        if len(parts) >= 4 and parts[2] == '0x2':
                            ip = parts[0]
                            mac = parts[3]
                            if mac != '00:00:00:00:00:00':
                                arp_cache[ip] = mac
            except:
                pass

            # Get self node to exclude
            self_node = data.get('Self', {}).get('HostName', '')

            for peer_id, peer in data.get('Peer', {}).items():
                hostname = peer.get('HostName', '')
                if not hostname or hostname == 'localhost':
                    dns_name = peer.get('DNSName', '')
                    hostname = dns_name.split('.')[0] if dns_name else ''
                if not hostname or hostname == self_node:
                    continue

                tailscale_ip = None
                tailscale_ips = peer.get('TailscaleIPs', [])
                for ts_ip in tailscale_ips:
                    if ts_ip.startswith('100.'):
                        tailscale_ip = ts_ip
                        break

                # Extract LAN IP from CurAddr (format: 192.168.x.x:port)
                lan_ip = None
                cur_addr = peer.get('CurAddr', '')
                if cur_addr and not cur_addr.startswith('100.') and not cur_addr.startswith('['):
                    lan_ip = cur_addr.rsplit(':', 1)[0]
                    if lan_ip.startswith('100.') or not lan_ip[0].isdigit():
                        lan_ip = None

                mac = arp_cache.get(lan_ip) if lan_ip else None
                os_type = peer.get('OS', '').lower()
                online = peer.get('Online', False)

                devices.append({
                    "hostname": hostname,
                    "tailscale_ip": tailscale_ip,
                    "lan_ip": lan_ip,
                    "mac": mac,
                    "os": os_type,
                    "online": online
                })
    except:
        pass

    # Fallback to ARP only if no Tailscale
    if source == "none":
        arp_cache = {}
        try:
            with open('/proc/net/arp', 'r') as f:
                for line in f.readlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 4 and parts[2] == '0x2':
                        ip = parts[0]
                        mac = parts[3]
                        if mac != '00:00:00:00:00:00':
                            arp_cache[ip] = mac
        except:
            pass
        if arp_cache:
            source = "arp"
            for ip, mac in arp_cache.items():
                devices.append({
                    "hostname": None,
                    "tailscale_ip": None,
                    "lan_ip": ip,
                    "mac": mac,
                    "os": None,
                    "online": True
                })

    return {"success": True, "source": source, "devices": devices, "default_ssh_user": default_ssh_user}

def get_all_container_statuses(device):
    """Get status of all containers with single docker ps call."""
    containers = device.get('docker', {}).get('containers', [])
    if not containers:
        return {}

    configured_names = set(
        c.get('name') if isinstance(c, dict) else c
        for c in containers
    )

    is_host = device.get('is_host', False)

    if is_host:
        try:
            result = subprocess.run(
                ["docker", "ps", "-a", "--format", "{{.Names}}:{{.State}}"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode != 0:
                return {name: 'unknown' for name in configured_names}
        except:
            return {name: 'unknown' for name in configured_names}
    else:
        ssh_config = device.get('ssh', {})
        user = ssh_config.get('user')
        port = ssh_config.get('port', 22)
        ip = device.get('ip')

        if not user:
            return {name: 'unknown' for name in configured_names}

        try:
            result = subprocess.run(
                ["ssh"] + SSH_CONTROL_OPTS + ["-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
                 "-p", str(port), f"{user}@{ip}",
                 "docker ps -a --format '{{.Names}}:{{.State}}'"],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode != 0:
                return {name: 'unknown' for name in configured_names}
        except:
            return {name: 'unknown' for name in configured_names}

    all_statuses = {}
    for line in result.stdout.strip().split('\n'):
        if ':' in line:
            name, state = line.split(':', 1)
            all_statuses[name] = state.lower()

    return {
        name: all_statuses.get(name, 'unknown')
        for name in configured_names
    }

def docker_action(container, action):
    if not is_valid_container_name(container):
        return {"success": False, "error": "Invalid container name"}
    try:
        if action == "status":
            result = subprocess.run(
                ["docker", "inspect", "-f", "{{.State.Status}}", container],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                status = result.stdout.strip()
                return {"success": True, "status": status, "running": status == "running"}
            return {"success": False, "error": "Container not found"}
        elif action in ["start", "stop"]:
            result = subprocess.run(
                ["docker", action, container],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode == 0:
                return {"success": True}
            return {"success": False, "error": result.stderr.strip()[:100] if result.stderr else f"docker {action} failed"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def ssh_shutdown(ip, user, port=22):
    try:
        result = subprocess.run(
            ["ssh"] + SSH_CONTROL_OPTS + ["-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
             "-p", str(port), f"{user}@{ip}", "sudo", "systemctl", "poweroff"],
            capture_output=True, text=True, timeout=30
        )
        return {"success": True}
    except subprocess.TimeoutExpired:
        return {"success": True}  # Expected - shutdown kills connection
    except Exception as e:
        return {"success": False, "error": str(e)}

def ssh_suspend(ip, user, port=22):
    try:
        result = subprocess.run(
            ["ssh"] + SSH_CONTROL_OPTS + ["-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
             "-p", str(port), f"{user}@{ip}", "sudo", "systemctl", "suspend"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            return {"success": False, "error": result.stderr.strip() or "Suspend failed"}
        return {"success": True}
    except subprocess.TimeoutExpired:
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


# === TASK EXECUTION ===
def log_task(task_id, message, max_lines=500):
    """Append a log line to the task's log file, keeping only last max_lines."""
    log_file = f"{TASK_LOGS_DIR}/{task_id}.log"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {message}\n"

    lines = []
    if os.path.exists(log_file):
        with open(log_file, 'r') as f:
            lines = f.readlines()
    lines.append(line)

    with open(log_file, 'w') as f:
        f.writelines(lines[-max_lines:])

# Track running tasks
running_tasks = {}

def run_task_async(task_id):
    """Execute a task in a background thread."""
    global CONFIG, running_tasks

    task = next((t for t in CONFIG.get('tasks', []) if t['id'] == task_id), None)
    if not task:
        return

    task_type = task.get('type', 'backup')
    log_task(task_id, f"Starting {task_type} task: {task.get('name', 'unnamed')}")

    try:
        if task_type == 'backup':
            result = run_backup_task(task)
        elif task_type == 'wake':
            result = run_wake_task(task)
        elif task_type == 'shutdown':
            result = run_shutdown_task(task)
        elif task_type == 'suspend':
            result = run_suspend_task(task)
        elif task_type == 'script':
            result = run_script_task(task)
        else:
            result = {"success": False, "error": f"Unknown task type: {task_type}"}

        # Update task status
        task['last_run'] = datetime.now().isoformat()
        if result.get('success'):
            task['last_status'] = 'success'
            task['last_error'] = None
            if 'size' in result:
                task['last_size'] = result['size']
            log_task(task_id, f"Completed successfully")
        elif result.get('skipped'):
            task['last_status'] = 'skipped'
            task['last_error'] = result.get('error', 'source offline')
            log_task(task_id, f"Skipped: {task['last_error']}")
        else:
            task['last_status'] = 'failed'
            task['last_error'] = result.get('error', 'unknown error')
            log_task(task_id, f"Failed: {task['last_error']}")

        save_config(CONFIG)

    except Exception as e:
        task['last_run'] = datetime.now().isoformat()
        task['last_status'] = 'failed'
        task['last_error'] = str(e)
        save_config(CONFIG)
        log_task(task_id, f"Exception: {e}")

    finally:
        running_tasks.pop(task_id, None)


def run_task(task_id):
    """Start a task in background thread, return immediately."""
    global CONFIG, running_tasks

    task = next((t for t in CONFIG.get('tasks', []) if t['id'] == task_id), None)
    if not task:
        return {"success": False, "error": "Task not found"}

    if task_id in running_tasks:
        return {"success": False, "error": "Task already running"}

    # Start in background thread
    running_tasks[task_id] = True
    thread = threading.Thread(target=run_task_async, args=(task_id,), daemon=True)
    thread.start()

    return {"success": True, "started": True}

def run_backup_task(task):
    """Execute a backup task using rsync."""
    source = task.get('source', {})
    dest = task.get('dest', {})
    options = task.get('options', {})

    source_device = next((d for d in CONFIG['devices'] if d['id'] == source.get('device')), None)
    dest_device = next((d for d in CONFIG['devices'] if d['id'] == dest.get('device')), None)

    if not source_device or not dest_device:
        return {"success": False, "error": "Source or destination device not found"}

    source_path = source.get('path', '')
    dest_path = dest.get('path', '')

    if not source_path or not dest_path:
        return {"success": False, "error": "Source or destination path not specified"}

    # Check if source device is online
    source_is_host = source_device.get('is_host', False)
    if not source_is_host:
        if not ping_host(source_device['ip']):
            return {"success": False, "skipped": True, "error": "source offline"}

    # Build rsync command
    rsync_opts = ["-avz", "--stats"]
    if options.get('delete'):
        rsync_opts.append("--delete")

    # Source path - respect user's trailing slash choice
    if source_is_host:
        rsync_source = source_path
    else:
        ssh_user = source_device.get('ssh', {}).get('user', 'root')
        ssh_port = source_device.get('ssh', {}).get('port', 22)
        rsync_opts.extend(["-e", f"ssh {SSH_CONTROL_STR} -p {ssh_port} -o StrictHostKeyChecking=no -o ConnectTimeout=10"])
        rsync_source = f"{ssh_user}@{source_device['ip']}:{source_path}"

    # Destination path - respect user's trailing slash choice
    dest_is_host = dest_device.get('is_host', False)
    if dest_is_host:
        # Ensure destination directory exists
        os.makedirs(dest_path, exist_ok=True)
        rsync_dest = dest_path
    else:
        ssh_user = dest_device.get('ssh', {}).get('user', 'root')
        ssh_port = dest_device.get('ssh', {}).get('port', 22)
        if "-e" not in rsync_opts:
            rsync_opts.extend(["-e", f"ssh {SSH_CONTROL_STR} -p {ssh_port} -o StrictHostKeyChecking=no -o ConnectTimeout=10"])
        rsync_dest = f"{ssh_user}@{dest_device['ip']}:{dest_path}"

    cmd = ["rsync"] + rsync_opts + [rsync_source, rsync_dest]
    log_task(task['id'], f"Running: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)

        if result.returncode == 0:
            # Parse total size from rsync stats
            size = ""
            for line in result.stdout.split('\n'):
                if 'Total file size' in line and 'transferred' not in line:
                    parts = line.split(':')
                    if len(parts) > 1:
                        size = parts[1].strip().split()[0]
                        # Convert to human readable
                        try:
                            # Remove thousand separators (comma or dot)
                            bytes_val = int(size.replace(',', '').replace('.', ''))
                            if bytes_val >= 1e9:
                                size = f"{bytes_val/1e9:.1f}GB"
                            elif bytes_val >= 1e6:
                                size = f"{bytes_val/1e6:.0f}MB"
                            else:
                                size = f"{bytes_val/1e3:.0f}KB"
                        except:
                            pass
            return {"success": True, "size": size}
        else:
            return {"success": False, "error": result.stderr[:200] if result.stderr else "rsync failed"}

    except subprocess.TimeoutExpired:
        return {"success": False, "error": "timeout (1h)"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def run_wake_task(task):
    """Execute a wake task - WOL for device, docker start for container."""
    target = task.get('target', 'device')

    if target == 'docker':
        container = task.get('container')
        if not container:
            return {"success": False, "error": "No container specified"}
        return docker_action(container, 'start')

    # Device wake (WOL)
    device_id = task.get('device') or task.get('source', {}).get('device')  # backward compat
    device = next((d for d in CONFIG['devices'] if d['id'] == device_id), None)

    if not device:
        return {"success": False, "error": "Device not found"}

    if not device.get('wol', {}).get('mac'):
        return {"success": False, "error": "Device has no WOL configured"}

    result = send_wol(device['wol']['mac'], device['wol'].get('broadcast', '255.255.255.255'))
    return result


def run_shutdown_task(task):
    """Execute a shutdown task - SSH shutdown for device, docker stop for container."""
    target = task.get('target', 'device')

    if target == 'docker':
        container = task.get('container')
        if not container:
            return {"success": False, "error": "No container specified"}
        return docker_action(container, 'stop')

    # Device shutdown
    device_id = task.get('device')
    device = next((d for d in CONFIG['devices'] if d['id'] == device_id), None)

    if not device:
        return {"success": False, "error": "Device not found"}

    # Host device: local shutdown
    if device.get('is_host'):
        try:
            subprocess.Popen(["sudo", "shutdown", "-h", "now"])
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}

    # Remote device: SSH shutdown
    if not device.get('ssh', {}).get('user'):
        return {"success": False, "error": "Device has no SSH configured"}

    result = ssh_shutdown(device['ip'], device['ssh']['user'], device['ssh'].get('port', 22))
    return result

def run_suspend_task(task):
    """Execute a suspend task - SSH suspend for device (no docker equivalent)."""
    device_id = task.get('device')
    device = next((d for d in CONFIG['devices'] if d['id'] == device_id), None)

    if not device:
        return {"success": False, "error": "Device not found"}

    # Host device: local suspend
    if device.get('is_host'):
        try:
            subprocess.Popen(["sudo", "systemctl", "suspend"])
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}

    # Remote device: SSH suspend
    if not device.get('ssh', {}).get('user'):
        return {"success": False, "error": "Device has no SSH configured"}

    result = ssh_suspend(device['ip'], device['ssh']['user'], device['ssh'].get('port', 22))
    return result

def run_script_task(task):
    """Start a scheduled script."""
    script_path = task.get('script')
    if not script_path:
        return {"success": False, "error": "No script specified"}
    return execute_quick_action(script_path)


# === TASK SCHEDULER ===
def calculate_next_run(task):
    """Calculate the next run time for a task based on its schedule."""
    if not task.get('enabled', True):
        return None

    schedule = task.get('schedule', {})
    schedule_type = schedule.get('type', 'daily')
    time_str = schedule.get('time', '03:00')

    try:
        hour, minute = map(int, time_str.split(':'))
    except Exception:
        hour, minute = 3, 0

    now = datetime.now()

    if schedule_type == 'hourly':
        # Run every hour at specified minute
        next_run = now.replace(minute=minute, second=0, microsecond=0)
        if next_run <= now:
            next_run += timedelta(hours=1)

    elif schedule_type == 'daily':
        next_run = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
        if next_run <= now:
            next_run += timedelta(days=1)

    elif schedule_type == 'weekly':
        day = schedule.get('day', 0)  # 0 = Sunday
        next_run = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
        # Convert to Python weekday (0=Monday)
        py_day = (day - 1) % 7 if day > 0 else 6
        days_ahead = py_day - now.weekday()
        if days_ahead < 0 or (days_ahead == 0 and next_run <= now):
            days_ahead += 7
        next_run += timedelta(days=days_ahead)

    elif schedule_type == 'monthly':
        date = schedule.get('date', 1)
        # Try current month first
        year, month = now.year, now.month
        for _ in range(12):  # Try up to 12 months ahead
            try:
                next_run = datetime(year, month, date, hour, minute, 0)
                if next_run > now:
                    break
                # Move to next month
                month += 1
                if month > 12:
                    month = 1
                    year += 1
            except ValueError:
                # Invalid day for this month (e.g., Feb 30), try next month
                month += 1
                if month > 12:
                    month = 1
                    year += 1
        else:
            return None  # Could not find valid date
    else:
        return None

    return next_run.isoformat()


class TaskScheduler:
    """Background scheduler for automated task execution."""

    def __init__(self):
        self.running = False
        self.thread = None

    def start(self):
        """Start the scheduler thread."""
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        print("Task scheduler started")

    def stop(self):
        """Stop the scheduler thread."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        print("Task scheduler stopped")

    def _run(self):
        """Main scheduler loop - checks every 60 seconds for due tasks."""
        # Update next_run times on startup
        self._update_next_runs()

        while self.running:
            try:
                self._check_and_run_tasks()
            except Exception as e:
                print(f"Scheduler error: {e}")

            # Sleep for 60 seconds, but check running flag periodically
            for _ in range(60):
                if not self.running:
                    break
                time.sleep(1)

    def _update_next_runs(self):
        """Update next_run times for all tasks, preserving valid future times."""
        global CONFIG
        changed = False
        now = datetime.now()
        for task in CONFIG.get('tasks', []):
            if task.get('enabled', True):
                current_next = task.get('next_run')
                if current_next:
                    try:
                        next_dt = datetime.fromisoformat(current_next)
                        if next_dt > now:
                            continue
                    except:
                        pass
                next_run = calculate_next_run(task)
                if next_run != current_next:
                    task['next_run'] = next_run
                    changed = True
        if changed:
            save_config(CONFIG)

    def _check_and_run_tasks(self):
        """Check for tasks due to run and execute them."""
        global CONFIG
        now = datetime.now()

        for task in CONFIG.get('tasks', []):
            if not task.get('enabled', True):
                continue

            next_run_str = task.get('next_run')
            if not next_run_str:
                # Calculate and set next_run if missing
                task['next_run'] = calculate_next_run(task)
                save_config(CONFIG)
                continue

            try:
                next_run = datetime.fromisoformat(next_run_str)
            except:
                continue

            if now >= next_run:
                print(f"Running scheduled task: {task.get('name', task['id'])}")
                run_task(task['id'])

                # Calculate next run time
                task['next_run'] = calculate_next_run(task)
                save_config(CONFIG)


# Global scheduler instance
task_scheduler = TaskScheduler()


# === EXTENSIONS ===
EXTENSIONS_DIR = f"{DATA_DIR}/extensions"
extension_sections = []

class DeqAPI:
    """API object passed to extensions."""

    @property
    def devices(self):
        return CONFIG.get('devices', [])

    @property
    def config(self):
        return get_config_with_defaults()

    def device_status(self, device_id):
        """Get cached status for a device."""
        return device_status_cache.get(device_id)

    def is_online(self, device_id):
        """Check if device is online."""
        status = self.device_status(device_id)
        return status.get('online') if status else None

    def wol(self, device_id):
        """Send Wake-on-LAN packet to device."""
        dev = self._get_device(device_id)
        if not dev:
            return {"success": False, "error": "Device not found"}
        wol = dev.get('wol', {})
        if not wol.get('mac'):
            return {"success": False, "error": "WOL not configured"}
        try:
            send_wol(wol['mac'], wol.get('broadcast', '255.255.255.255'))
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def shutdown(self, device_id):
        """Shutdown device via SSH (or local for host)."""
        dev = self._get_device(device_id)
        if not dev:
            return {"success": False, "error": "Device not found"}
        if dev.get('is_host'):
            subprocess.Popen(["sudo", "shutdown", "-h", "now"])
            return {"success": True}
        ssh = dev.get('ssh', {})
        if not ssh.get('user'):
            return {"success": False, "error": "SSH not configured"}
        try:
            run_ssh_command(dev['ip'], ssh['user'], ssh.get('port', 22),
                          "sudo shutdown -h now", timeout=10)
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def suspend(self, device_id):
        """Suspend device via SSH (or local for host)."""
        dev = self._get_device(device_id)
        if not dev:
            return {"success": False, "error": "Device not found"}
        if dev.get('is_host'):
            subprocess.Popen(["sudo", "systemctl", "suspend"])
            return {"success": True}
        ssh = dev.get('ssh', {})
        if not ssh.get('user'):
            return {"success": False, "error": "SSH not configured"}
        try:
            run_ssh_command(dev['ip'], ssh['user'], ssh.get('port', 22),
                          "sudo systemctl suspend", timeout=10)
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def docker(self, device_id, container, action):
        """Control Docker container."""
        if action not in ('start', 'stop', 'status'):
            return {"success": False, "error": "Invalid action"}

        # Validate container name to prevent command injection
        # Docker container names: [a-zA-Z0-9][a-zA-Z0-9_.-]*
        if not container or not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9_.-]*$', container):
            return {"success": False, "error": "Invalid container name"}

        dev = self._get_device(device_id)
        if not dev:
            return {"success": False, "error": "Device not found"}
        try:
            if dev.get('is_host'):
                if action == 'status':
                    cmd = ["docker", "inspect", "-f", "{{.State.Status}}", container]
                else:
                    cmd = ["docker", action, container]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if action == 'status':
                    return {"success": True, "status": result.stdout.strip()}
                return {"success": result.returncode == 0, "error": result.stderr if result.returncode != 0 else None}
            else:
                ssh = dev.get('ssh', {})
                if not ssh.get('user'):
                    return {"success": False, "error": "SSH not configured"}
                if action == 'status':
                    cmd = f"docker inspect -f '{{{{.State.Status}}}}' '{container}'"
                else:
                    cmd = f"docker {action} '{container}'"
                result = run_ssh_command(dev['ip'], ssh['user'], ssh.get('port', 22), cmd, timeout=30)
                if action == 'status':
                    return {"success": True, "status": result.strip()}
                return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def ssh(self, device_id, command):
        """Execute command on device via SSH (or local shell for host)."""
        dev = self._get_device(device_id)
        if not dev:
            return False, "", "Device not found"

        if dev.get('is_host'):
            try:
                result = subprocess.run(
                    command, shell=True,
                    capture_output=True, text=True, timeout=30
                )
                return result.returncode == 0, result.stdout, result.stderr
            except Exception as e:
                return False, "", str(e)

        ssh_cfg = dev.get('ssh', {})
        if not ssh_cfg.get('user'):
            return False, "", "SSH not configured"

        try:
            result = run_ssh_command(dev['ip'], ssh_cfg['user'], ssh_cfg.get('port', 22), command, timeout=30)
            return True, result, ""
        except Exception as e:
            return False, "", str(e)

    def register_section(self, id, title, icon, render):
        """Register a dashboard section."""
        extension_sections.append({
            "id": f"ext:{id}",
            "title": title,
            "icon": icon,
            "render": render
        })

    def _get_device(self, device_id):
        return next((d for d in CONFIG.get('devices', []) if d['id'] == device_id), None)

# Global API instance
deq = DeqAPI()

def load_extensions():
    """Load all extensions from extensions directory."""
    global extension_sections
    extension_sections = []

    if not os.path.exists(EXTENSIONS_DIR):
        os.makedirs(EXTENSIONS_DIR, exist_ok=True)
        return

    for filepath in sorted(glob.glob(f"{EXTENSIONS_DIR}/*.py")):
        try:
            filename = os.path.basename(filepath)
            ext_name = filename[:-3]

            with open(filepath, 'r') as f:
                code = f.read()

            namespace = {"deq": deq, "__name__": ext_name}
            exec(code, namespace)

            if 'register' in namespace:
                namespace['register'](deq)

            print(f"[Extensions] Loaded: {ext_name}")
        except Exception as e:
            print(f"[Extensions] Failed to load {filepath}: {e}")

def get_extension_sections_html():
    """Render all extension sections."""
    sections = []
    for s in extension_sections:
        try:
            html = s["render"]()
            sections.append({
                "id": s["id"],
                "title": s["title"],
                "icon": s["icon"],
                "html": html
            })
        except Exception as e:
            sections.append({
                "id": s["id"],
                "title": s["title"],
                "icon": s["icon"],
                "html": f'<div class="extension-error">Error: {e}</div>'
            })
    return sections

# Load extensions at startup
load_extensions()


class RequestHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        print(f"[{self.log_date_time_string()}] {args[0]}")
    
    def send_json(self, data, status=200):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())
    
    def send_html(self, html):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())
    
    def send_file(self, content, content_type, cache=True):
        self.send_response(200)
        self.send_header('Content-Type', content_type)
        if cache:
            self.send_header('Cache-Control', 'public, max-age=31536000')
        self.end_headers()
        if isinstance(content, str):
            self.wfile.write(content.encode())
        else:
            self.wfile.write(content)

    def get_session_cookie(self):
        """Get session token from cookie."""
        cookie_header = self.headers.get('Cookie', '')
        cookie = SimpleCookie()
        cookie.load(cookie_header)
        if SESSION_COOKIE_NAME in cookie:
            return cookie[SESSION_COOKIE_NAME].value
        return None

    def is_authenticated(self):
        """Check if request is authenticated."""
        if not is_auth_enabled():
            return True
        token = self.get_session_cookie()
        return verify_session_token(token)

    def send_login_page(self):
        """Send login page HTML."""
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(get_login_page().encode())

    def do_GET(self):
        path = urlparse(self.path).path
        query = parse_qs(urlparse(self.path).query)

        # Static files don't require auth
        if path in ['/manifest.json', '/icon.svg'] or path.startswith('/fonts/'):
            pass  # Continue to serve static files
        elif not self.is_authenticated():
            self.send_login_page()
            return

        if path == '/' or path == '':
            needs_onboarding = not CONFIG.get('onboarding_done') and len(CONFIG.get('devices', [])) <= 1
            html = get_html_page().replace('__NEEDS_ONBOARDING__', 'true' if needs_onboarding else 'false')
            self.send_html(html)
            return
        
        if path == '/manifest.json':
            self.send_file(get_manifest_json(), 'application/manifest+json')
            return
        
        if path == '/icon.svg':
            self.send_file(get_icon_svg(), 'image/svg+xml')
            return

        if path.startswith('/fonts/'):
            font_name = path.split('/')[-1]
            # Try local fonts dir first (bundled), then DATA_DIR
            script_dir = os.path.dirname(os.path.abspath(__file__))
            font_paths = [
                os.path.join(script_dir, 'fonts', font_name),
                f"{DATA_DIR}/fonts/{font_name}"
            ]
            for font_path in font_paths:
                if os.path.exists(font_path):
                    with open(font_path, 'rb') as f:
                        self.send_file(f.read(), 'font/woff2')
                    return
            self.send_response(404)
            self.end_headers()
            return
        
        # API
        if path.startswith('/api/'):
            api_path = path[5:].split('?')[0]
            
            if api_path == 'config':
                self.send_json({"success": True, "config": get_config_with_defaults(), "running_tasks": list(running_tasks.keys()), "auth_enabled": is_auth_enabled()})
                return
            
            if api_path == 'stats/host':
                self.send_json({"success": True, "stats": get_local_stats()})
                return

            if api_path == 'health':
                health = get_health_status()
                self.send_json(health)
                return

            if api_path == 'version':
                self.send_json({"version": VERSION, "name": "DeQ"})
                return

            if api_path == 'network/scan':
                result = scan_network()
                self.send_json(result)
                return

            if api_path == 'scripts/scan':
                scripts = discover_scripts()
                self.send_json({"success": True, "scripts": scripts})
                return

            if api_path.startswith('job/'):
                job_id = api_path.split('/')[1]
                status = get_job_status(job_id)
                self.send_json(status)
                return

            if api_path.startswith('quick-action/') and api_path.endswith('/run'):
                parts = api_path.split('/')
                qa_id = parts[1]
                qa = next((q for q in CONFIG.get('quick_actions', []) if q['id'] == qa_id), None)
                if not qa:
                    self.send_json({"success": False, "error": "Quick action not found"}, 404)
                    return
                result = execute_quick_action(qa['path'])
                self.send_json(result)
                return

            if api_path.startswith('device/'):
                parts = api_path.split('/')
                if len(parts) >= 3:
                    dev_id = parts[1]
                    action = parts[2]
                    dev = next((d for d in CONFIG['devices'] if d['id'] == dev_id), None)
                    
                    if not dev:
                        self.send_json({"success": False, "error": "Device not found"}, 404)
                        return
                    
                    if action == 'scan-containers':
                        result = scan_docker_containers(dev)
                        self.send_json(result)
                        return

                    if action == 'ssh-check':
                        ssh_config = dev.get('ssh', {})
                        if not ssh_config.get('user'):
                            self.send_json({"success": False, "error": "No SSH user configured"})
                            return
                        try:
                            result = subprocess.run(
                                ["ssh"] + SSH_CONTROL_OPTS + ["-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5", "-o", "BatchMode=yes",
                                 "-p", str(ssh_config.get('port', 22)), f"{ssh_config['user']}@{dev['ip']}", "echo ok"],
                                capture_output=True, text=True, timeout=10
                            )
                            if result.returncode == 0 and 'ok' in result.stdout:
                                self.send_json({"success": True})
                            else:
                                self.send_json({"success": False, "error": "SSH auth failed"})
                        except subprocess.TimeoutExpired:
                            self.send_json({"success": False, "error": "SSH timeout"})
                        except Exception as e:
                            self.send_json({"success": False, "error": str(e)})
                        return

                    if action == 'status':
                        cached = get_cached_status(dev_id)
                        refresh_device_status_async(dev)
                        if cached:
                            self.send_json({"success": True, **cached})
                        else:
                            self.send_json({"success": True, "online": None, "stats": None, "containers": {}})
                        return

                    if action == 'stats':
                        if dev.get('is_host'):
                            stats = get_local_stats()
                            online = True
                        else:
                            online = ping_host(dev.get('ip', ''))
                            ssh = dev.get('ssh', {})
                            if online and ssh.get('user'):
                                stats = get_remote_stats(dev['ip'], ssh['user'], ssh.get('port', 22))
                            else:
                                stats = None
                        self.send_json({"success": True, "stats": stats or {}, "online": online})
                        return

                    if action == 'wake':
                        if dev.get('wol', {}).get('mac'):
                            result = send_wol(dev['wol']['mac'], dev['wol'].get('broadcast', '255.255.255.255'))
                            self.send_json(result)
                        else:
                            self.send_json({"success": False, "error": "WOL not configured"})
                        return
                    
                    if action == 'shutdown':
                        # Host device: local shutdown
                        if dev.get('is_host'):
                            try:
                                subprocess.Popen(["sudo", "shutdown", "-h", "now"])
                                self.send_json({"success": True})
                            except Exception as e:
                                self.send_json({"success": False, "error": str(e)})
                            return

                        if dev.get('ssh', {}).get('user'):
                            result = ssh_shutdown(dev['ip'], dev['ssh']['user'], dev['ssh'].get('port', 22))
                            self.send_json(result)
                        else:
                            self.send_json({"success": False, "error": "SSH not configured"})
                        return

                    if action == 'suspend':
                        # Host device: local suspend
                        if dev.get('is_host'):
                            try:
                                subprocess.Popen(["sudo", "systemctl", "suspend"])
                                self.send_json({"success": True})
                            except Exception as e:
                                self.send_json({"success": False, "error": str(e)})
                            return

                        if dev.get('ssh', {}).get('user'):
                            result = ssh_suspend(dev['ip'], dev['ssh']['user'], dev['ssh'].get('port', 22))
                            self.send_json(result)
                        else:
                            self.send_json({"success": False, "error": "SSH not configured"})
                        return
                    
                    # Docker: /api/device/{id}/docker/{container}/{action}
                    if action == 'docker' and len(parts) >= 5:
                        container_name = parts[3]
                        docker_act = parts[4]

                        if not is_valid_container_name(container_name):
                            self.send_json({"success": False, "error": "Invalid container name"})
                            return

                        containers = dev.get('docker', {}).get('containers', [])
                        container_names = [c.get('name') if isinstance(c, dict) else c for c in containers]

                        if container_name not in container_names:
                            self.send_json({"success": False, "error": f"Container '{container_name}' not configured"})
                            return

                        if dev.get('is_host'):
                            result = docker_action(container_name, docker_act)
                        else:
                            ssh_config = dev.get('ssh', {})
                            if ssh_config.get('user'):
                                result = remote_docker_action(
                                    dev['ip'],
                                    ssh_config['user'],
                                    ssh_config.get('port', 22),
                                    container_name,
                                    docker_act
                                )
                            else:
                                result = {"success": False, "error": "SSH not configured"}

                        self.send_json(result)
                        return

                    # Browse folders: /api/device/{id}/browse?path=/
                    if action == 'browse':
                        browse_path = query.get('path', ['/'])[0]
                        result = browse_folder(dev, browse_path)
                        self.send_json(result)
                        return

                    # List files: /api/device/{id}/files?path=/
                    if action == 'files':
                        file_path = query.get('path', ['/'])[0]
                        result = list_files(dev, file_path)
                        self.send_json(result)
                        return

                    # Download file: /api/device/{id}/download?path=/file.txt
                    if action == 'download':
                        file_path = query.get('path', [''])[0]
                        if not file_path:
                            self.send_json({"success": False, "error": "Path required"}, 400)
                            return
                        content, filename, error = get_file_for_download(dev, file_path)
                        if error:
                            self.send_json({"success": False, "error": error}, 400)
                            return
                        self.send_response(200)
                        self.send_header('Content-Type', 'application/octet-stream')
                        self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
                        self.send_header('Content-Length', len(content))
                        self.end_headers()
                        self.wfile.write(content)
                        return

            # Task status (check if running)
            if api_path.startswith('task/') and api_path.endswith('/status'):
                task_id = api_path.split('/')[1]
                is_running = task_id in running_tasks
                task = next((t for t in CONFIG.get('tasks', []) if t['id'] == task_id), None)
                if task:
                    self.send_json({
                        "success": True,
                        "running": is_running,
                        "last_status": task.get('last_status'),
                        "last_error": task.get('last_error'),
                        "last_size": task.get('last_size')
                    })
                else:
                    self.send_json({"success": False, "error": "Task not found"}, 404)
                return

            self.send_json({"success": False, "error": "Not found"}, 404)
            return

        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        path = urlparse(self.path).path

        # Auth endpoints (no auth required for login)
        if path == '/auth/login':
            length = int(self.headers.get('Content-Length', 0))
            data = json.loads(self.rfile.read(length)) if length > 0 else {}
            password = data.get('password', '')
            if verify_password(password):
                token = create_session_token()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Set-Cookie', f'{SESSION_COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Strict')
                self.end_headers()
                self.wfile.write(json.dumps({"success": True}).encode())
            else:
                self.send_json({"success": False, "error": "Invalid password"}, 401)
            return

        if path == '/auth/logout':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Set-Cookie', f'{SESSION_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0')
            self.end_headers()
            self.wfile.write(json.dumps({"success": True}).encode())
            return

        # All other POST requests require auth
        if not self.is_authenticated():
            self.send_json({"success": False, "error": "Unauthorized"}, 401)
            return

        if path == '/api/config':
            length = int(self.headers.get('Content-Length', 0))
            data = json.loads(self.rfile.read(length))
            global CONFIG
            CONFIG = data
            # Update next_run for all enabled tasks
            for task in CONFIG.get('tasks', []):
                if task.get('enabled', True):
                    task['next_run'] = calculate_next_run(task)
            save_config(CONFIG)
            self.send_json({"success": True})
            return

        if path == '/api/onboarding/complete':
            CONFIG['onboarding_done'] = True
            save_config(CONFIG)
            self.send_json({"success": True})
            return

        # Task execution
        if path.startswith('/api/task/') and path.endswith('/run'):
            task_id = path.split('/')[3]
            result = run_task(task_id)
            self.send_json(result)
            return

        # Task toggle (pause/resume)
        if path.startswith('/api/task/') and path.endswith('/toggle'):
            task_id = path.split('/')[3]
            for task in CONFIG.get('tasks', []):
                if task['id'] == task_id:
                    task['enabled'] = not task.get('enabled', True)
                    if task['enabled']:
                        task['next_run'] = calculate_next_run(task)
                    save_config(CONFIG)
                    self.send_json({"success": True, "enabled": task['enabled']})
                    return
            self.send_json({"success": False, "error": "Task not found"}, 404)
            return

        # File operations: /api/device/{id}/files
        if path.startswith('/api/device/') and path.endswith('/files'):
            parts = path.split('/')
            dev_id = parts[3]
            dev = next((d for d in CONFIG['devices'] if d['id'] == dev_id), None)

            if not dev:
                self.send_json({"success": False, "error": "Device not found"}, 404)
                return

            length = int(self.headers.get('Content-Length', 0))
            data = json.loads(self.rfile.read(length))
            operation = data.get('operation')
            paths = data.get('paths', [])

            if operation in ('copy', 'move', 'preflight'):
                dest_dev_id = data.get('dest_device')
                dest_path = data.get('dest_path')
                dest_dev = next((d for d in CONFIG['devices'] if d['id'] == dest_dev_id), None)
                if not dest_dev:
                    self.send_json({"success": False, "error": "Destination device not found"}, 404)
                    return
                result = file_operation(dev, operation, paths, dest_device=dest_dev, dest_path=dest_path)
            elif operation == 'extract':
                dest_dev_id = data.get('dest_device')
                dest_path = data.get('dest_path')
                dest_dev = next((d for d in CONFIG['devices'] if d['id'] == dest_dev_id), None) if dest_dev_id else None
                result = file_operation(dev, operation, paths, dest_device=dest_dev, dest_path=dest_path)
            elif operation == 'rename':
                new_name = data.get('new_name')
                result = file_operation(dev, operation, paths, new_name=new_name)
            elif operation == 'mkdir':
                new_name = data.get('new_name')
                result = file_operation(dev, operation, paths, new_name=new_name)
            elif operation in ('delete', 'zip'):
                result = file_operation(dev, operation, paths)
            else:
                result = {"success": False, "error": f"Unknown operation: {operation}"}

            self.send_json(result)
            return

        # File upload: /api/device/{id}/upload?path=/dest/folder
        if path.startswith('/api/device/') and '/upload' in path:
            parts = path.split('/')
            dev_id = parts[3]
            dev = next((d for d in CONFIG['devices'] if d['id'] == dev_id), None)

            if not dev:
                self.send_json({"success": False, "error": "Device not found"}, 404)
                return

            parsed = urlparse(self.path)
            query = parse_qs(parsed.query)
            dest_path = query.get('path', ['/'])[0]

            # Parse multipart form data
            content_type = self.headers.get('Content-Type', '')
            if 'multipart/form-data' not in content_type:
                self.send_json({"success": False, "error": "Expected multipart/form-data"}, 400)
                return

            # Extract boundary
            boundary = None
            for part in content_type.split(';'):
                part = part.strip()
                if part.startswith('boundary='):
                    boundary = part[9:].strip('"')
                    break

            if not boundary:
                self.send_json({"success": False, "error": "No boundary in multipart"}, 400)
                return

            length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(length)

            # Parse multipart - simple parser for single file
            boundary_bytes = ('--' + boundary).encode()
            parts = body.split(boundary_bytes)

            uploaded = 0
            errors = []

            for part in parts:
                if b'Content-Disposition: form-data;' not in part:
                    continue
                if b'filename="' not in part:
                    continue

                # Extract filename
                header_end = part.find(b'\r\n\r\n')
                if header_end == -1:
                    continue
                header = part[:header_end].decode('utf-8', errors='ignore')
                content = part[header_end + 4:]

                # Remove trailing \r\n--
                if content.endswith(b'\r\n'):
                    content = content[:-2]
                if content.endswith(b'--'):
                    content = content[:-2]
                if content.endswith(b'\r\n'):
                    content = content[:-2]

                # Get filename from header
                match = re.search(r'filename="([^"]+)"', header)
                if not match:
                    continue
                filename = match.group(1)

                # Upload file
                result = upload_file(dev, dest_path, filename, content)
                if result['success']:
                    uploaded += 1
                else:
                    errors.append(f"{filename}: {result['error']}")

            if errors:
                self.send_json({"success": False, "error": "; ".join(errors), "uploaded": uploaded})
            else:
                self.send_json({"success": True, "uploaded": uploaded})
            return

        self.send_json({"success": False, "error": "Not found"}, 404)


def main():
    parser = argparse.ArgumentParser(description='DeQ - Homelab Dashboard')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT, help=f'Port to run on (default: {DEFAULT_PORT})')
    args = parser.parse_args()

    port = args.port

    print(f"""
================================================================
              DeQ - Homelab Admin Panel
================================================================
  Version: {VERSION}
  Port:    {port}

  Access URL:
  http://YOUR-IP:{port}/
================================================================
    """)

    # Clean up stale SSH ControlMaster sockets from previous runs
    for socket_file in glob.glob("/tmp/deq-ssh-*"):
        try:
            os.remove(socket_file)
        except OSError:
            pass

    # Start task scheduler
    task_scheduler.start()

    server = HTTPServer(('0.0.0.0', port), RequestHandler)
    print(f"Server running on port {port}...")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        task_scheduler.stop()
        server.shutdown()

# === LOGIN PAGE ===
def get_login_page():
    return '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no">
    <meta name="theme-color" content="#000000">
    <title>DeQ</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            background: #000;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding-bottom: 15vh;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        }
        .logo {
            width: 120px;
            height: 120px;
            margin-bottom: 48px;
            color: #e0e0e0;
        }
        .logo svg {
            width: 100%;
            height: 100%;
        }
        .icon-bg { fill: transparent; }
        .icon-accent { stroke: #2ed573; }
        input {
            background: transparent;
            border: 1px solid #2ed573;
            border-radius: 8px;
            padding: 12px 16px;
            width: 280px;
            color: #fff;
            font-size: 14px;
            outline: none;
        }
        input::placeholder {
            color: #444;
        }
        input:focus {
            border-color: #2ed573;
            box-shadow: 0 0 0 1px #2ed57333;
        }
        .login-error {
            color: #ff4757;
            font-size: 12px;
            margin-top: 12px;
            opacity: 0;
            transition: opacity 0.2s;
        }
        .login-error.visible { opacity: 1; }
    </style>
</head>
<body>
    <div class="logo">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">
            <rect class="icon-bg" width="512" height="512" rx="96"/>
            <path d="M80 80 L210 80 Q230 80 230 100 L230 412 Q230 432 210 432 L80 432 Z" fill="none" stroke="currentColor" stroke-width="16"/>
            <path d="M430 155 L432 100 Q432 80 412 80 L302 80 Q282 80 282 100 L282 210 Q282 230 302 230 L430 230" fill="none" stroke="currentColor" stroke-width="16" stroke-linecap="round"/>
            <line x1="400" y1="155" x2="428" y2="155" stroke="currentColor" stroke-width="16" stroke-linecap="round"/>
            <path class="icon-accent" d="M432 380 L432 302 Q432 282 412 282 L302 282 Q282 282 282 302 L282 412 Q282 432 302 432 L380 432" fill="none" stroke-width="16" stroke-linecap="round"/>
            <line class="icon-accent" x1="405" y1="405" x2="435" y2="435" stroke-width="16" stroke-linecap="round"/>
        </svg>
    </div>
    <form id="login-form">
        <input type="password" id="password" placeholder="Enter Password" autocomplete="current-password" autofocus>
    </form>
    <div class="login-error" id="error">Invalid password</div>
    <script>
        document.getElementById('login-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const password = document.getElementById('password').value;
            const res = await fetch('/auth/login', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({password})
            });
            if (res.ok) {
                window.location.reload();
            } else {
                document.getElementById('error').classList.add('visible');
                document.getElementById('password').value = '';
                document.getElementById('password').focus();
            }
        });
    </script>
</body>
</html>'''

# === HTML TEMPLATE ===
def get_html_page():
    return '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
    <meta name="mobile-web-app-capable" content="yes">
    <meta name="theme-color" content="#0a0a0a">
    <meta name="application-name" content="DeQ">
    <meta name="apple-mobile-web-app-title" content="DeQ">
    <title>DeQ</title>
    <link rel="manifest" href="/manifest.json">
    <link rel="icon" type="image/svg+xml" href="/icon.svg">
    <link rel="apple-touch-icon" href="/icon.svg">
    <style>
        @font-face {
            font-family: 'JetBrains Mono';
            src: url('/fonts/JetBrainsMono-Regular.woff2') format('woff2');
            font-weight: 400;
            font-style: normal;
        }
        @font-face {
            font-family: 'JetBrains Mono';
            src: url('/fonts/JetBrainsMono-Medium.woff2') format('woff2');
            font-weight: 500;
            font-style: normal;
        }
        
        :root {
            --bg-primary: #161616;
            --bg-secondary: #151515;
            --bg-tertiary: #1a1a1a;
            --border: #2b2b2b;
            --text-primary: #e0e0e0;
            --text-secondary: #b6b6b6;
            --accent: #2ed573;
            --accent-muted: rgba(46, 213, 115, 0.6);
            --danger: #ff4757;
            --danger-muted: rgba(255, 71, 87, 0.6);
            --warning: #ffa502;
        }
        
        * { box-sizing: border-box; margin: 0; padding: 0; }
        
        body {
            font-family: 'JetBrains Mono', 'SF Mono', Consolas, monospace;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
            padding: 0;
            font-size: 12px;
            line-height: 1.4;
        }

        .container {
            width: 100%;
            padding: 0 6px;
            box-sizing: border-box;
        }
        
        /* Header */
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 32px;
        }
        
        .logo {
            display: flex;
            align-items: center;
            padding: 8px;
            color: var(--text-primary);
        }

        .logo svg {
            width: 38px;
            height: 38px;
        }

        #onboarding-logo svg {
            width: 32px;
            height: 32px;
        }

        .header-actions {
            display: flex;
            gap: 12px;
            align-items: center;
        }
        
        .icon-btn {
            background: none;
            border: none;
            color: var(--text-secondary);
            cursor: pointer;
            padding: 8px;
            border-radius: 6px;
            transition: all 0.15s;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .icon-btn:hover {
            background: var(--bg-tertiary);
            color: var(--text-primary);
        }
        
        .icon-btn.active {
            color: var(--accent);
        }
        
        .icon-btn svg {
            width: 18px;
            height: 18px;
        }

        #files-btn svg,
        #edit-toggle svg {
            width: 32px;
            height: 32px;
        }

        /* Header icon backgrounds with glass effect */
        .logo,
        #files-btn,
        #edit-toggle {
            background: var(--bg-secondary);
            border-radius: 12px;
            backdrop-filter: blur(var(--glass-blur, 0px));
            -webkit-backdrop-filter: blur(var(--glass-blur, 0px));
            border: 1px solid transparent;
            transition: border-color 0.15s, box-shadow 0.15s;
        }

        #files-btn,
        #edit-toggle {
            color: var(--text-primary);
        }


        .logo svg .icon-bg,
        #files-btn svg .icon-bg,
        #edit-toggle svg .icon-bg {
            fill: transparent;
        }

        .logo svg .icon-accent,
        #files-btn svg .icon-accent,
        #edit-toggle svg .icon-accent,
        #onboarding-modal .icon-accent {
            stroke: var(--accent);
        }

        /* Sections */
        .section {
            margin-bottom: 24px;
        }

        /* Hidden sections: invisible normally, collapsed in edit mode */
        .section-hidden {
            display: none;
        }

        .edit-mode .section-hidden {
            display: block;
            opacity: 0.4;
        }

        .edit-mode .section-hidden > *:not(.section-header) {
            display: none;
        }

        /* Empty sections: hidden until edit mode */
        .section-empty {
            display: none;
        }

        .section-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 12px;
            padding: 4px 8px;
            border-radius: 8px;
            border: 1px solid transparent;
            transition: border-color 0.15s;
            background: var(--bg-secondary);
        }

        .edit-mode .section-header {
            border-color: var(--border);
            background: var(--bg-secondary);
        }

        .section-header-left {
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .section-title {
            font-size: 11px;
            font-weight: 500;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .section-add {
            opacity: 0;
            pointer-events: none;
            transition: all 0.15s;
            background: var(--bg-secondary) !important;
        }

        .section-add:hover {
            background: var(--bg-tertiary) !important;
        }

        .edit-mode .section-add,
        .task-add {
            opacity: 1;
            pointer-events: auto;
        }

        .edit-mode .icon-btn.section-add,
        .edit-mode .icon-btn.section-add svg {
            color: var(--text-primary);
        }

        /* Section Drag & Drop */
        .edit-mode .section {
            cursor: grab;
        }

        .edit-mode .section.dragging {
            opacity: 0.5;
            cursor: grabbing;
        }

        .edit-mode .section.drag-over {
            border-color: var(--accent) !important;
            box-shadow: 0 0 0 2px var(--accent-muted);
        }

        /* Extension Sections */
        .extension-error {
            padding: 12px;
            background: rgba(255, 100, 100, 0.1);
            border: 1px solid rgba(255, 100, 100, 0.3);
            border-radius: 6px;
            color: #ff6464;
            font-size: 13px;
        }

        /* Links */
        .cards-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
            gap: 8px;
        }

        .cards-grid .card-item {
            min-width: 0;
            width: 100%;
        }

        .cards-grid .card-name {
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            flex: 1;
            min-width: 0;
        }

        .edit-mode .cards-grid {
            overflow: visible;
            padding-top: 12px;
            padding-right: 12px;
        }
        
        .card-item {
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 12px 16px;
            display: flex;
            align-items: center;
            gap: 10px;
            cursor: pointer;
            transition: all 0.15s;
            text-decoration: none;
            color: var(--text-primary);
            position: relative;
        }
        

        .edit-mode .card-item {
            cursor: grab;
        }

        .edit-mode .card-item.dragging {
            opacity: 0.5;
            cursor: grabbing;
        }

        .edit-mode .card-item.drag-over {
            border-color: var(--accent);
            box-shadow: inset 0 0 0 2px var(--accent);
            transform: scale(1.02);
        }
        
        .card-item svg,
        .card-item .custom-icon {
            width: 22px;
            height: 22px;
            color: var(--text-secondary);
            object-fit: contain;
        }

        .icons-mono .custom-icon {
            filter: grayscale(1) brightness(0.7) contrast(1.2);
        }

        .card-text {
            display: flex;
            flex-direction: column;
            min-width: 0;
            flex: 1;
        }

        .card-name {
            font-size: 12px;
            line-height: 1.2;
        }

        .card-note {
            font-size: 10px;
            line-height: 1.2;
            color: var(--text-secondary);
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        /* Edit/Delete buttons (shared) */
        .link-edit, .link-delete,
        .action-edit, .action-delete,
        .task-edit, .task-delete,
        .device-edit, .device-delete {
            display: none;
            position: absolute;
            top: -10px;
            width: 26px;
            height: 26px;
            border-radius: 50%;
            align-items: center;
            justify-content: center;
            cursor: pointer;
        }

        .link-edit, .action-edit, .task-edit, .device-edit {
            right: 28px;
            background: var(--accent-muted);
        }

        .link-delete, .action-delete, .task-delete, .device-delete {
            right: -10px;
            background: var(--danger-muted);
        }

        .edit-mode .link-edit, .edit-mode .link-delete,
        .edit-mode .action-edit, .edit-mode .action-delete,
        .edit-mode .task-edit, .edit-mode .task-delete,
        .edit-mode .device-edit, .edit-mode .device-delete {
            display: flex;
        }

        .link-edit svg, .action-edit svg, .task-edit svg, .device-edit svg {
            width: 16px;
            height: 16px;
            color: white;
        }

        .link-delete svg, .action-delete svg, .task-delete svg, .device-delete svg {
            width: 12px;
            height: 12px;
            color: white;
        }
        
        /* Devices */
        #devices-list {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 12px;
            align-items: start;
        }

        .device-card {
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 16px;
            position: relative;
        }

        .edit-mode .device-card {
            cursor: grab;
        }

        .edit-mode .device-card.dragging {
            opacity: 0.5;
            cursor: grabbing;
        }

        .edit-mode .device-card.drag-over {
            border-color: var(--accent);
            box-shadow: inset 0 0 0 2px var(--accent);
            transform: scale(1.01);
        }

        .device-header {
            display: flex;
            align-items: center;
            margin-bottom: 12px;
        }

        .device-info {
            display: flex;
            align-items: center;
            gap: 12px;
            flex: 1;
        }

        .device-icon {
            width: 32px;
            height: 32px;
            color: var(--text-secondary);
        }

        .device-icon svg,
        .device-icon .custom-icon {
            width: 32px;
            height: 32px;
            object-fit: contain;
        }

        .device-name {
            font-weight: 500;
        }
        
        .status-dot {
            width: 6px;
            height: 6px;
            border-radius: 50%;
        }
        
        .status-dot.online {
            background: var(--accent);
            box-shadow: 0 0 8px var(--accent);
        }
        
        .status-dot.offline {
            background: var(--danger);
        }
        
        .status-dot.loading {
            background: var(--warning);
            animation: pulse 1s infinite;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.4; }
        }

        .container-spinner {
            width: 12px;
            height: 12px;
            border: 2px solid var(--border);
            border-top-color: var(--accent);
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
            display: none;
            margin-left: 8px;
        }

        .container-spinner.active {
            display: inline-block;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        .onboarding-row {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 10px 12px;
            background: var(--bg-secondary);
            border-radius: 8px;
            margin-bottom: 8px;
        }
        .onboarding-row input[type="checkbox"] {
            width: 16px;
            height: 16px;
            accent-color: var(--accent);
        }
        .onboarding-row input[type="text"] {
            padding: 4px 8px;
            background: var(--bg-tertiary);
            border: 1px solid var(--border);
            border-radius: 4px;
            color: var(--text-primary);
            font-size: 12px;
        }
        .onboarding-row input[type="text"].ob-name {
            flex: 1;
            min-width: 100px;
            max-width: 140px;
        }
        .onboarding-row input[type="text"].ob-ssh {
            width: 70px;
            font-family: monospace;
        }
        .onboarding-row .ob-ip {
            font-size: 11px;
            color: var(--text-secondary);
            min-width: 100px;
        }
        .onboarding-row .ob-mac {
            font-size: 11px;
            color: var(--text-secondary);
            min-width: 90px;
            font-family: monospace;
        }
        .onboarding-row .ob-status {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: var(--text-secondary);
            flex-shrink: 0;
            margin-left: auto;
        }
        .onboarding-row .ob-status.online {
            background: var(--accent);
        }
        .onboarding-row.disabled {
            opacity: 0.5;
            pointer-events: none;
        }
        .onboarding-header {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 0 12px 8px;
            font-size: 11px;
            color: var(--text-secondary);
            border-bottom: 1px solid var(--border);
            margin-bottom: 8px;
        }
        .onboarding-header span:nth-child(1) { width: 16px; }
        .onboarding-header span:nth-child(2) { flex: 1; min-width: 100px; max-width: 140px; }
        .onboarding-header span:nth-child(3) { width: 70px; }
        .onboarding-header span:nth-child(4) { min-width: 100px; }
        .onboarding-header span:nth-child(5) { min-width: 100px; }
        .onboarding-header span:nth-child(6) { min-width: 90px; }
        .onboarding-header span:nth-child(7) { width: 8px; }
        .docker-scan-row {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 10px 12px;
            background: var(--bg-secondary);
            border-radius: 8px;
            margin-bottom: 8px;
        }
        .docker-scan-row input[type="checkbox"] {
            width: 16px;
            height: 16px;
            accent-color: var(--accent);
        }
        .docker-scan-row .ds-name {
            flex: 1;
            font-size: 13px;
        }
        .docker-scan-row .ds-status {
            font-size: 11px;
            color: var(--text-secondary);
        }
        .docker-scan-row .ds-status.success {
            color: var(--accent);
        }
        .docker-scan-row .ds-status.error {
            color: #ff6b6b;
        }
        .docker-scan-row.no-ssh {
            opacity: 0.5;
        }
        .docker-scan-row.no-ssh input[type="checkbox"] {
            display: none;
        }

        /* Stats bars */
        .device-stats-bars {
            display: flex;
            gap: 12px;
            margin-bottom: 12px;
            cursor: pointer;
        }

        .stat-bar-group {
            display: flex;
            align-items: center;
            gap: 6px;
            flex: 1;
        }

        .stat-label {
            font-size: 10px;
            color: var(--text-secondary);
            min-width: 32px;
        }

        .stat-bar {
            flex: 1;
            height: 6px;
            background: var(--bg-tertiary);
            border-radius: 3px;
            overflow: hidden;
        }

        .stat-bar-fill {
            height: 100%;
            border-radius: 3px;
            transition: width 0.3s ease;
        }

        .stat-value {
            font-size: 10px;
            color: var(--text-secondary);
            min-width: 28px;
            text-align: right;
            display: none;
        }

        .device-stats-bars.show-values .stat-bar {
            display: none;
        }

        .device-stats-bars.show-values .stat-value {
            display: block;
        }

        .stats-modal-btn {
            background: none;
            border: none;
            color: var(--text-secondary);
            cursor: pointer;
            padding: 4px;
            margin-left: 4px;
            opacity: 0.5;
            transition: opacity 0.15s, color 0.15s;
        }

        .stats-modal-btn:hover {
            opacity: 1;
            color: var(--accent);
        }

        .stats-modal-btn i {
            width: 16px;
            height: 16px;
        }

        /* Stats Modal */
        .stats-section {
            margin-bottom: 20px;
        }

        .stats-section:last-child {
            margin-bottom: 0;
        }

        .stats-section-title {
            font-size: 11px;
            font-weight: 500;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 8px;
        }

        .stats-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 11px;
        }

        .stats-table th {
            text-align: left;
            padding: 6px 8px;
            font-weight: 500;
            color: var(--text-secondary);
            font-size: 11px;
            border-bottom: 1px solid var(--border);
        }

        .stats-table td {
            padding: 6px 8px;
            border-bottom: 1px solid var(--border);
        }

        .stats-table tr:last-child td {
            border-bottom: none;
        }

        .stats-table th:nth-child(1) { width: 30%; }
        .stats-table th:nth-child(2) { width: 35%; }
        .stats-table th:nth-child(3) { width: 15%; text-align: center; }
        .stats-table th:nth-child(4) { width: 20%; }

        .stats-table td:nth-child(3) { text-align: center; }

        .stats-table input[type="checkbox"] {
            width: 16px;
            height: 16px;
            background: var(--bg-tertiary);
            border: 1px solid var(--border);
            border-radius: 4px;
            -webkit-appearance: none;
            appearance: none;
            cursor: pointer;
            position: relative;
        }

        .stats-table input[type="checkbox"]:checked {
            background: var(--accent);
            border-color: var(--accent);
        }

        .stats-table input[type="checkbox"]:checked::after {
            content: '';
            position: absolute;
            left: 4px;
            top: 1px;
            width: 5px;
            height: 9px;
            border: solid var(--bg-primary);
            border-width: 0 2px 2px 0;
            transform: rotate(45deg);
        }

        .container-stats-inline {
            color: var(--text-secondary);
            font-size: 10px;
            margin-left: 6px;
            white-space: nowrap;
        }

        @media (max-width: 500px) {
            .container-stats-inline {
                display: block;
                margin-left: 0;
                margin-top: 2px;
            }
        }

        .stats-table input[type="number"] {
            width: 55px;
            padding: 3px 6px;
            background: var(--bg-tertiary);
            border: 1px solid var(--border);
            border-radius: 4px;
            color: var(--text-primary);
            font-size: 11px;
        }

        .stats-table input[type="number"]:focus {
            outline: none;
            border-color: var(--accent);
        }

        .stats-value {
            font-family: monospace;
        }

        .stats-value.ok { color: var(--accent); }
        .stats-value.warn { color: var(--warning); }
        .stats-value.error { color: var(--danger); }

        .ok { color: var(--accent); }
        .error { color: var(--danger); }

        /* Status indicator (dot + uptime) */
        .device-status-indicator {
            display: flex;
            align-items: center;
            gap: 6px;
            margin-left: auto;
        }

        .device-uptime {
            font-size: 11px;
            color: var(--text-secondary);
        }

        /* Container styling */
        .container-name.container-online {
            color: var(--accent);
        }

        .container-start {
            color: var(--text-secondary) !important;
        }

        .container-stop {
            color: #ff4757 !important;
        }

        .connect-group {
            display: flex;
            gap: 8px;
            margin-right: 16px;
        }

        /* Tasks */
        #tasks-list {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 12px;
        }

        .task-card {
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 16px;
            position: relative;
        }

        .task-header {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 8px;
        }

        .task-icon {
            width: 24px;
            height: 24px;
            color: var(--text-secondary);
        }

        .task-name {
            font-weight: 500;
            flex: 1;
        }

        .task-schedule {
            font-size: 11px;
            color: var(--text-secondary);
        }

        .task-status {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 11px;
            color: var(--text-secondary);
        }

        .task-status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
        }

        .task-status-dot.success {
            background: var(--accent);
        }

        .task-status-dot.warning {
            background: #ffa502;
        }

        .task-status-dot.error {
            background: var(--danger);
        }

        .task-status-dot.paused {
            background: var(--text-secondary);
        }

        .task-status-dot.running {
            background: var(--accent);
            animation: pulse 1s ease-in-out infinite;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.4; }
        }

        .edit-mode .task-card {
            cursor: grab;
        }

        .edit-mode .task-card.dragging {
            opacity: 0.5;
            cursor: grabbing;
        }

        .edit-mode .task-card.drag-over {
            border-color: var(--accent);
            box-shadow: inset 0 0 0 2px var(--accent);
            transform: scale(1.01);
        }

        .task-card.running {
            border-color: var(--accent);
        }

        .task-btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }

        .task-actions {
            display: flex;
            gap: 8px;
            margin-top: 12px;
        }

        .task-btn {
            background: none;
            border: 1px solid var(--border);
            color: var(--text-secondary);
            padding: 4px 8px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 11px;
            display: flex;
            align-items: center;
            gap: 4px;
        }


        .task-empty {
            text-align: center;
            color: var(--text-secondary);
            padding: 24px;
            font-size: 14px;
        }

        /* Task Wizard */
        .wizard-step {
            min-height: 200px;
        }

        .wizard-nav {
            display: flex;
            justify-content: space-between;
            margin-top: 24px;
            padding-top: 16px;
            border-top: 1px solid var(--border);
        }

        .task-type-options {
            display: flex;
            flex-direction: column;
            gap: 8px;
        }

        .task-type-option {
            display: block;
            cursor: pointer;
        }

        .task-type-option input {
            display: none;
        }

        .task-type-label {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 12px;
            border: 1px solid var(--border);
            border-radius: 8px;
            transition: all 0.2s;
        }

        .task-type-label i {
            width: 24px;
            height: 24px;
            color: var(--text-secondary);
        }

        .task-type-label strong {
            flex: 1;
        }

        .task-type-label small {
            color: var(--text-secondary);
            font-size: 11px;
        }

        .task-type-option input:checked + .task-type-label {
            border-color: var(--accent);
            background: rgba(46, 213, 115, 0.1);
        }

        .task-type-option input:checked + .task-type-label i {
            color: var(--accent);
        }

        .form-checkbox {
            display: flex;
            align-items: center;
            gap: 8px;
            cursor: pointer;
        }

        .form-checkbox input {
            width: 16px;
            height: 16px;
        }

        .device-actions {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
        }
        
        .device-action {
            color: var(--text-secondary);
            font-size: 11px;
            cursor: pointer;
            padding: 4px 0;
            border: none;
            background: none;
            font-family: inherit;
            transition: color 0.15s;
        }
        
        .device-action:hover:not(:disabled) {
            color: var(--accent);
        }

        .device-action:disabled {
            opacity: 0.3;
            cursor: not-allowed;
        }

        .device-action:disabled:hover {
            color: var(--text-secondary);
        }

        .device-action.danger:hover:not(:disabled) {
            color: var(--danger);
        }
        
        .action-separator {
            color: var(--border);
        }

        .device-containers {
            margin-top: 4px;
            padding-top: 0;
        }

        .containers-toggle {
            display: flex;
            align-items: center;
            gap: 8px;
            cursor: pointer;
            user-select: none;
            margin-left: auto;
        }

        .containers-summary {
            display: flex;
            align-items: center;
            gap: 6px;
            font-size: 11px;
            color: var(--text-secondary);
        }

        .containers-chevron {
            width: 14px;
            height: 14px;
            transition: transform 0.2s;
            color: var(--text-secondary);
        }

        .containers-chevron.expanded {
            transform: rotate(180deg);
        }

        .containers-list {
            display: none;
        }

        .containers-list.expanded {
            display: block;
        }

        .container-row {
            display: flex;
            align-items: center;
            padding: 6px 0;
            font-size: 11px;
        }

        .container-name {
            color: var(--text-secondary);
            min-width: 120px;
        }

        .container-actions {
            display: flex;
            align-items: center;
            gap: 8px;
            margin-left: auto;
        }

        /* Theme Section */
        .theme-section {
            display: none;
        }

        .edit-mode .theme-section {
            display: block;
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
        }

        .theme-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 16px;
            margin-bottom: 16px;
        }

        /* Hover states - only on devices with pointer */
        @media (hover: hover) {
            #files-btn:hover,
            #edit-toggle:hover {
                background: var(--bg-secondary);
                color: var(--text-primary);
                border-color: var(--accent);
                box-shadow: 0 0 4px var(--accent);
            }
            .card-item:hover {
                border-color: var(--accent);
                background: var(--bg-tertiary);
            }
            .task-btn:hover {
                border-color: var(--text-secondary);
                color: var(--text-primary);
            }
            .task-btn.danger:hover {
                border-color: var(--danger);
                color: var(--danger);
            }
            .fm-btn:hover:not(:disabled) {
                background: var(--accent);
                border-color: var(--accent);
                color: var(--bg-primary);
            }
            .fm-btn.danger:hover:not(:disabled) {
                background: var(--danger);
                border-color: var(--danger);
            }
        }

        @media (max-width: 600px) {
            .theme-grid {
                grid-template-columns: repeat(2, 1fr);
            }
        }

        .theme-row {
            display: flex;
            gap: 16px;
            margin-bottom: 16px;
        }

        .theme-group {
            display: flex;
            flex-direction: column;
            gap: 6px;
        }

        .theme-group-wide {
            flex: 1;
        }

        .theme-group-full {
            width: 100%;
        }

        .theme-label {
            font-size: 11px;
            color: var(--text-secondary);
        }

        .theme-color-input {
            display: flex;
            gap: 8px;
            align-items: center;
        }

        .theme-color-input input[type="color"] {
            width: 36px;
            height: 36px;
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 2px;
            cursor: pointer;
            background: var(--bg-secondary);
        }

        .theme-color-input input[type="color"]::-webkit-color-swatch-wrapper {
            padding: 0;
        }

        .theme-color-input input[type="color"]::-webkit-color-swatch {
            border: none;
            border-radius: 4px;
        }

        .theme-hex {
            width: 80px;
            padding: 8px;
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 6px;
            color: var(--text-primary);
            font-family: inherit;
            font-size: 12px;
        }

        .theme-slider-row {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .theme-slider {
            flex: 1;
            height: 6px;
            -webkit-appearance: none;
            background: var(--bg-tertiary);
            border-radius: 3px;
            outline: none;
        }

        .theme-slider::-webkit-slider-thumb {
            -webkit-appearance: none;
            width: 18px;
            height: 18px;
            background: var(--accent);
            border-radius: 50%;
            cursor: pointer;
        }

        .theme-slider::-moz-range-thumb {
            width: 18px;
            height: 18px;
            background: var(--accent);
            border-radius: 50%;
            cursor: pointer;
            border: none;
        }

        #theme-glass-value,
        #theme-blur-value {
            font-size: 12px;
            color: var(--text-secondary);
            min-width: 40px;
        }

        .theme-actions {
            margin-top: 16px;
            padding-top: 16px;
            border-top: 1px solid var(--border);
        }

        /* Wallpaper & Glass Effect */
        body.has-wallpaper {
            background-size: cover;
            background-position: center;
            background-attachment: fixed;
        }

        body.has-wallpaper .card-item,
        body.has-wallpaper .device-card,
        body.has-wallpaper .task-card,
        body.has-wallpaper .theme-section,
        body.has-wallpaper .modal-content,
        body.has-wallpaper .section-header,
        body.has-wallpaper .fm-pane,
        body.has-wallpaper .fm-toolbar {
            backdrop-filter: blur(var(--glass-blur, 0px));
            -webkit-backdrop-filter: blur(var(--glass-blur, 0px));
        }

        body.has-wallpaper #fm-modal.visible {
            background: transparent;
        }

        body.has-wallpaper .fm-modal {
            backdrop-filter: blur(var(--glass-blur, 0px));
            -webkit-backdrop-filter: blur(var(--glass-blur, 0px));
            background: var(--bg-secondary);
        }

        /* Footer */
        .footer {
            display: flex;
            justify-content: flex-end;
            align-items: center;
            gap: 12px;
            margin-top: 32px;
            font-size: 11px;
            color: var(--text-secondary);
        }
        
        .version {
            cursor: pointer;
        }
        
        .version:hover {
            color: var(--text-primary);
        }
        
        /* Modal */
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0, 0, 0, 0.8);
            align-items: center;
            justify-content: center;
            z-index: 1000;
            padding: 10px;
        }
        
        .modal.visible {
            display: flex;
        }
        
        .modal-content {
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
            width: 100%;
            max-width: 800px;
            max-height: 92vh;
            overflow-y: auto;
        }

        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }
        
        .modal-title {
            font-weight: 500;
        }
        
        .modal-close {
            background: none;
            border: none;
            color: var(--text-secondary);
            cursor: pointer;
            padding: 4px;
        }
        
        .modal-close:hover {
            color: var(--text-primary);
        }

        .help-accordion {
            display: none;
            background: var(--bg-tertiary);
            border-radius: 8px;
            padding: 12px;
            margin-bottom: 16px;
            font-size: 11px;
            line-height: 1.4;
        }

        .help-accordion.visible {
            display: block;
        }

        .help-item {
            padding: 6px 0;
            border-bottom: 1px solid var(--border);
            color: var(--text-secondary);
        }

        .help-item:last-child {
            border-bottom: none;
            padding-bottom: 0;
        }

        .help-item:first-child {
            padding-top: 0;
        }

        .help-item strong {
            color: var(--text-primary);
        }

        .help-title {
            font-weight: 500;
            color: var(--text-primary);
            margin-bottom: 8px;
            font-size: 12px;
        }

        .help-item a {
            color: var(--accent);
        }

        /* Folder Browser */
        .folder-browser {
            border: 1px solid var(--border);
            border-radius: 8px;
            background: var(--bg-primary);
            overflow: hidden;
        }

        .folder-browser-path {
            padding: 10px 12px;
            background: var(--bg-tertiary);
            font-family: monospace;
            font-size: 11px;
            color: var(--text-secondary);
            border-bottom: 1px solid var(--border);
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            direction: rtl;
            text-align: left;
        }

        .folder-browser-filter {
            padding: 8px 12px;
            border-bottom: 1px solid var(--border);
        }

        .folder-browser-filter input {
            width: 100%;
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 4px;
            padding: 6px 10px;
            font-size: 11px;
            color: var(--text-primary);
        }

        .folder-browser-filter input:focus {
            outline: none;
            border-color: var(--accent);
        }

        .folder-browser-list {
            height: 280px;
            overflow-y: auto;
        }

        .folder-item {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 10px 12px;
            cursor: pointer;
            border-bottom: 1px solid var(--border);
            color: var(--text-primary);
            transition: background 0.1s;
        }

        .folder-item:last-child {
            border-bottom: none;
        }

        .folder-item:hover {
            background: var(--bg-secondary);
        }

        .folder-item.selected {
            background: var(--accent);
            color: var(--bg-primary);
        }

        .folder-item.selected .folder-icon {
            color: var(--bg-primary);
        }

        .folder-icon {
            color: var(--text-secondary);
            flex-shrink: 0;
        }

        .folder-name {
            flex: 1;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        .folder-browser-status {
            padding: 10px 12px;
            background: var(--bg-tertiary);
            border-top: 1px solid var(--border);
            font-size: 11px;
            color: var(--text-secondary);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .folder-browser-hint {
            font-size: 11px;
            color: var(--text-secondary);
            margin-top: 8px;
        }

        .folder-browser-error {
            padding: 20px;
            text-align: center;
            color: var(--danger);
        }

        .folder-browser-loading {
            padding: 40px;
            text-align: center;
            color: var(--text-secondary);
        }

        /* File Manager */
        .modal.fm-fullscreen {
            padding: 0;
        }

        .fm-modal {
            max-width: 100%;
            width: 100%;
            height: 100%;
            max-height: 100%;
            border-radius: 0;
            padding: 12px;
            display: flex;
            flex-direction: column;
        }

        .fm-container {
            flex: 1;
            display: flex;
            gap: 2px;
            background: var(--border);
            overflow: hidden;
            border-radius: 8px;
        }

        .fm-pane {
            flex: 1;
            display: flex;
            flex-direction: column;
            background: var(--bg-secondary);
            min-width: 0;
            border: 2px solid transparent;
            border-radius: 8px;
            overflow: hidden;
        }

        .fm-pane.active {
            border-color: var(--accent);
        }

        .fm-pane-header {
            padding: 12px;
            background: var(--bg-tertiary);
            border-bottom: 1px solid var(--border);
        }

        .fm-header-row {
            display: flex;
            gap: 8px;
            margin-bottom: 6px;
        }

        .fm-pane-header select {
            flex: 1;
            min-width: 0;
            font-size: 11px;
            text-overflow: ellipsis;
        }

        .fm-storage {
            flex: 1;
            display: flex;
            align-items: center;
            gap: 6px;
            font-size: 11px;
            color: var(--text-secondary);
            min-width: 0;
        }

        .fm-storage-text {
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        .fm-storage-bar {
            flex-shrink: 0;
            width: 50px;
            height: 6px;
            background: var(--bg-primary);
            border-radius: 3px;
            overflow: hidden;
        }

        .fm-storage-fill {
            height: 100%;
            border-radius: 3px;
            transition: width 0.3s ease;
        }

        .fm-storage-percent {
            flex-shrink: 0;
            min-width: 28px;
            text-align: right;
        }

        .fm-path {
            font-family: monospace;
            font-size: 11px;
            color: var(--text-secondary);
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            direction: rtl;
            text-align: left;
        }

        .fm-list {
            flex: 1;
            overflow-y: auto;
            user-select: none;
            -webkit-user-select: none;
        }

        .fm-item {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 8px 12px;
            cursor: pointer;
            border-bottom: 1px solid var(--border);
            color: var(--text-primary);
            font-size: 11px;
            transition: background 0.1s;
        }

        .fm-item:hover {
            background: var(--bg-tertiary);
        }

        .fm-item.selected {
            background: var(--accent);
            color: var(--bg-primary);
        }

        .fm-item.selected .fm-icon,
        .fm-item.selected .fm-size,
        .fm-item.selected .fm-date {
            color: var(--bg-primary);
        }

        .fm-icon {
            color: var(--text-secondary);
            flex-shrink: 0;
        }

        .fm-name {
            flex: 1;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            font-size: 12px;
        }

        .fm-size {
            font-size: 11px;
            color: var(--text-secondary);
            width: 70px;
            text-align: right;
        }

        .fm-date {
            font-size: 11px;
            color: var(--text-secondary);
            width: 75px;
            text-align: right;
        }

        .fm-actions {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            padding: 12px;
            background: var(--bg-tertiary);
            border-top: 1px solid var(--border);
            justify-content: center;
        }

        .fm-btn {
            padding: 8px 16px;
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 6px;
            color: var(--text-primary);
            font-family: inherit;
            font-size: 11px;
            cursor: pointer;
            transition: all 0.15s;
            position: relative;
            z-index: 1;
        }

        .fm-btn:active:not(:disabled) {
            background: var(--accent);
            border-color: var(--accent);
            color: var(--bg-primary);
        }

        .fm-btn:disabled {
            opacity: 0.3;
            cursor: not-allowed;
        }

        .fm-btn.danger:active:not(:disabled) {
            background: var(--danger);
            border-color: var(--danger);
        }

        .fm-progress {
            display: none;
            padding: 12px;
            background: var(--bg-tertiary);
            border-top: 1px solid var(--border);
        }

        .fm-progress.visible {
            display: block;
        }

        .fm-progress-bar {
            height: 8px;
            background: var(--bg-secondary);
            border-radius: 4px;
            overflow: hidden;
        }

        .fm-progress-fill {
            height: 100%;
            background: var(--accent);
            border-radius: 4px;
            transition: width 0.2s;
            width: 0%;
        }

        .fm-progress-text {
            font-size: 11px;
            color: var(--text-secondary);
            margin-top: 6px;
            text-align: center;
        }

        .fm-loading {
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 40px;
            color: var(--text-secondary);
        }

        .fm-error {
            padding: 20px;
            text-align: center;
            color: var(--danger);
        }

        @media (max-width: 768px) {
            .fm-modal {
                padding: 8px;
            }

            .fm-modal .modal-header {
                margin-bottom: 8px;
            }

            .fm-container {
                flex-direction: column;
            }

            .fm-pane {
                flex: 1;
                min-height: 0;
            }

            .fm-pane-header {
                padding: 8px;
            }

            .fm-header-row {
                gap: 6px;
                margin-bottom: 4px;
            }

            .fm-item {
                padding: 6px 8px;
                gap: 8px;
            }

            .fm-size, .fm-date {
                display: none;
            }

            .fm-actions {
                padding: 8px;
                gap: 6px;
            }

            .fm-btn {
                padding: 6px 10px;
            }
        }

        .form-group {
            margin-bottom: 16px;
        }
        
        .form-label {
            display: block;
            font-size: 11px;
            color: var(--text-secondary);
            margin-bottom: 6px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .form-input {
            width: 100%;
            background: var(--bg-tertiary);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 10px 12px;
            color: var(--text-primary);
            font-family: inherit;
            font-size: 12px;
            outline: none;
            -webkit-appearance: none;
            appearance: none;
        }

        select.form-input {
            background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%23888' stroke-width='2'%3E%3Cpath d='M6 9l6 6 6-6'/%3E%3C/svg%3E");
            background-repeat: no-repeat;
            background-position: right 10px center;
            padding-right: 32px;
            cursor: pointer;
        }

        select.form-input option {
            background: var(--bg-secondary);
            color: var(--text-primary);
        }

        input[type="time"].form-input {
            color-scheme: dark;
        }

        input[type="checkbox"].form-checkbox-input {
            width: 18px;
            height: 18px;
            background: var(--bg-tertiary);
            border: 1px solid var(--border);
            border-radius: 4px;
            -webkit-appearance: none;
            appearance: none;
            cursor: pointer;
            position: relative;
        }

        input[type="checkbox"].form-checkbox-input:checked {
            background: var(--accent);
            border-color: var(--accent);
        }

        input[type="checkbox"].form-checkbox-input:checked::after {
            content: '';
            position: absolute;
            left: 5px;
            top: 2px;
            width: 5px;
            height: 10px;
            border: solid var(--bg-primary);
            border-width: 0 2px 2px 0;
            transform: rotate(45deg);
        }

        .form-input:focus {
            border-color: var(--accent);
        }
        
        .form-row {
            display: flex;
            gap: 12px;
        }
        
        .form-row .form-group {
            flex: 1;
        }
        
        .form-hint {
            font-size: 11px;
            color: var(--text-secondary);
            margin-top: 4px;
        }

        .container-form-row {
            display: flex;
            gap: 8px;
            align-items: center;
            margin-bottom: 8px;
            padding: 8px;
            background: var(--bg-tertiary);
            border-radius: 6px;
        }

        .container-form-row input {
            flex: 1;
            min-width: 0;
        }

        .container-form-row .remove-btn {
            background: none;
            border: none;
            color: var(--danger);
            cursor: pointer;
            padding: 4px 8px;
            font-size: 16px;
        }
        
        .form-section {
            border-top: 1px solid var(--border);
            padding-top: 16px;
            margin-top: 16px;
        }
        
        .form-section-title {
            font-size: 11px;
            color: var(--text-secondary);
            margin-bottom: 12px;
        }
        
        .form-checkbox {
            display: flex;
            align-items: center;
            gap: 8px;
            cursor: pointer;
        }
        
        .form-checkbox input {
            width: 16px;
            height: 16px;
        }
        
        .btn {
            background: var(--accent);
            color: var(--bg-primary);
            border: none;
            border-radius: 6px;
            padding: 8px 10px;
            font-family: inherit;
            font-size: 12px;
            font-weight: 500;
            cursor: pointer;
            transition: opacity 0.15s;
        }
        
        .btn:hover {
            opacity: 0.9;
        }
        
        .btn-secondary {
            background: var(--bg-tertiary);
            color: var(--text-primary);
        }
        
        .modal-actions {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            justify-content: center;
            margin-top: 20px;
        }
        
        /* Toast notifications */
        .toast {
            position: fixed;
            bottom: 24px;
            left: 50%;
            transform: translateX(-50%);
            background: var(--bg-tertiary);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 12px 20px;
            font-size: 12px;
            z-index: 1001;
            opacity: 0;
            transition: opacity 0.2s;
            pointer-events: none;
        }
        
        .toast.visible {
            opacity: 1;
        }
        
        .toast.success {
            border-color: var(--accent);
        }
        
        .toast.error {
            border-color: var(--danger);
        }
    </style>
    <script src="https://unpkg.com/lucide@latest"></script>
</head>
<body>
    <div class="container">
        <header class="header">
            <a href="https://deq.rocks" target="_blank" rel="noopener" class="logo" id="header-logo"></a>
            <div class="header-actions">
                <button class="icon-btn" id="files-btn" title="File Manager" onclick="openFileManager()">
                    <svg viewBox="0 0 512 512" fill="none">
                        <rect class="icon-bg" width="512" height="512" rx="96"/>
                        <path d="M60 80 L190 80 Q210 80 210 100 L210 412 Q210 432 190 432 L60 432 Z" stroke="currentColor" stroke-width="16"/>
                        <line x1="85" y1="140" x2="185" y2="140" stroke="currentColor" stroke-width="12" stroke-linecap="round"/>
                        <line x1="85" y1="190" x2="160" y2="190" stroke="currentColor" stroke-width="12" stroke-linecap="round"/>
                        <line x1="85" y1="240" x2="175" y2="240" stroke="currentColor" stroke-width="12" stroke-linecap="round"/>
                        <path class="icon-accent" d="M302 80 L432 80 Q452 80 452 100 L452 412 Q452 432 432 432 L302 432 Z" fill="none" stroke-width="16"/>
                        <line class="icon-accent" x1="327" y1="140" x2="427" y2="140" stroke-width="12" stroke-linecap="round"/>
                        <line class="icon-accent" x1="327" y1="190" x2="390" y2="190" stroke-width="12" stroke-linecap="round"/>
                        <line class="icon-accent" x1="327" y1="240" x2="410" y2="240" stroke-width="12" stroke-linecap="round"/>
                        <line class="icon-accent" x1="230" y1="256" x2="275" y2="256" stroke-width="16" stroke-linecap="round"/>
                        <path class="icon-accent" d="M265 246 L280 256 L265 266" fill="none" stroke-width="16" stroke-linecap="round" stroke-linejoin="round"/>
                    </svg>
                </button>
                <button class="icon-btn" id="edit-toggle" title="Edit mode">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">
                        <rect class="icon-bg" width="512" height="512" rx="96"/>
                        <path d="M340 100 L412 172 L172 412 L100 412 L100 340 Z" fill="none" stroke="currentColor" stroke-width="16" stroke-linejoin="round"/>
                        <line x1="140" y1="372" x2="172" y2="340" stroke="currentColor" stroke-width="16" stroke-linecap="round"/>
                        <line class="icon-accent" x1="340" y1="100" x2="412" y2="172" stroke-width="16" stroke-linecap="round"/>
                        <line x1="300" y1="140" x2="372" y2="212" stroke="currentColor" stroke-width="16" stroke-linecap="round"/>
                    </svg>
                </button>
                <button class="icon-btn" id="logout-btn" title="Logout" onclick="logout()" style="display:none">
                    <i data-lucide="log-out"></i>
                </button>
            </div>
        </header>

        <!-- Dynamic Sections Container -->
        <div id="sections-container"></div>

        <!-- Theme Section (edit mode only) -->
        <section class="section theme-section" id="theme-section">
            <div class="section-header">
                <span class="section-title">Theme</span>
            </div>
            <div class="theme-grid">
                <div class="theme-group">
                    <label class="theme-label">Background</label>
                    <div class="theme-color-input">
                        <input type="color" id="theme-bg">
                        <input type="text" class="theme-hex" id="theme-bg-hex" maxlength="7">
                    </div>
                </div>
                <div class="theme-group">
                    <label class="theme-label">Cards</label>
                    <div class="theme-color-input">
                        <input type="color" id="theme-cards">
                        <input type="text" class="theme-hex" id="theme-cards-hex" maxlength="7">
                    </div>
                </div>
                <div class="theme-group">
                    <label class="theme-label">Border</label>
                    <div class="theme-color-input">
                        <input type="color" id="theme-border">
                        <input type="text" class="theme-hex" id="theme-border-hex" maxlength="7">
                    </div>
                </div>
                <div class="theme-group">
                    <label class="theme-label">Text</label>
                    <div class="theme-color-input">
                        <input type="color" id="theme-text">
                        <input type="text" class="theme-hex" id="theme-text-hex" maxlength="7">
                    </div>
                </div>
                <div class="theme-group">
                    <label class="theme-label">Text Muted</label>
                    <div class="theme-color-input">
                        <input type="color" id="theme-text-muted">
                        <input type="text" class="theme-hex" id="theme-text-muted-hex" maxlength="7">
                    </div>
                </div>
                <div class="theme-group">
                    <label class="theme-label">Accent</label>
                    <div class="theme-color-input">
                        <input type="color" id="theme-accent">
                        <input type="text" class="theme-hex" id="theme-accent-hex" maxlength="7">
                    </div>
                </div>
            </div>
            <div class="theme-row">
                <div class="theme-group theme-group-wide">
                    <label class="theme-label">Transparency</label>
                    <div class="theme-slider-row">
                        <input type="range" id="theme-glass" min="0" max="100" value="0" class="theme-slider">
                        <span id="theme-glass-value">0%</span>
                    </div>
                </div>
                <div class="theme-group theme-group-wide">
                    <label class="theme-label">Blur</label>
                    <div class="theme-slider-row">
                        <input type="range" id="theme-blur" min="0" max="30" value="0" class="theme-slider">
                        <span id="theme-blur-value">0px</span>
                    </div>
                </div>
            </div>
            <div class="theme-group theme-group-full">
                <label class="theme-label">Wallpaper</label>
                <input type="text" class="form-input" id="theme-wallpaper" placeholder="https://example.com/wallpaper.jpg">
                <div class="form-hint">Image URL (https://...)</div>
            </div>
            <div class="theme-actions">
                <button type="button" class="btn btn-secondary" onclick="resetTheme()">Reset to Defaults</button>
            </div>
        </section>

        <footer class="footer">
            <span class="version" id="version">v''' + VERSION + '''</span>
        </footer>
    </div>
    
    <!-- Link Modal -->
    <div class="modal" id="link-modal">
        <div class="modal-content">
            <div class="modal-header">
                <span class="modal-title" id="link-modal-title">Add Link</span>
                <button class="modal-close" onclick="closeModal('link-modal')"></button>
            </div>
            <form id="link-form">
                <input type="hidden" id="link-id">
                <div class="form-group">
                    <label class="form-label">Name</label>
                    <input type="text" class="form-input" id="card-name" required>
                </div>
                <div class="form-group">
                    <label class="form-label">URL</label>
                    <input type="url" class="form-input" id="link-url" required>
                </div>
                <div class="form-group">
                    <label class="form-label">Icon</label>
                    <input type="text" class="form-input" id="link-icon" placeholder="e.g. server, dash:proxmox, https://...">
                    <div class="form-hint">Lucide name, dash:name (dashboardicons.com), or image URL</div>
                </div>
                <div class="form-group">
                    <label class="form-label">Note</label>
                    <input type="text" class="form-input" id="card-note" placeholder="Optional, e.g. Runs on NAS">
                </div>
                <div class="modal-actions">
                    <button type="button" class="btn btn-secondary" onclick="closeModal('link-modal')">Cancel</button>
                    <button type="submit" class="btn">Save</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Quick Action Scan Modal -->
    <div class="modal" id="qa-scan-modal">
        <div class="modal-content" style="max-width: 600px;">
            <div class="modal-header">
                <span class="modal-title">Scan for Scripts</span>
                <button class="modal-close" onclick="closeModal('qa-scan-modal')"></button>
            </div>
            <div style="font-size: 12px; color: var(--text-secondary); margin-bottom: 12px;">
                Executable scripts in /opt/deq/scripts/
            </div>
            <div id="qa-scan-list" style="max-height: 400px; overflow-y: auto;"></div>
            <div class="modal-actions">
                <button type="button" class="btn btn-secondary" onclick="closeModal('qa-scan-modal')">Cancel</button>
                <button type="button" class="btn" onclick="addScannedActions()">Add Selected</button>
            </div>
        </div>
    </div>

    <!-- Quick Action Edit Modal -->
    <div class="modal" id="qa-modal">
        <div class="modal-content">
            <div class="modal-header">
                <span class="modal-title" id="qa-modal-title">Edit Script</span>
                <button class="modal-close" onclick="closeModal('qa-modal')"></button>
            </div>
            <form id="qa-form" onsubmit="saveQuickAction(event)">
                <input type="hidden" id="qa-id">
                <input type="hidden" id="qa-path">
                <div class="form-group">
                    <label class="form-label">Name</label>
                    <input type="text" class="form-input" id="qa-name" required>
                </div>
                <div class="form-group">
                    <label class="form-label">Icon</label>
                    <input type="text" class="form-input" id="qa-icon" placeholder="e.g. terminal, play, zap">
                    <div class="form-hint">Lucide icon name</div>
                </div>
                <div class="form-group">
                    <label class="form-label">Note</label>
                    <input type="text" class="form-input" id="qa-note" placeholder="Optional description">
                </div>
                <div class="modal-actions">
                    <button type="button" class="btn btn-secondary" onclick="closeModal('qa-modal')">Cancel</button>
                    <button type="submit" class="btn">Save</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Device Modal -->
    <div class="modal" id="device-modal">
        <div class="modal-content">
            <div class="modal-header">
                <span class="modal-title" id="device-modal-title">Add Device</span>
                <div style="display: flex; gap: 8px; align-items: center;">
                    <button type="button" class="icon-btn" onclick="document.getElementById('device-help').classList.toggle('visible')" title="Help">
                        <i data-lucide="circle-help" style="width: 18px; height: 18px;"></i>
                    </button>
                    <button class="modal-close" onclick="closeModal('device-modal')"></button>
                </div>
            </div>
            <div id="device-help" class="help-accordion">
                <div class="help-title">Field Reference</div>
                <div class="help-item"><strong>IP Address</strong> - LAN IP (192.168.x.x). Used by DeQ server for WOL, SSH, and ping.</div>
                <div class="help-item"><strong>Icon</strong> - Lucide icon name. Browse all at <a href="https://lucide.dev/icons" target="_blank">lucide.dev/icons</a></div>
                <div class="help-item"><strong>Wake-on-LAN</strong> - MAC address for magic packet. Broadcast is usually your IP ending in .255</div>
                <div class="help-item"><strong>RDP / VNC</strong> - Port only (e.g. 3389) → uses device IP. Full IP:port (e.g. 100.64.1.5:3389) → uses that directly.</div>
                <div class="help-item"><strong>Web</strong> - Full URL required (e.g. http://192.168.1.100 or http://100.64.1.5:8080)</div>
                <div class="help-item"><strong>Docker</strong> - Container name must match exactly. RDP/VNC/Web work the same as above.</div>
                <div class="help-item"><strong>SSH</strong> - Required for stats and shutdown. User needs sudo access for shutdown.</div>
            </div>
            <form id="device-form">
                <input type="hidden" id="device-id">
                <div class="form-group">
                    <label class="form-label">Name</label>
                    <input type="text" class="form-input" id="device-name" required>
                </div>
                <div class="form-row">
                    <div class="form-group">
                        <label class="form-label">IP Address</label>
                        <input type="text" class="form-input" id="device-ip" required>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Icon</label>
                        <input type="text" class="form-input" id="device-icon" placeholder="server, dash:synology, https://...">
                    </div>
                </div>
                <div class="form-hint">Icon: Lucide name, dash:name (dashboardicons.com), or image URL</div>

                <div class="form-section" id="section-wol">
                    <div class="form-section-title">Wake-on-LAN (optional)</div>
                    <div class="form-row">
                        <div class="form-group">
                            <label class="form-label">MAC Address</label>
                            <input type="text" class="form-input" id="device-mac" placeholder="AA:BB:CC:DD:EE:FF">
                        </div>
                        <div class="form-group">
                            <label class="form-label">Broadcast</label>
                            <input type="text" class="form-input" id="device-broadcast" placeholder="192.168.1.255">
                        </div>
                    </div>
                </div>

                <div class="form-section">
                    <div class="form-section-title">Connections (optional)</div>
                    <div class="form-row">
                        <div class="form-group">
                            <label class="form-label">RDP</label>
                            <input type="text" class="form-input" id="device-rdp" placeholder="host:port or port">
                        </div>
                        <div class="form-group">
                            <label class="form-label">VNC</label>
                            <input type="text" class="form-input" id="device-vnc" placeholder="host:port or port">
                        </div>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Web URL</label>
                        <input type="url" class="form-input" id="device-web" placeholder="http://...">
                    </div>
                </div>

                <div class="form-section">
                    <div class="form-section-title" style="display: flex; justify-content: space-between; align-items: center;">
                        Docker Containers (optional)
                        <div style="display: flex; gap: 4px;">
                            <button type="button" class="btn btn-secondary" onclick="scanContainers()" id="scan-containers-btn" style="padding: 4px 8px; font-size: 11px;">Scan</button>
                            <button type="button" class="icon-btn" onclick="addContainerRow()" style="padding: 4px;">+</button>
                        </div>
                    </div>
                    <div id="device-containers-list"></div>
                </div>
                
                <div class="form-section" id="section-ssh">
                    <div class="form-section-title">SSH (for shutdown & stats)</div>
                    <div class="form-row">
                        <div class="form-group">
                            <label class="form-label">SSH User</label>
                            <input type="text" class="form-input" id="device-ssh-user">
                        </div>
                        <div class="form-group">
                            <label class="form-label">SSH Port</label>
                            <input type="number" class="form-input" id="device-ssh-port" placeholder="22">
                        </div>
                    </div>
                </div>

                <div class="modal-actions">
                    <button type="button" class="btn btn-secondary" onclick="closeModal('device-modal')">Cancel</button>
                    <button type="submit" class="btn">Save</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Task Modal -->
    <div class="modal" id="task-modal">
        <div class="modal-content" style="max-width: 500px;">
            <div class="modal-header">
                <span class="modal-title" id="task-modal-title">New Task</span>
                <button class="modal-close" onclick="closeModal('task-modal')"></button>
            </div>
            <form onsubmit="saveTask(event)">
                <input type="hidden" id="task-id">

                <!-- Step 1: Action Type -->
                <div class="wizard-step" id="wizard-step-1">
                    <div class="form-section">
                        <div class="form-section-title">What do you want to do?</div>
                        <div class="task-type-options">
                            <label class="task-type-option">
                                <input type="radio" name="task-action" value="wake" checked>
                                <span class="task-type-label">
                                    <i data-lucide="power"></i>
                                    <strong>Power On</strong>
                                    <small>Devices or containers</small>
                                </span>
                            </label>
                            <label class="task-type-option">
                                <input type="radio" name="task-action" value="shutdown">
                                <span class="task-type-label">
                                    <i data-lucide="power-off"></i>
                                    <strong>Power Off</strong>
                                    <small>Devices or containers</small>
                                </span>
                            </label>
                            <label class="task-type-option">
                                <input type="radio" name="task-action" value="suspend">
                                <span class="task-type-label">
                                    <i data-lucide="moon"></i>
                                    <strong>Suspend</strong>
                                    <small>Devices only</small>
                                </span>
                            </label>
                            <label class="task-type-option">
                                <input type="radio" name="task-action" value="backup">
                                <span class="task-type-label">
                                    <i data-lucide="folder-sync"></i>
                                    <strong>Backup</strong>
                                    <small>Sync files between devices</small>
                                </span>
                            </label>
                            <label class="task-type-option">
                                <input type="radio" name="task-action" value="script">
                                <span class="task-type-label">
                                    <i data-lucide="terminal"></i>
                                    <strong>Script</strong>
                                    <small>Run a script on the host</small>
                                </span>
                            </label>
                        </div>
                    </div>
                    <div class="wizard-nav">
                        <span></span>
                        <button type="button" class="btn" onclick="wizardNext()">Next</button>
                    </div>
                </div>

                <!-- Step 2: Target Type (Device or Docker) - only for wake/shutdown -->
                <div class="wizard-step" id="wizard-step-2" style="display: none;">
                    <div class="form-section">
                        <div class="form-section-title">What do you want to <span id="step2-action">power on</span>?</div>
                        <div class="task-type-options">
                            <label class="task-type-option">
                                <input type="radio" name="task-target" value="device" checked>
                                <span class="task-type-label">
                                    <i data-lucide="server"></i>
                                    <strong>Device</strong>
                                    <small id="step2-device-desc">Wake via Wake-on-LAN</small>
                                </span>
                            </label>
                            <label class="task-type-option">
                                <input type="radio" name="task-target" value="docker">
                                <span class="task-type-label">
                                    <i data-lucide="box"></i>
                                    <strong>Docker Container</strong>
                                    <small id="step2-docker-desc">Start a container</small>
                                </span>
                            </label>
                        </div>
                    </div>
                    <div class="wizard-nav">
                        <button type="button" class="btn btn-secondary" onclick="wizardBack()">Back</button>
                        <button type="button" class="btn" onclick="wizardNext()">Next</button>
                    </div>
                </div>

                <!-- Step 3: Schedule -->
                <div class="wizard-step" id="wizard-step-3" style="display: none;">
                    <div class="form-section">
                        <div class="form-section-title">Schedule</div>
                        <div class="form-group">
                            <label class="form-label">Frequency</label>
                            <select class="form-input" id="task-frequency" onchange="updateScheduleOptions()">
                                <option value="hourly">Hourly</option>
                                <option value="daily" selected>Daily</option>
                                <option value="weekly">Weekly</option>
                                <option value="monthly">Monthly</option>
                            </select>
                        </div>
                        <div class="form-row">
                            <div class="form-group" id="schedule-time-group">
                                <label class="form-label">Time</label>
                                <input type="time" class="form-input" id="task-time" value="03:00">
                            </div>
                            <div class="form-group" id="schedule-day-group" style="display: none;">
                                <label class="form-label">Day</label>
                                <select class="form-input" id="task-day">
                                    <option value="0">Sunday</option>
                                    <option value="1">Monday</option>
                                    <option value="2">Tuesday</option>
                                    <option value="3">Wednesday</option>
                                    <option value="4">Thursday</option>
                                    <option value="5">Friday</option>
                                    <option value="6">Saturday</option>
                                </select>
                            </div>
                            <div class="form-group" id="schedule-date-group" style="display: none;">
                                <label class="form-label">Date</label>
                                <select class="form-input" id="task-date">
                                    <option value="1">1st</option>
                                    <option value="15">15th</option>
                                </select>
                            </div>
                        </div>
                    </div>
                    <div class="wizard-nav">
                        <button type="button" class="btn btn-secondary" onclick="wizardBack()">Back</button>
                        <button type="button" class="btn" onclick="wizardNext()">Next</button>
                    </div>
                </div>

                <!-- Step 4: Target Selection (Device or Container) -->
                <div class="wizard-step" id="wizard-step-4" style="display: none;">
                    <div class="form-section">
                        <div class="form-section-title" id="step4-title">Target</div>
                        <div class="form-group" id="target-device-group">
                            <label class="form-label">Device</label>
                            <select class="form-input" id="task-target-device"></select>
                        </div>
                        <div class="form-group" id="target-container-group" style="display: none;">
                            <label class="form-label">Container</label>
                            <select class="form-input" id="task-target-container"></select>
                        </div>
                    </div>
                    <div class="wizard-nav">
                        <button type="button" class="btn btn-secondary" onclick="wizardBack()">Back</button>
                        <button type="button" class="btn" onclick="wizardNext()">Next</button>
                    </div>
                </div>

                <!-- Step 5: Backup Source -->
                <div class="wizard-step" id="wizard-step-5" style="display: none;">
                    <div class="form-section">
                        <div class="form-section-title">Source</div>
                        <div class="form-group">
                            <label class="form-label">Device</label>
                            <select class="form-input" id="task-source-device" onchange="browseFolder('source')"></select>
                        </div>
                        <div class="folder-browser" id="source-browser">
                            <div class="folder-browser-path" id="source-selected">/</div>
                            <div class="folder-browser-filter">
                                <input type="text" id="source-filter" placeholder="Filter folders..." oninput="filterFolders('source')">
                            </div>
                            <div class="folder-browser-list" id="source-list"></div>
                        </div>
                        <input type="hidden" id="task-source-path">
                        <div class="folder-browser-hint">Click = select folder, Double-click = select contents inside folder</div>
                    </div>
                    <div class="wizard-nav">
                        <button type="button" class="btn btn-secondary" onclick="wizardBack()">Back</button>
                        <button type="button" class="btn" onclick="wizardNext()">Next</button>
                    </div>
                </div>

                <!-- Step 6: Backup Destination -->
                <div class="wizard-step" id="wizard-step-6" style="display: none;">
                    <div class="form-section">
                        <div class="form-section-title">Destination</div>
                        <div class="form-group">
                            <label class="form-label">Device</label>
                            <select class="form-input" id="task-dest-device" onchange="browseFolder('dest')"></select>
                        </div>
                        <div class="folder-browser" id="dest-browser">
                            <div class="folder-browser-path" id="dest-selected">/</div>
                            <div class="folder-browser-filter">
                                <input type="text" id="dest-filter" placeholder="Filter folders..." oninput="filterFolders('dest')">
                            </div>
                            <div class="folder-browser-list" id="dest-list"></div>
                        </div>
                        <input type="hidden" id="task-dest-path">
                        <div class="folder-browser-hint">Double-click = navigate, Click = select target</div>
                    </div>
                    <div class="wizard-nav">
                        <button type="button" class="btn btn-secondary" onclick="wizardBack()">Back</button>
                        <button type="button" class="btn" onclick="wizardNext()">Next</button>
                    </div>
                </div>

                <!-- Step 7: Options & Name -->
                <div class="wizard-step" id="wizard-step-7" style="display: none;">
                    <div class="form-section">
                        <div class="form-section-title">Options</div>
                        <div class="form-group">
                            <label class="form-label">Task Name</label>
                            <input type="text" class="form-input" id="task-name" placeholder="My task name">
                        </div>
                        <div class="form-group" id="backup-options" style="display: none;">
                            <label class="form-checkbox">
                                <input type="checkbox" class="form-checkbox-input" id="task-delete-files">
                                <span>Mirror mode (remove extra files from destination)</span>
                            </label>
                        </div>
                    </div>
                    <div class="wizard-nav">
                        <button type="button" class="btn btn-secondary" onclick="wizardBack()">Back</button>
                        <button type="submit" class="btn">Create Task</button>
                    </div>
                </div>

                <!-- Step 8: Script Selection -->
                <div class="wizard-step" id="wizard-step-8" style="display: none;">
                    <div class="form-section">
                        <div class="form-section-title">Script</div>
                        <div class="form-group">
                            <label class="form-label">Select Script</label>
                            <select class="form-input" id="task-script"></select>
                        </div>
                        <div style="font-size: 11px; color: var(--text-secondary); margin-top: 8px;">
                            Scripts from /opt/deq/scripts/
                        </div>
                    </div>
                    <div class="wizard-nav">
                        <button type="button" class="btn btn-secondary" onclick="wizardBack()">Back</button>
                        <button type="button" class="btn" onclick="wizardNext()">Next</button>
                    </div>
                </div>

            </form>
        </div>
    </div>

    <!-- File Manager Modal -->
    <div class="modal fm-fullscreen" id="fm-modal">
        <div class="modal-content fm-modal">
            <div class="modal-header">
                <span class="modal-title">File Manager</span>
                <button class="modal-close" onclick="closeModal('fm-modal')"></button>
            </div>
            <div class="fm-container">
                <div class="fm-pane" id="fm-left">
                    <div class="fm-pane-header">
                        <div class="fm-header-row">
                            <select class="form-input" id="fm-left-device" onchange="fmLoadFiles('left')"></select>
                            <div class="fm-storage" id="fm-left-storage"></div>
                        </div>
                        <div class="fm-path" id="fm-left-path">/</div>
                    </div>
                    <div class="fm-list" id="fm-left-list"></div>
                </div>
                <div class="fm-pane" id="fm-right">
                    <div class="fm-pane-header">
                        <div class="fm-header-row">
                            <select class="form-input" id="fm-right-device" onchange="fmLoadFiles('right')"></select>
                            <div class="fm-storage" id="fm-right-storage"></div>
                        </div>
                        <div class="fm-path" id="fm-right-path">/</div>
                    </div>
                    <div class="fm-list" id="fm-right-list"></div>
                </div>
            </div>
            <div class="fm-actions">
                <button class="fm-btn" id="fm-copy" onclick="fmCopy()" disabled>Copy</button>
                <button class="fm-btn" id="fm-move" onclick="fmMove()" disabled>Move</button>
                <button class="fm-btn" id="fm-newfolder" onclick="fmNewFolder()" disabled>New Folder</button>
                <button class="fm-btn" id="fm-rename" onclick="fmRename()" disabled>Rename</button>
                <button class="fm-btn danger" id="fm-delete" onclick="fmDelete()" disabled>Delete</button>
                <button class="fm-btn" id="fm-zip" onclick="fmZip()" disabled>Zip</button>
                <button class="fm-btn" id="fm-extract" onclick="fmExtract()" disabled>Extract</button>
                <button class="fm-btn" id="fm-download" onclick="fmDownload()" disabled>Download</button>
                <button class="fm-btn" id="fm-upload" onclick="document.getElementById('fm-upload-input').click()">Upload</button>
                <input type="file" id="fm-upload-input" multiple style="display:none" onchange="fmUploadFiles(this.files)">
            </div>
            <div class="fm-progress" id="fm-progress">
                <div class="fm-progress-bar">
                    <div class="fm-progress-fill" id="fm-progress-fill"></div>
                </div>
                <div class="fm-progress-text" id="fm-progress-text">Uploading...</div>
            </div>
        </div>
    </div>

    <!-- Toast -->
    <div class="toast" id="toast"></div>

    <!-- Onboarding Modal -->
    <div class="modal" id="onboarding-modal">
        <div class="modal-content" style="max-width: 700px;">
            <div class="modal-header">
                <div style="display: flex; align-items: center; gap: 12px;">
                    <span id="onboarding-logo" style="width: 32px; height: 32px;"></span>
                    <span class="modal-title" id="onboarding-title">Welcome to DeQ!</span>
                </div>
                <button class="modal-close" onclick="closeOnboarding(true)"></button>
            </div>
            <div id="onboarding-content">
                <div id="onboarding-loading" style="text-align: center; padding: 40px;">
                    <p style="margin-bottom: 20px; color: var(--text-primary);">Your new Admin Dash.</p>
                    <div class="container-spinner active" style="width: 24px; height: 24px; margin: 0 auto;"></div>
                    <p style="margin-top: 16px; color: var(--text-secondary);">Scanning your network...</p>
                </div>
                <div id="onboarding-devices" style="display: none;">
                    <p style="color: var(--text-secondary); margin-bottom: 12px;">We found these devices. Select the ones you want to add:</p>
                    <div id="onboarding-device-list" style="max-height: 280px; overflow-y: auto;"></div>
                    <p style="color: var(--text-secondary); font-size: 11px; margin-top: 12px;">Don't see a device? You can always add more manually later.</p>
                </div>
                <div id="onboarding-empty" style="display: none; text-align: center; padding: 40px;">
                    <p style="color: var(--text-primary); margin-bottom: 8px;">Your new Admin Dash.</p>
                    <p style="color: var(--text-secondary);">We couldn't find any devices on your network.</p>
                    <p style="color: var(--text-secondary); font-size: 12px; margin-top: 8px;">No worries - you can add them manually from the dashboard.</p>
                </div>
            </div>
            <div class="modal-actions" id="onboarding-actions" style="display: none;">
                <button type="button" class="btn btn-secondary" onclick="onboardingSelectAll()">All</button>
                <button type="button" class="btn btn-secondary" onclick="onboardingSelectNone()">None</button>
                <button type="button" class="btn btn-secondary" onclick="onboardingSelectLinux()">Linux</button>
                <button type="button" class="btn btn-secondary" id="onboarding-skip-btn" onclick="closeOnboarding(true)">Skip</button>
                <button type="button" class="btn btn-primary" onclick="addOnboardingDevices()">Add</button>
            </div>
            <div class="modal-actions" id="onboarding-empty-actions" style="display: none;">
                <button type="button" class="btn btn-primary" onclick="closeOnboarding(true)">Get Started</button>
            </div>
        </div>
    </div>

    <!-- Device Stats Modal -->
    <div class="modal" id="stats-modal">
        <div class="modal-content" style="max-width: 700px;">
            <div class="modal-header">
                <span class="modal-title" id="stats-modal-title">Device Stats</span>
                <button class="modal-close" onclick="closeModal('stats-modal')"></button>
            </div>
            <div id="stats-modal-content">
                <div id="stats-loading" style="text-align: center; padding: 40px;">
                    <div class="container-spinner active" style="width: 24px; height: 24px; margin: 0 auto;"></div>
                    <p style="margin-top: 16px; color: var(--text-secondary);">Loading stats...</p>
                </div>
                <div id="stats-data" style="display: none;">
                    <div class="stats-section">
                        <div class="stats-section-title">Hardware</div>
                        <table class="stats-table">
                            <thead>
                                <tr>
                                    <th>Stat</th>
                                    <th>Value</th>
                                    <th>Alert</th>
                                    <th>Event</th>
                                </tr>
                            </thead>
                            <tbody id="stats-hardware"></tbody>
                        </table>
                    </div>
                    <div class="stats-section" id="stats-mounts-section">
                        <div class="stats-section-title">Mounts</div>
                        <table class="stats-table">
                            <thead>
                                <tr>
                                    <th>Mount</th>
                                    <th>Usage</th>
                                    <th>Alert</th>
                                    <th>Event</th>
                                </tr>
                            </thead>
                            <tbody id="stats-mounts"></tbody>
                        </table>
                    </div>
                    <div class="stats-section" id="stats-disks-section">
                        <div class="stats-section-title">Disks</div>
                        <table class="stats-table">
                            <thead>
                                <tr>
                                    <th>Disk</th>
                                    <th>Prop</th>
                                    <th>Value</th>
                                    <th>Alert</th>
                                    <th>Event</th>
                                </tr>
                            </thead>
                            <tbody id="stats-disks"></tbody>
                        </table>
                    </div>
                    <div class="stats-section" id="stats-containers-section">
                        <div class="stats-section-title">Containers</div>
                        <table class="stats-table">
                            <thead>
                                <tr>
                                    <th>Container</th>
                                    <th>Status</th>
                                    <th>On Exit</th>
                                </tr>
                            </thead>
                            <tbody id="stats-containers"></tbody>
                        </table>
                    </div>
                </div>
            </div>
            <div class="modal-actions">
                <button type="button" class="btn btn-secondary" onclick="closeModal('stats-modal')">Cancel</button>
                <button type="button" class="btn" onclick="saveStatsConfig()">Save</button>
            </div>
        </div>
    </div>

    <!-- Docker Scan Modal -->
    <div class="modal" id="docker-scan-modal">
        <div class="modal-content" style="max-width: 500px;">
            <div class="modal-header">
                <span class="modal-title">Scan for Docker containers?</span>
                <button class="modal-close" onclick="closeDockerScan()"></button>
            </div>
            <div id="docker-scan-content">
                <div id="docker-scan-checking" style="text-align: center; padding: 30px;">
                    <div class="container-spinner active" style="width: 24px; height: 24px; margin: 0 auto;"></div>
                    <p style="margin-top: 16px; color: var(--text-secondary);">Checking SSH access...</p>
                </div>
                <div id="docker-scan-available" style="display: none;">
                    <p style="color: var(--text-secondary); margin-bottom: 12px;">SSH access available on:</p>
                    <div id="docker-scan-list" style="max-height: 200px; overflow-y: auto;"></div>
                </div>
                <div id="docker-scan-none" style="display: none; text-align: center; padding: 20px;">
                    <p style="color: var(--text-secondary);">No SSH access configured yet.</p>
                    <p style="color: var(--text-secondary); font-size: 12px; margin-top: 8px;">To scan for Docker containers, set up SSH keys first.<br>You can configure SSH later in device settings.</p>
                </div>
            </div>
            <div class="modal-actions" id="docker-scan-actions" style="display: none;">
                <button type="button" class="btn btn-secondary" onclick="closeDockerScan()">Skip</button>
                <button type="button" class="btn btn-primary" onclick="runDockerScan()">Scan</button>
            </div>
            <div class="modal-actions" id="docker-scan-none-actions" style="display: none;">
                <button type="button" class="btn btn-primary" onclick="closeDockerScan()">Continue</button>
            </div>
        </div>
    </div>

    <script>
        const NEEDS_ONBOARDING = __NEEDS_ONBOARDING__;
        // UUID fallback for non-secure contexts (HTTP)
        function generateUUID() {
            if (typeof crypto !== 'undefined' && crypto.randomUUID) {
                return crypto.randomUUID();
            }
            // Fallback for HTTP contexts
            return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
                const r = Math.random() * 16 | 0;
                const v = c === 'x' ? r : (r & 0x3 | 0x8);
                return v.toString(16);
            });
        }

        let config = {settings: {}, links: [], devices: []};
        let editMode = false;
        let deviceStats = {};

        const LOGO_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">
          <rect class="icon-bg" width="512" height="512" rx="96"/>
          <path d="M80 80 L210 80 Q230 80 230 100 L230 412 Q230 432 210 432 L80 432 Z" fill="none" stroke="currentColor" stroke-width="16"/>
          <path d="M430 155 L432 100 Q432 80 412 80 L302 80 Q282 80 282 100 L282 210 Q282 230 302 230 L430 230" fill="none" stroke="currentColor" stroke-width="16" stroke-linecap="round"/>
          <line x1="400" y1="155" x2="428" y2="155" stroke="currentColor" stroke-width="16" stroke-linecap="round"/>
          <path class="icon-accent" d="M432 380 L432 302 Q432 282 412 282 L302 282 Q282 282 282 302 L282 412 Q282 432 302 432 L380 432" fill="none" stroke-width="16" stroke-linecap="round"/>
          <line class="icon-accent" x1="405" y1="405" x2="435" y2="435" stroke-width="16" stroke-linecap="round"/>
        </svg>`;

        const ICON_CLOSE = `<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>`;
        const ICON_PLUS = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg>`;
        const ICON_EDIT = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 3a2.85 2.83 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5Z"></path><path d="m15 5 4 4"></path></svg>`;
        const ICON_DELETE = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="20" y1="4" x2="4" y2="20"></line><line x1="4" y1="4" x2="20" y2="20"></line></svg>`;

        // Security: HTML escaping for user input
        function escapeHTML(str) {
            if (!str) return '';
            return String(str)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#39;');
        }

        // Platform detection
        const ua = navigator.userAgent;
        const platform = {
            isIOS: /iPad|iPhone|iPod/.test(ua),
            isAndroid: /Android/.test(ua),
            isMac: /Macintosh/.test(ua) && !('ontouchend' in document),
            isWindows: /Windows/.test(ua),
            isLinux: /Linux/.test(ua) && !/Android/.test(ua),
            isChromeOS: /CrOS/.test(ua)
        };
        const currentPlatform = platform.isIOS ? 'ios' : platform.isAndroid ? 'android' :
                                platform.isMac ? 'mac' : platform.isWindows ? 'windows' :
                                platform.isLinux ? 'linux' : 'unknown';
        
        // === API ===
        async function api(endpoint, method = 'GET', data = null) {
            const opts = {
                method,
                headers: {'Content-Type': 'application/json'}
            };
            if (data) opts.body = JSON.stringify(data);
            const res = await fetch(`/api/${endpoint}`, opts);
            return res.json();
        }
        
        // === Toast ===
        function toast(msg, type = 'success') {
            const el = document.getElementById('toast');
            el.textContent = msg;
            el.className = 'toast visible ' + type;
            setTimeout(() => el.classList.remove('visible'), 3000);
        }
        
        // === Modal ===
        function openModal(id) {
            document.getElementById(id).classList.add('visible');
        }
        
        function closeModal(id) {
            document.getElementById(id).classList.remove('visible');
        }
        
        // === Icons ===
        function getIcon(icon) {
            if (!icon) icon = 'link';

            // URL format: url:https://... or just https://...
            if (icon.startsWith('url:')) {
                return `<img src="${icon.slice(4)}" class="custom-icon" alt="">`;
            }
            if (icon.startsWith('http://') || icon.startsWith('https://')) {
                return `<img src="${icon}" class="custom-icon" alt="">`;
            }

            // Dashboard Icons format: dashboard:proxmox or dash:proxmox
            if (icon.startsWith('dashboard:') || icon.startsWith('dash:')) {
                const name = icon.includes(':') ? icon.split(':')[1] : icon;
                return `<img src="https://cdn.jsdelivr.net/gh/walkxcode/dashboard-icons/png/${name}.png" class="custom-icon" alt="">`;
            }

            // Lucide format: lucide:server or just server (default)
            const lucideName = icon.startsWith('lucide:') ? icon.slice(7) : icon;
            return `<i data-lucide="${lucideName}"></i>`;
        }

        function refreshIcons() {
            if (typeof lucide !== 'undefined') {
                lucide.createIcons();
            }
        }
        
        // === Format Helpers ===
        function formatBytes(bytes) {
            if (bytes < 1e9) return (bytes / 1e6).toFixed(0) + 'MB';
            if (bytes < 1e12) return (bytes / 1e9).toFixed(1) + 'GB';
            return (bytes / 1e12).toFixed(2) + 'TB';
        }

        // HSV gradient: H from 99 (green) to 0 (red) based on percentage
        function getBarColor(percent) {
            const hue = Math.round(99 - (percent * 0.99));
            return `hsl(${hue}, 70%, 45%)`;
        }

        // Toggle between bar and value display
        let showValues = false;
        let showValuesTimer = null;
        function toggleStatsMode(el) {
            if (showValuesTimer) clearTimeout(showValuesTimer);
            showValues = !showValues;
            document.querySelectorAll('.device-stats-bars').forEach(bars => {
                bars.classList.toggle('show-values', showValues);
            });
            if (showValues) {
                showValuesTimer = setTimeout(() => {
                    showValues = false;
                    document.querySelectorAll('.device-stats-bars').forEach(bars => {
                        bars.classList.remove('show-values');
                    });
                }, 5000);
            }
        }

        // === Section System ===

        const CORE_SECTIONS = {
            devices: {
                id: 'devices',
                title: 'Devices',
                icon: 'server',
                render: () => renderDevicesContent(),
                toggleKey: 'show_devices',
                buttons: [
                    { icon: 'radar', onclick: 'startOnboarding(true)', title: 'Scan for devices' },
                    { icon: 'plus', onclick: 'openDeviceModal()', title: 'Add device', class: 'icon-plus' }
                ]
            },
            links: {
                id: 'links',
                title: 'Links',
                icon: 'bookmark',
                render: () => renderLinksContent(),
                toggleKey: 'show_links',
                buttons: [
                    { icon: 'palette', onclick: 'toggleMonochrome()', title: 'Toggle monochrome icons', id: 'mono-toggle' },
                    { icon: 'plus', onclick: 'openLinkModal()', title: 'Add link', class: 'icon-plus' }
                ]
            },
            quick_actions: {
                id: 'quick_actions',
                title: 'Scripts',
                icon: 'terminal',
                render: () => renderActionsContent(),
                toggleKey: 'show_actions',
                buttons: [
                    { icon: 'radar', onclick: 'scanQuickActions()', title: 'Scan for scripts' }
                ]
            },
            tasks: {
                id: 'tasks',
                title: 'Scheduled Tasks',
                icon: 'calendar-clock',
                render: () => renderTasksContent(),
                toggleKey: 'show_tasks',
                buttons: [
                    { icon: 'plus', onclick: 'openTaskWizard()', title: 'Add task', class: 'icon-plus' }
                ]
            }
        };

        let extensionSections = {};
        let draggedSectionId = null;
        let extensionsLoaded = false;

        async function loadExtensions() {
            try {
                const res = await api('health');
                if (res.extensions && res.extensions.length > 0) {
                    const newSections = {};
                    res.extensions.forEach(ext => {
                        newSections[ext.id] = {
                            id: ext.id,
                            title: ext.title,
                            icon: ext.icon,
                            render: () => ext.html,
                            toggleKey: `show_${ext.id}`,
                            buttons: []
                        };

                        // Add to section_order if not present
                        if (!config.settings.section_order) {
                            config.settings.section_order = ['devices', 'links', 'quick_actions', 'tasks'];
                        }
                        if (!config.settings.section_order.includes(ext.id)) {
                            config.settings.section_order.push(ext.id);
                        }
                    });

                    const changed = JSON.stringify(newSections) !== JSON.stringify(extensionSections);
                    const newExtensions = Object.keys(newSections).length > Object.keys(extensionSections).length;
                    extensionSections = newSections;

                    if (changed || !extensionsLoaded) {
                        extensionsLoaded = true;
                        // Save config if new extensions were added to section_order
                        if (newExtensions) {
                            saveConfig();
                        }
                        renderSections();
                    }
                }
            } catch (e) {
                console.log('Failed to load extensions:', e);
            }
        }

        function renderSections() {
            const container = document.getElementById('sections-container');
            if (!container) return;

            const order = config.settings.section_order || ['devices', 'links', 'quick_actions', 'tasks'];
            const allSections = { ...CORE_SECTIONS, ...extensionSections };
            const isEditMode = document.body.classList.contains('edit-mode');

            container.innerHTML = order
                .filter(id => allSections[id])
                .map(id => {
                    const section = allSections[id];
                    const isHidden = config.settings[section.toggleKey] === false;
                    const isEmpty = isSectionEmpty(id);
                    const hideSection = isEmpty && !isEditMode;

                    const buttonsHtml = (section.buttons || []).map(btn =>
                        `<button class="icon-btn section-add ${btn.class || ''}" ${btn.id ? `id="${btn.id}"` : ''} onclick="${btn.onclick}" title="${btn.title}">
                            <i data-lucide="${btn.icon}"></i>
                        </button>`
                    ).join('');

                    const toggleIcon = isHidden ? 'eye' : 'eye-off';

                    return `
                        <section class="section ${isHidden ? 'section-hidden' : ''} ${hideSection ? 'section-empty' : ''}"
                                 id="${id}-section"
                                 data-section-id="${id}"
                                 draggable="true">
                            <div class="section-header">
                                <div class="section-header-left">
                                    <span class="section-title">${escapeHTML(section.title)}</span>
                                    <button class="icon-btn section-add section-toggle" id="${id}-toggle" title="${isHidden ? 'Show' : 'Hide'} section" onclick="toggleSection('${id}')">
                                        <i data-lucide="${toggleIcon}"></i>
                                    </button>
                                </div>
                                ${buttonsHtml}
                            </div>
                            <div class="section-content" id="${id}-content">
                                ${section.render()}
                            </div>
                        </section>
                    `;
                }).join('');

            refreshIcons();
            applyMonochrome();
            attachSectionDragHandlers();
        }

        function isSectionEmpty(id) {
            switch(id) {
                case 'links': return !config.links || config.links.length === 0;
                case 'quick_actions': return !config.quick_actions || config.quick_actions.length === 0;
                case 'devices': return !config.devices || config.devices.length === 0;
                case 'tasks': return !config.tasks || config.tasks.length === 0;
                default: return false;
            }
        }

        function attachSectionDragHandlers() {
            document.querySelectorAll('#sections-container .section').forEach(section => {
                section.ondragstart = sectionDragStart;
                section.ondragover = sectionDragOver;
                section.ondragleave = sectionDragLeave;
                section.ondrop = sectionDrop;
                section.ondragend = sectionDragEnd;
            });
        }

        function sectionDragStart(e) {
            if (!document.body.classList.contains('edit-mode')) {
                e.preventDefault();
                return;
            }
            draggedSectionId = e.target.closest('.section').dataset.sectionId;
            e.target.closest('.section').classList.add('dragging');
            e.dataTransfer.effectAllowed = 'move';
        }

        function sectionDragOver(e) {
            if (!draggedSectionId) return;
            e.preventDefault();
            const target = e.target.closest('.section');
            if (target && target.dataset.sectionId !== draggedSectionId) {
                target.classList.add('drag-over');
            }
        }

        function sectionDragLeave(e) {
            const target = e.target.closest('.section');
            if (target) target.classList.remove('drag-over');
        }

        function sectionDrop(e) {
            e.preventDefault();
            const target = e.target.closest('.section');
            if (!target || !draggedSectionId) return;

            const targetId = target.dataset.sectionId;
            if (targetId === draggedSectionId) return;

            let order = config.settings.section_order || ['devices', 'links', 'quick_actions', 'tasks'];
            const fromIdx = order.indexOf(draggedSectionId);
            const toIdx = order.indexOf(targetId);

            if (fromIdx === -1 || toIdx === -1) return;

            order.splice(fromIdx, 1);
            order.splice(toIdx, 0, draggedSectionId);

            config.settings.section_order = order;
            saveConfig();
            renderSections();
        }

        function sectionDragEnd(e) {
            draggedSectionId = null;
            document.querySelectorAll('.section').forEach(el => {
                el.classList.remove('dragging', 'drag-over');
            });
        }

        // === Section Content Renderers ===

        function renderLinksContent() {
            return `<div class="cards-grid" id="cards-grid">
                ${config.links.map(link => `
                    <a href="${link.url}" target="_blank" class="card-item" data-id="${link.id}"
                       draggable="true" ondragstart="linkDragStart(event)" ondragover="linkDragOver(event)" ondragleave="linkDragLeave(event)" ondrop="linkDrop(event)" ondragend="linkDragEnd(event)">
                        ${getIcon(escapeHTML(link.icon || 'link'))}
                        <div class="card-text">
                            <span class="card-name">${escapeHTML(link.name)}</span>
                            ${link.note ? `<span class="card-note">${escapeHTML(link.note)}</span>` : ''}
                        </div>
                        <div class="link-edit" onclick="event.preventDefault(); editLink('${link.id}')">${ICON_EDIT}</div>
                        <div class="link-delete" onclick="event.preventDefault(); deleteLink('${link.id}')">${ICON_DELETE}</div>
                    </a>
                `).join('')}
            </div>`;
        }

        function renderActionsContent() {
            const actions = config.quick_actions || [];
            if (actions.length === 0) return '<div class="cards-grid" id="actions-grid"></div>';
            return `<div class="cards-grid" id="actions-grid">
                ${actions.map(qa => {
                    const exists = qa.exists !== false;
                    return `
                        <div class="card-item ${!exists ? 'missing' : ''}" data-id="${qa.id}"
                             draggable="true" ondragstart="qaDragStart(event)" ondragover="qaDragOver(event)" ondragleave="qaDragLeave(event)" ondrop="qaDrop(event)" ondragend="qaDragEnd(event)"
                             onclick="runQuickAction('${qa.id}')">
                            ${getIcon(escapeHTML(qa.icon || 'terminal'))}
                            <div class="card-text">
                                <span class="card-name">${escapeHTML(qa.name)}</span>
                                ${qa.note ? `<span class="card-note">${escapeHTML(qa.note)}</span>` : ''}
                            </div>
                            <div class="link-edit" onclick="event.stopPropagation(); editQuickAction('${qa.id}')">${ICON_EDIT}</div>
                            <div class="link-delete" onclick="event.stopPropagation(); deleteQuickAction('${qa.id}')">${ICON_DELETE}</div>
                        </div>
                    `;
                }).join('')}
            </div>`;
        }

        function renderDevicesContent() {
            return `<div id="devices-list">
                ${config.devices.map(dev => {
                const stats = deviceStats[dev.id] || {};
                const online = stats.online;
                const s = stats.stats || {};

                const isHost = dev.is_host;
                const containerStats = stats.containers || {};

                // Device actions (Wake, Shutdown, Connections)
                let actions = [];
                if (!isHost && !online && dev.wol?.mac) actions.push(`<button class="device-action" onclick="event.stopPropagation(); doWake('${dev.id}')">Wake</button>`);
                if (dev.connect?.rdp) actions.push(`<button class="device-action" onclick="event.stopPropagation(); doConnect('${dev.id}', 'rdp')" ${!online ? 'disabled' : ''}>RDP</button>`);
                if (dev.connect?.vnc) actions.push(`<button class="device-action" onclick="event.stopPropagation(); doConnect('${dev.id}', 'vnc')" ${!online ? 'disabled' : ''}>VNC</button>`);
                if (dev.connect?.web) actions.push(`<button class="device-action" onclick="event.stopPropagation(); doConnect('${dev.id}', 'web')" ${!online ? 'disabled' : ''}>Web</button>`);
                // Host can always shutdown/suspend, remote devices need SSH
                if (isHost || dev.ssh?.user) actions.push(`<button class="device-action" onclick="event.stopPropagation(); doSuspend('${dev.id}')" ${!online ? 'disabled' : ''}>Suspend</button>`);
                if (isHost || dev.ssh?.user) actions.push(`<button class="device-action danger" onclick="event.stopPropagation(); doShutdown('${dev.id}')" ${!online ? 'disabled' : ''}>Shutdown</button>`);

                // Docker containers section
                const containers = dev.docker?.containers || [];
                let containersToggle = '';
                let containersListHtml = '';
                if (containers.length > 0) {
                    // Count running vs stopped
                    let runningCount = 0;
                    let stoppedCount = 0;
                    containers.forEach(c => {
                        const cName = typeof c === 'string' ? c : c.name;
                        const cStatus = containerStats[cName];
                        if (cStatus === 'running') runningCount++;
                        else if (cStatus !== undefined) stoppedCount++;
                    });

                    // Check if expanded (default: true)
                    const isExpanded = config.settings?.accordion?.[dev.id] !== false;

                    // Toggle button for actions row
                    containersToggle = `
                        <span class="containers-toggle" onclick="event.stopPropagation(); toggleContainers('${dev.id}')">
                            <span class="containers-summary" style="${isExpanded ? 'display: none;' : ''}">
                                ${runningCount > 0 ? `<span>${runningCount}</span><span class="status-dot online"></span>` : ''}
                                ${stoppedCount > 0 ? `<span>${stoppedCount}</span><span class="status-dot offline"></span>` : ''}
                            </span>
                            <svg class="containers-chevron ${isExpanded ? 'expanded' : ''}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <polyline points="6 9 12 15 18 9"></polyline>
                            </svg>
                        </span>
                    `;

                    // Container list
                    containersListHtml = `
                        <div class="device-containers">
                            <div class="containers-list ${isExpanded ? 'expanded' : ''}">
                                ${containers.map(c => {
                                    const cName = typeof c === 'string' ? c : c.name;
                                    const cStatus = containerStats[cName];
                                    const cOnline = cStatus === 'running';
                                    const cLoading = cStatus === undefined;

                                    // Connection buttons only when container is running
                                    let connectBtns = '';
                                    if (cOnline) {
                                        if (c.rdp) connectBtns += `<button class="device-action" onclick="event.stopPropagation(); doContainerConnect('${dev.id}', 'rdp', '${c.rdp}')">RDP</button>`;
                                        if (c.vnc) connectBtns += `<button class="device-action" onclick="event.stopPropagation(); doContainerConnect('${dev.id}', 'vnc', '${c.vnc}')">VNC</button>`;
                                        if (c.web) connectBtns += `<button class="device-action" onclick="event.stopPropagation(); doContainerConnect('${dev.id}', 'web', '${c.web}')">Web</button>`;
                                    }

                                    // Single Start or Stop button based on state
                                    const actionBtn = cLoading ?
                                        `<span class="container-spinner active"></span>` :
                                        (cOnline ?
                                            `<button class="device-action container-stop" onclick="event.stopPropagation(); doDockerContainer('${dev.id}', '${cName}', 'stop')">Stop</button>` :
                                            `<button class="device-action container-start" onclick="event.stopPropagation(); doDockerContainer('${dev.id}', '${cName}', 'start')">Start</button>`
                                        );

                                    return `
                                        <div class="container-row">
                                            <span class="container-name ${cOnline ? 'container-online' : ''}">${cName}</span>
                                            <div class="container-actions">
                                                ${connectBtns ? `<span class="connect-group">${connectBtns}</span>` : ''}
                                                ${actionBtn}
                                                <span class="container-spinner" id="spinner-${dev.id}-${cName}"></span>
                                            </div>
                                        </div>
                                    `;
                                }).join('')}
                            </div>
                        </div>
                    `;
                }

                // RAM percentage for bar
                const ramPercent = s.ram_total ? Math.round(s.ram_used / s.ram_total * 100) : 0;

                return `
                <div class="device-card" data-id="${dev.id}" draggable="true" ondragstart="deviceDragStart(event)" ondragover="deviceDragOver(event)" ondragleave="deviceDragLeave(event)" ondrop="deviceDrop(event)" ondragend="deviceDragEnd(event)">
                    <div class="device-header">
                        <div class="device-info">
                            <div class="device-icon">${getIcon(escapeHTML(dev.icon || 'server'))}</div>
                            <span class="device-name">${escapeHTML(dev.name)}</span>
                            <span class="device-status-indicator">
                                <span class="status-dot ${online === undefined ? 'loading' : (online ? 'online' : 'offline')}"></span>
                                ${s.uptime ? `<span class="device-uptime">${s.uptime}</span>` : ''}
                            </span>
                        </div>
                    </div>
                    ${online && (s.cpu !== undefined) ? `
                        <div class="device-stats-bars${showValues ? ' show-values' : ''}" onclick="toggleStatsMode(this)">
                            <div class="stat-bar-group">
                                <span class="stat-label">CPU</span>
                                <div class="stat-bar"><div class="stat-bar-fill" style="width: ${s.cpu}%; background: ${getBarColor(s.cpu)}"></div></div>
                                <span class="stat-value">${s.cpu}%</span>
                            </div>
                            <div class="stat-bar-group">
                                <span class="stat-label">RAM</span>
                                <div class="stat-bar"><div class="stat-bar-fill" style="width: ${ramPercent}%; background: ${getBarColor(ramPercent)}"></div></div>
                                <span class="stat-value">${ramPercent}%</span>
                            </div>
                            ${s.temp ? `
                            <div class="stat-bar-group">
                                <span class="stat-label">TEMP</span>
                                <div class="stat-bar"><div class="stat-bar-fill" style="width: ${s.temp}%; background: ${getBarColor(s.temp)}"></div></div>
                                <span class="stat-value">${s.temp}°</span>
                            </div>
                            ` : ''}
                            <button class="stats-modal-btn" onclick="event.stopPropagation(); openStatsModal('${dev.id}')" title="Device Stats">
                                <i data-lucide="square-activity"></i>
                            </button>
                        </div>
                    ` : ''}
                    ${actions.length || containersToggle ? `
                        <div class="device-actions">
                            ${actions.join('<span class="action-separator">·</span>')}
                            ${containersToggle}
                        </div>
                    ` : ''}
                    ${containersListHtml}
                    <div class="device-edit" onclick="editDevice('${dev.id}')">${ICON_EDIT}</div>
                    ${!isHost ? `<div class="device-delete" onclick="deleteDevice('${dev.id}')">${ICON_DELETE}</div>` : ''}
                </div>
                `;
            }).join('')}
            </div>`;
        }

        function renderTasksContent() {
            const tasks = config.tasks || [];

            if (tasks.length === 0) {
                return `<div id="tasks-list"><div class="task-empty">No tasks configured. Click + to add one.</div></div>`;
            }

            return `<div id="tasks-list">
                ${tasks.map(task => {
                const isRunning = task._running || runningTasks.includes(task.id);
                const statusClass = isRunning ? 'running' :
                    !task.enabled ? 'paused' :
                    task.last_status === 'success' ? 'success' :
                    task.last_status === 'skipped' ? 'warning' :
                    task.last_status === 'failed' ? 'error' : 'success';

                const statusText = isRunning ? 'Running...' :
                    !task.enabled ? 'Paused' :
                    task.next_run ? `Next: ${formatTimeUntil(task.next_run)}` : 'Scheduled';

                const lastStatusText = task.last_status === 'skipped' ? `Skipped: ${task.last_error || 'source offline'}` :
                    task.last_status === 'failed' ? `Failed: ${task.last_error || 'unknown error'}` :
                    task.last_status === 'success' ? 'OK' : '';

                const scheduleText = formatSchedule(task.schedule);
                const typeIcon = task.type === 'backup' ? 'folder-sync' :
                                 task.type === 'shutdown' ? 'power-off' :
                                 task.type === 'suspend' ? 'moon' :
                                 task.type === 'script' ? 'terminal' : 'power';

                return `
                <div class="task-card ${isRunning ? 'running' : ''}" data-id="${task.id}" draggable="true" ondragstart="taskDragStart(event)" ondragover="taskDragOver(event)" ondragleave="taskDragLeave(event)" ondrop="taskDrop(event)" ondragend="taskDragEnd(event)">
                    <div class="task-header">
                        <div class="task-icon">${getIcon(typeIcon)}</div>
                        <span class="task-name">${escapeHTML(task.name)}</span>
                        <span class="task-schedule">${scheduleText}</span>
                    </div>
                    <div class="task-status">
                        <span class="task-status-dot ${statusClass}"></span>
                        <span>${statusText}</span>
                        ${task.last_run ? `<span style="margin-left: auto;">${lastStatusText}${lastStatusText ? ' · ' : ''}${formatLastRun(task.last_run)}${task.last_size ? ' · ' + task.last_size : ''}</span>` : ''}
                    </div>
                    <div class="task-actions">
                        <button class="task-btn" onclick="toggleTask('${task.id}')" ${isRunning ? 'disabled' : ''}>
                            ${task.enabled ? '<svg viewBox="0 0 24 24" width="12" height="12" fill="currentColor"><rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/></svg> Pause' : '<svg viewBox="0 0 24 24" width="12" height="12" fill="currentColor"><polygon points="5,3 19,12 5,21"/></svg> Resume'}
                        </button>
                        <button class="task-btn" onclick="runTaskNow('${task.id}')" ${isRunning ? 'disabled' : ''}>
                            ${isRunning ? 'Running...' : '<svg viewBox="0 0 24 24" width="12" height="12" fill="currentColor"><polygon points="5,3 19,12 5,21"/></svg> Run Now'}
                        </button>
                    </div>
                    <div class="task-edit" onclick="editTask('${task.id}')">${ICON_EDIT}</div>
                    <div class="task-delete" onclick="deleteTask('${task.id}')">${ICON_DELETE}</div>
                </div>
                `;
            }).join('')}
            </div>`;
        }

        // === Render Functions ===

        function toggleSection(section) {
            const key = `show_${section}`;
            const current = config.settings[key] !== false; // default true
            config.settings[key] = !current;
            renderSections();
            saveConfig();
        }

        function toggleMonochrome() {
            const current = config.settings.icons_mono || false;
            config.settings.icons_mono = !current;
            applyMonochrome();
            saveConfig();
        }

        function applyMonochrome() {
            const mono = config.settings.icons_mono || false;
            document.body.classList.toggle('icons-mono', mono);
            const btn = document.getElementById('mono-toggle');
            if (btn) {
                btn.innerHTML = mono ? '<i data-lucide="circle-off"></i>' : '<i data-lucide="palette"></i>';
                refreshIcons();
            }
        }

        // === Theme ===
        const defaultTheme = {
            bg: '#161616',
            cards: '#151515',
            border: '#2b2b2b',
            text: '#e0e0e0',
            textMuted: '#808080',
            accent: '#2ed573',
            glass: 0,
            blur: 0,
            wallpaper: ''
        };

        function initTheme() {
            const theme = config.settings.theme_colors || defaultTheme;

            // Set color inputs
            ['bg', 'cards', 'border', 'text', 'textMuted', 'accent'].forEach(key => {
                const id = key === 'textMuted' ? 'text-muted' : key;
                const colorInput = document.getElementById(`theme-${id}`);
                const hexInput = document.getElementById(`theme-${id}-hex`);
                const value = theme[key] || defaultTheme[key];
                if (colorInput) colorInput.value = value;
                if (hexInput) hexInput.value = value;
            });

            // Set sliders
            const glassSlider = document.getElementById('theme-glass');
            const blurSlider = document.getElementById('theme-blur');
            if (glassSlider) glassSlider.value = theme.glass || 0;
            if (blurSlider) blurSlider.value = theme.blur || 0;
            document.getElementById('theme-glass-value').textContent = (theme.glass || 0) + '%';
            document.getElementById('theme-blur-value').textContent = (theme.blur || 0) + 'px';

            // Set wallpaper
            const wallpaperInput = document.getElementById('theme-wallpaper');
            if (wallpaperInput) wallpaperInput.value = theme.wallpaper || '';

            // Apply theme
            applyTheme(theme);

            // Add event listeners
            setupThemeListeners();
        }

        function setupThemeListeners() {
            // Color inputs
            ['bg', 'cards', 'border', 'text', 'text-muted', 'accent'].forEach(id => {
                const colorInput = document.getElementById(`theme-${id}`);
                const hexInput = document.getElementById(`theme-${id}-hex`);

                if (colorInput) {
                    colorInput.addEventListener('input', (e) => {
                        hexInput.value = e.target.value;
                        updateThemeColor(id, e.target.value);
                    });
                }

                if (hexInput) {
                    hexInput.addEventListener('input', (e) => {
                        let val = e.target.value;
                        if (val.match(/^#[0-9a-fA-F]{6}$/)) {
                            colorInput.value = val;
                            updateThemeColor(id, val);
                        }
                    });
                }
            });

            // Sliders
            const glassSlider = document.getElementById('theme-glass');
            const blurSlider = document.getElementById('theme-blur');

            glassSlider?.addEventListener('input', (e) => {
                document.getElementById('theme-glass-value').textContent = e.target.value + '%';
                updateThemeEffect('glass', parseInt(e.target.value));
            });

            blurSlider?.addEventListener('input', (e) => {
                document.getElementById('theme-blur-value').textContent = e.target.value + 'px';
                updateThemeEffect('blur', parseInt(e.target.value));
            });

            // Wallpaper
            const wallpaperInput = document.getElementById('theme-wallpaper');
            wallpaperInput?.addEventListener('change', (e) => {
                updateThemeWallpaper(e.target.value);
            });
        }

        function updateThemeColor(id, value) {
            const key = id === 'text-muted' ? 'textMuted' : id;
            if (!config.settings.theme_colors) config.settings.theme_colors = {...defaultTheme};
            config.settings.theme_colors[key] = value;
            applyTheme(config.settings.theme_colors);
            saveConfig();
        }

        function updateThemeEffect(type, value) {
            if (!config.settings.theme_colors) config.settings.theme_colors = {...defaultTheme};
            config.settings.theme_colors[type] = value;
            applyTheme(config.settings.theme_colors);
            saveConfig();
        }

        function updateThemeWallpaper(url) {
            if (!config.settings.theme_colors) config.settings.theme_colors = {...defaultTheme};
            config.settings.theme_colors.wallpaper = url;
            applyTheme(config.settings.theme_colors);
            saveConfig();
        }

        function applyTheme(theme) {
            const root = document.documentElement;

            // Apply colors
            root.style.setProperty('--bg-primary', theme.bg || defaultTheme.bg);
            root.style.setProperty('--bg-secondary', theme.cards || defaultTheme.cards);
            root.style.setProperty('--bg-tertiary', adjustColor(theme.cards || defaultTheme.cards, 20));
            root.style.setProperty('--border', theme.border || defaultTheme.border);
            root.style.setProperty('--text-primary', theme.text || defaultTheme.text);
            root.style.setProperty('--text-secondary', theme.textMuted || defaultTheme.textMuted);
            root.style.setProperty('--accent', theme.accent || defaultTheme.accent);
            root.style.setProperty('--accent-muted', hexToRgba(theme.accent || defaultTheme.accent, 0.6));

            // Apply glass effect
            const glass = theme.glass || 0;
            const blur = theme.blur || 0;
            root.style.setProperty('--glass-opacity', glass / 100);
            root.style.setProperty('--glass-blur', blur + 'px');

            // Make cards semi-transparent when glass > 0
            if (glass > 0) {
                const cardsColor = theme.cards || defaultTheme.cards;
                root.style.setProperty('--bg-secondary', hexToRgba(cardsColor, 1 - glass / 100));
            }

            // Apply wallpaper (URL only)
            if (theme.wallpaper && (theme.wallpaper.startsWith('http://') || theme.wallpaper.startsWith('https://'))) {
                document.body.style.backgroundImage = `url(${theme.wallpaper})`;
                document.body.classList.add('has-wallpaper');
            } else {
                document.body.style.backgroundImage = '';
                document.body.classList.remove('has-wallpaper');
            }
        }

        function hexToRgba(hex, alpha) {
            const r = parseInt(hex.slice(1, 3), 16);
            const g = parseInt(hex.slice(3, 5), 16);
            const b = parseInt(hex.slice(5, 7), 16);
            return `rgba(${r}, ${g}, ${b}, ${alpha})`;
        }

        function adjustColor(hex, amount) {
            const r = Math.min(255, parseInt(hex.slice(1, 3), 16) + amount);
            const g = Math.min(255, parseInt(hex.slice(3, 5), 16) + amount);
            const b = Math.min(255, parseInt(hex.slice(5, 7), 16) + amount);
            return `#${r.toString(16).padStart(2, '0')}${g.toString(16).padStart(2, '0')}${b.toString(16).padStart(2, '0')}`;
        }

        function resetTheme() {
            config.settings.theme_colors = {...defaultTheme};
            initTheme();
            saveConfig();
        }

        function applySectionVisibility() {
            // Update section visibility classes without full re-render
            const isEditMode = document.body.classList.contains('edit-mode');
            const order = config.settings.section_order || ['devices', 'links', 'quick_actions', 'tasks'];

            order.forEach(id => {
                const section = document.getElementById(`${id}-section`);
                if (!section) return;

                const allSections = { ...CORE_SECTIONS, ...extensionSections };
                const sectionDef = allSections[id];
                if (!sectionDef) return;

                const isHidden = config.settings[sectionDef.toggleKey] === false;
                const isEmpty = isSectionEmpty(id);

                section.classList.toggle('section-hidden', isHidden);
                section.classList.toggle('section-empty', isEmpty && !isEditMode);
            });
        }

        function renderLinks() {
            const content = document.getElementById('links-content');
            if (content) {
                content.innerHTML = renderLinksContent();
                refreshIcons();
            }
        }

        let draggedLinkId = null;

        function linkDragStart(e) {
            if (!document.body.classList.contains('edit-mode')) {
                e.preventDefault();
                return;
            }
            draggedLinkId = e.target.closest('.card-item').dataset.id;
            e.target.closest('.card-item').classList.add('dragging');
            e.dataTransfer.effectAllowed = 'move';
        }

        function linkDragOver(e) {
            if (!draggedLinkId) return;
            e.preventDefault();
            const target = e.target.closest('.card-item');
            if (target && target.dataset.id !== draggedLinkId) {
                target.classList.add('drag-over');
            }
        }

        function linkDragLeave(e) {
            const target = e.target.closest('.card-item');
            if (target) target.classList.remove('drag-over');
        }

        function linkDrop(e) {
            e.preventDefault();
            const target = e.target.closest('.card-item');
            if (!target || !draggedLinkId) return;

            const targetId = target.dataset.id;
            if (targetId === draggedLinkId) return;

            // Reorder links
            const fromIdx = config.links.findIndex(l => l.id === draggedLinkId);
            const toIdx = config.links.findIndex(l => l.id === targetId);

            const [moved] = config.links.splice(fromIdx, 1);
            config.links.splice(toIdx, 0, moved);

            // Update order values
            config.links.forEach((l, i) => l.order = i);

            saveConfig();
            renderLinks();
        }

        function linkDragEnd(e) {
            draggedLinkId = null;
            document.querySelectorAll('.card-item').forEach(el => {
                el.classList.remove('dragging', 'drag-over');
            });
        }

        // === Quick Actions ===
        function renderQuickActions() {
            const content = document.getElementById('quick_actions-content');
            if (content) {
                content.innerHTML = renderActionsContent();
                refreshIcons();
            }
        }

        async function runQuickAction(id) {
            if (document.body.classList.contains('edit-mode')) return;
            const qa = config.quick_actions.find(q => q.id === id);
            if (!qa) return;
            try {
                const res = await api(`quick-action/${id}/run`);
                if (res.success) {
                    toast('Script started');
                } else {
                    toast(res.error || 'Failed to start script', 'error');
                }
            } catch (e) {
                toast('Failed to run script', 'error');
            }
        }

        function editQuickAction(id) {
            const qa = config.quick_actions.find(q => q.id === id);
            if (!qa) return;
            document.getElementById('qa-id').value = qa.id;
            document.getElementById('qa-name').value = qa.name;
            document.getElementById('qa-path').value = qa.path;
            document.getElementById('qa-icon').value = qa.icon || '';
            document.getElementById('qa-note').value = qa.note || '';
            document.getElementById('qa-modal-title').textContent = 'Edit Script';
            openModal('qa-modal');
        }

        function deleteQuickAction(id) {
            config.quick_actions = config.quick_actions.filter(q => q.id !== id);
            saveConfig();
            renderQuickActions();
            applySectionVisibility();
        }

        function saveQuickAction(e) {
            e.preventDefault();
            const id = document.getElementById('qa-id').value;
            const qa = config.quick_actions.find(q => q.id === id);
            if (!qa) return;
            qa.name = document.getElementById('qa-name').value;
            qa.icon = document.getElementById('qa-icon').value || 'terminal';
            qa.note = document.getElementById('qa-note').value;
            saveConfig();
            renderQuickActions();
            closeModal('qa-modal');
        }

        let draggedQaId = null;

        function qaDragStart(e) {
            if (!document.body.classList.contains('edit-mode')) {
                e.preventDefault();
                return;
            }
            draggedQaId = e.target.closest('.card-item').dataset.id;
            e.target.closest('.card-item').classList.add('dragging');
            e.dataTransfer.effectAllowed = 'move';
        }

        function qaDragOver(e) {
            if (!draggedQaId) return;
            e.preventDefault();
            const target = e.target.closest('.card-item');
            if (target && target.dataset.id !== draggedQaId) {
                target.classList.add('drag-over');
            }
        }

        function qaDragLeave(e) {
            const target = e.target.closest('.card-item');
            if (target) target.classList.remove('drag-over');
        }

        function qaDrop(e) {
            e.preventDefault();
            const target = e.target.closest('.card-item');
            if (!target || !draggedQaId) return;
            const targetId = target.dataset.id;
            if (targetId === draggedQaId) return;
            const fromIdx = config.quick_actions.findIndex(q => q.id === draggedQaId);
            const toIdx = config.quick_actions.findIndex(q => q.id === targetId);
            const [moved] = config.quick_actions.splice(fromIdx, 1);
            config.quick_actions.splice(toIdx, 0, moved);
            saveConfig();
            renderQuickActions();
        }

        function qaDragEnd(e) {
            draggedQaId = null;
            document.querySelectorAll('#actions-grid .card-item').forEach(el => {
                el.classList.remove('dragging', 'drag-over');
            });
        }

        async function scanQuickActions() {
            openModal('qa-scan-modal');
            document.getElementById('qa-scan-list').innerHTML = '<div style="text-align: center; padding: 20px;">Scanning...</div>';
            try {
                const res = await api('scripts/scan');
                const scripts = res.scripts || [];
                const existing = new Set((config.quick_actions || []).map(q => q.path));
                if (scripts.length === 0) {
                    document.getElementById('qa-scan-list').innerHTML = '<div style="padding: 20px; color: var(--text-secondary);">No executable scripts found in /opt/deq/scripts/</div>';
                    document.querySelector('#qa-scan-modal .btn:not(.btn-secondary)').style.display = 'none';
                    return;
                }
                document.querySelector('#qa-scan-modal .btn:not(.btn-secondary)').style.display = '';
                document.getElementById('qa-scan-list').innerHTML = scripts.map(s => {
                    const isNew = !existing.has(s.path);
                    return `
                    <div class="onboarding-row${isNew ? '' : ' disabled'}">
                        <input type="checkbox" ${isNew ? 'checked' : 'disabled'} data-path="${s.path}" data-name="${s.name}">
                        <span class="ob-ip">${s.path}</span>
                        <input type="text" class="ob-name" placeholder="Name" ${isNew ? '' : 'disabled'}>
                        <input type="text" class="ob-ssh" placeholder="Icon" ${isNew ? '' : 'disabled'}>
                    </div>`;
                }).join('');
            } catch (e) {
                document.getElementById('qa-scan-list').innerHTML = '<div style="padding: 20px; color: var(--text-secondary);">Failed to scan scripts</div>';
            }
        }

        function addScannedActions() {
            const rows = document.querySelectorAll('#qa-scan-list .onboarding-row:not(.disabled)');
            rows.forEach(row => {
                const checkbox = row.querySelector('input[type="checkbox"]');
                if (!checkbox.checked) return;
                const path = checkbox.dataset.path;
                const inputs = row.querySelectorAll('input[type="text"]');
                const name = inputs[0].value || checkbox.dataset.name.replace(/\.[^/.]+$/, '');
                const icon = inputs[1].value || 'terminal';
                config.quick_actions = config.quick_actions || [];
                config.quick_actions.push({
                    id: 'qa-' + Date.now() + '-' + Math.random().toString(36).substr(2, 5),
                    path: path,
                    name: name,
                    icon: icon,
                    note: ''
                });
            });
            saveConfig();
            renderQuickActions();
            applySectionVisibility();
            closeModal('qa-scan-modal');
        }

        // Device drag & drop
        let draggedDeviceId = null;

        function deviceDragStart(e) {
            if (!document.body.classList.contains('edit-mode')) {
                e.preventDefault();
                return;
            }
            draggedDeviceId = e.target.closest('.device-card').dataset.id;
            e.target.closest('.device-card').classList.add('dragging');
            e.dataTransfer.effectAllowed = 'move';
        }

        function deviceDragOver(e) {
            if (!draggedDeviceId) return;
            e.preventDefault();
            const target = e.target.closest('.device-card');
            if (target && target.dataset.id !== draggedDeviceId) {
                target.classList.add('drag-over');
            }
        }

        function deviceDragLeave(e) {
            const target = e.target.closest('.device-card');
            if (target) target.classList.remove('drag-over');
        }

        function deviceDrop(e) {
            e.preventDefault();
            const target = e.target.closest('.device-card');
            if (!target || !draggedDeviceId) return;

            const targetId = target.dataset.id;
            if (targetId === draggedDeviceId) return;

            // Reorder devices
            const fromIdx = config.devices.findIndex(d => d.id === draggedDeviceId);
            const toIdx = config.devices.findIndex(d => d.id === targetId);

            const [moved] = config.devices.splice(fromIdx, 1);
            config.devices.splice(toIdx, 0, moved);

            // Update order values
            config.devices.forEach((d, i) => d.order = i);

            saveConfig();
            renderDevices();
        }

        function deviceDragEnd(e) {
            draggedDeviceId = null;
            document.querySelectorAll('.device-card').forEach(el => {
                el.classList.remove('dragging', 'drag-over');
            });
        }

        // Task drag & drop
        let draggedTaskId = null;

        function taskDragStart(e) {
            if (!document.body.classList.contains('edit-mode')) {
                e.preventDefault();
                return;
            }
            draggedTaskId = e.target.closest('.task-card').dataset.id;
            e.target.closest('.task-card').classList.add('dragging');
            e.dataTransfer.effectAllowed = 'move';
        }

        function taskDragOver(e) {
            if (!draggedTaskId) return;
            e.preventDefault();
            const target = e.target.closest('.task-card');
            if (target && target.dataset.id !== draggedTaskId) {
                target.classList.add('drag-over');
            }
        }

        function taskDragLeave(e) {
            const target = e.target.closest('.task-card');
            if (target) target.classList.remove('drag-over');
        }

        function taskDrop(e) {
            e.preventDefault();
            const target = e.target.closest('.task-card');
            if (!target || !draggedTaskId) return;

            const targetId = target.dataset.id;
            if (targetId === draggedTaskId) return;

            const tasks = config.tasks || [];
            const fromIdx = tasks.findIndex(t => t.id === draggedTaskId);
            const toIdx = tasks.findIndex(t => t.id === targetId);

            const [moved] = tasks.splice(fromIdx, 1);
            tasks.splice(toIdx, 0, moved);

            saveConfig();
            renderTasks();
        }

        function taskDragEnd(e) {
            draggedTaskId = null;
            document.querySelectorAll('.task-card').forEach(el => {
                el.classList.remove('dragging', 'drag-over');
            });
        }

        function editLink(id) {
            const link = config.links.find(l => l.id === id);
            if (link) openLinkModal(link);
        }

        function renderDevices() {
            const content = document.getElementById('devices-content');
            if (content) {
                content.innerHTML = renderDevicesContent();
                refreshIcons();
            }
        }

        // === Container Accordion ===
        async function toggleContainers(deviceId) {
            // Toggle accordion state
            if (!config.settings.accordion) config.settings.accordion = {};
            const currentState = config.settings.accordion[deviceId] !== false;
            config.settings.accordion[deviceId] = !currentState;

            // Update UI
            const card = document.querySelector(`.device-card[data-id="${deviceId}"]`);
            if (card) {
                const summary = card.querySelector('.containers-summary');
                const chevron = card.querySelector('.containers-chevron');
                const list = card.querySelector('.containers-list');

                if (config.settings.accordion[deviceId]) {
                    // Expanding
                    summary.style.display = 'none';
                    chevron.classList.add('expanded');
                    list.classList.add('expanded');
                } else {
                    // Collapsing
                    summary.style.display = '';
                    chevron.classList.remove('expanded');
                    list.classList.remove('expanded');
                }
            }

            // Save to config
            await api('config', 'POST', config);
        }

        // === Actions ===
        async function doWake(id) {
            const res = await api(`device/${id}/wake`);
            if (res.success) {
                toast('Magic packet sent');
                setTimeout(loadDeviceStatus, 3000);
                setTimeout(loadDeviceStatus, 8000);
            } else {
                toast(res.error || 'Failed', 'error');
            }
        }
        
        async function doDockerContainer(deviceId, container, action) {
            if (action === 'stop' && !confirm(`Stop container "${container}"?`)) return;

            const spinner = document.getElementById(`spinner-${deviceId}-${container}`);
            if (spinner) spinner.classList.add('active');

            const targetState = action === 'start' ? 'running' : 'exited';
            const res = await api(`device/${deviceId}/docker/${container}/${action}`);
            if (res.success) {
                toast(`Container ${action}ed`);
                // Poll until status changes
                let attempts = 0;
                const checkStatus = async () => {
                    const status = await api(`device/${deviceId}/status`);
                    const containerStatus = status.containers?.[container];
                    attempts++;
                    if (containerStatus === targetState || containerStatus === 'running' && action === 'start' || attempts >= 15) {
                        await loadDeviceStatus();
                        const newSpinner = document.getElementById(`spinner-${deviceId}-${container}`);
                        if (newSpinner) newSpinner.classList.remove('active');
                    } else {
                        setTimeout(checkStatus, 1000);
                    }
                };
                setTimeout(checkStatus, 1000);
            } else {
                if (spinner) spinner.classList.remove('active');
                toast(res.error || 'Failed', 'error');
            }
        }
        
        async function doShutdown(id) {
            const dev = config.devices.find(d => d.id === id);
            const isHost = dev?.is_host;
            const msg = isHost ? 'This will SHUTDOWN the host server running DeQ. Continue?' : 'Shutdown this device?';
            if (!confirm(msg)) return;
            const res = await api(`device/${id}/shutdown`);
            if (res.success) {
                toast('Shutdown command sent');
                setTimeout(loadDeviceStatus, 5000);
            } else {
                toast(res.error || 'Failed', 'error');
            }
        }

        async function doSuspend(id) {
            const dev = config.devices.find(d => d.id === id);
            const isHost = dev?.is_host;
            const msg = isHost ? 'This will SUSPEND the host server running DeQ. Continue?' : 'Suspend this device?';
            if (!confirm(msg)) return;
            const res = await api(`device/${id}/suspend`);
            if (res.success) {
                toast(res.warning || 'Suspend command sent');
                setTimeout(loadDeviceStatus, 5000);
            } else {
                let msg = res.error || 'Failed';
                if (res.available) msg += ` (available: ${res.available})`;
                toast(msg, 'error');
            }
        }
        
        function connectRDP(addr) {
            if (currentPlatform === 'ios' || currentPlatform === 'mac' || currentPlatform === 'windows' || currentPlatform === 'android') {
                // ms-rd: works for Microsoft Remote Desktop app on all platforms
                window.location.href = `ms-rd:full%20address=s:${addr}`;
            } else {
                // Linux - show command in prompt
                const cmd = `xfreerdp /v:${addr} /u:USER /p:PASSWORD /f`;
                prompt('RDP Command (copy and run in terminal):', cmd);
            }
        }

        function connectVNC(addr, port) {
            const webPorts = [8006, 6080, 6081, 5800, 5801];
            const p = parseInt(port);
            if (webPorts.includes(p)) {
                window.open(`http://${addr}`, '_blank');
            } else if (currentPlatform === 'mac') {
                window.location.href = `vnc://${addr}`;
            } else if (currentPlatform === 'ios') {
                window.location.href = `vnc://${addr}`;
            } else if (currentPlatform === 'windows') {
                prompt('VNC Address (use your VNC client):', addr);
            } else {
                // Linux/Android
                window.open(`vnc://${addr}`, '_blank');
            }
        }

        function doConnect(id, type) {
            const dev = config.devices.find(d => d.id === id);
            if (!dev) return;

            if (type === 'rdp') {
                const addr = dev.connect.rdp.includes(':') ? dev.connect.rdp : `${dev.ip}:${dev.connect.rdp}`;
                connectRDP(addr);
            } else if (type === 'vnc') {
                const port = dev.connect.vnc;
                const addr = port.includes(':') ? port : `${dev.ip}:${port}`;
                connectVNC(addr, port);
            } else if (type === 'web') {
                window.open(dev.connect.web, '_blank');
            }
        }

        function doContainerConnect(devId, type, value) {
            const dev = config.devices.find(d => d.id === devId);
            if (!dev) return;

            if (type === 'rdp') {
                const addr = value.includes(':') ? value : `${dev.ip}:${value}`;
                connectRDP(addr);
            } else if (type === 'vnc') {
                const addr = value.includes(':') ? value : `${dev.ip}:${value}`;
                connectVNC(addr, value);
            } else if (type === 'web') {
                window.open(value, '_blank');
            }
        }
        
        // === CRUD ===
        async function saveConfig() {
            await api('config', 'POST', config);
        }

        async function logout() {
            await fetch('/auth/logout', {method: 'POST'});
            window.location.reload();
        }

        async function saveLink(e) {
            e.preventDefault();
            const id = document.getElementById('link-id').value || generateUUID();
            const note = document.getElementById('card-note').value.trim();
            const link = {
                id,
                name: document.getElementById('card-name').value,
                url: document.getElementById('link-url').value,
                icon: document.getElementById('link-icon').value || 'link',
                order: config.links.length
            };
            if (note) link.note = note;

            const idx = config.links.findIndex(l => l.id === id);
            if (idx >= 0) config.links[idx] = link;
            else config.links.push(link);
            
            await api('config', 'POST', config);
            closeModal('link-modal');
            renderLinks();
            applySectionVisibility();
            toast('Link saved');
        }

        async function deleteLink(id) {
            if (!confirm('Delete this link?')) return;
            config.links = config.links.filter(l => l.id !== id);
            await api('config', 'POST', config);
            renderLinks();
            applySectionVisibility();
            toast('Link deleted');
        }
        
        async function saveDevice(e) {
            e.preventDefault();
            const id = document.getElementById('device-id').value || generateUUID();
            const existingDevice = config.devices.find(d => d.id === id);

            const device = {
                id,
                name: document.getElementById('device-name').value,
                ip: document.getElementById('device-ip').value,
                icon: document.getElementById('device-icon').value || 'server'
            };

            // Preserve is_host flag
            if (existingDevice?.is_host) {
                device.is_host = true;
            }
            
            // WOL
            const mac = document.getElementById('device-mac').value;
            if (mac) {
                device.wol = {
                    mac,
                    broadcast: document.getElementById('device-broadcast').value || '255.255.255.255'
                };
            }
            
            // Docker containers
            const containers = getContainersFromForm();
            if (containers.length) device.docker = { containers };

            // Device-level connections
            const rdp = document.getElementById('device-rdp').value.trim();
            const vnc = document.getElementById('device-vnc').value.trim();
            const web = document.getElementById('device-web').value.trim();
            if (rdp || vnc || web) {
                device.connect = {};
                if (rdp) device.connect.rdp = rdp;
                if (vnc) device.connect.vnc = vnc;
                if (web) device.connect.web = web;
            }
            
            // SSH
            const sshUser = document.getElementById('device-ssh-user').value;
            if (sshUser) {
                device.ssh = {
                    user: sshUser,
                    port: parseInt(document.getElementById('device-ssh-port').value) || 22
                };
            }

            const idx = config.devices.findIndex(d => d.id === id);
            if (idx >= 0) config.devices[idx] = device;
            else config.devices.push(device);
            
            await api('config', 'POST', config);
            closeModal('device-modal');
            renderDevices();
            loadDeviceStatus();
            toast('Device saved');
        }
        
        async function deleteDevice(id) {
            if (!confirm('Delete this device?')) return;
            config.devices = config.devices.filter(d => d.id !== id);
            await api('config', 'POST', config);
            renderDevices();
            toast('Device deleted');
        }
        
        function openLinkModal(link = null) {
            document.getElementById('link-modal-title').textContent = link ? 'Edit Link' : 'Add Link';
            document.getElementById('link-id').value = link?.id || '';
            document.getElementById('card-name').value = link?.name || '';
            document.getElementById('link-url').value = link?.url || '';
            document.getElementById('link-icon').value = link?.icon || '';
            document.getElementById('card-note').value = link?.note || '';
            openModal('link-modal');
        }
        
        function addContainerRow(container = null) {
            const list = document.getElementById('device-containers-list');
            const row = document.createElement('div');
            row.className = 'container-form-row';
            const name = typeof container === 'string' ? container : (container?.name || '');
            const rdp = typeof container === 'object' ? (container?.rdp || '') : '';
            const vnc = typeof container === 'object' ? (container?.vnc || '') : '';
            const web = typeof container === 'object' ? (container?.web || '') : '';
            row.innerHTML = `
                <input type="text" class="form-input container-name" placeholder="Name" value="${name}">
                <input type="text" class="form-input container-rdp" placeholder="RDP" value="${rdp}" style="max-width: 100px;">
                <input type="text" class="form-input container-vnc" placeholder="VNC" value="${vnc}" style="max-width: 100px;">
                <input type="text" class="form-input container-web" placeholder="Web URL" value="${web}">
                <button type="button" class="remove-btn" onclick="this.parentElement.remove()">×</button>
            `;
            list.appendChild(row);
        }

        async function scanContainers() {
            const deviceId = document.getElementById('device-id').value;

            if (!deviceId) {
                toast('Save the device first, then scan for containers', 'error');
                return;
            }

            const btn = document.getElementById('scan-containers-btn');
            btn.disabled = true;

            try {
                const res = await api(`device/${deviceId}/scan-containers`);

                if (!res.success) {
                    toast(res.error || 'Scan failed', 'error');
                    return;
                }

                if (!res.containers || res.containers.length === 0) {
                    toast('No containers found');
                    return;
                }

                const existingNames = new Set();
                document.querySelectorAll('.container-form-row .container-name').forEach(input => {
                    if (input.value.trim()) {
                        existingNames.add(input.value.trim());
                    }
                });

                let added = 0;
                for (const name of res.containers) {
                    if (!existingNames.has(name)) {
                        addContainerRow({ name });
                        added++;
                    }
                }

                if (added > 0) {
                    toast(`Added ${added} container(s)`);
                } else {
                    toast('All containers already configured');
                }

            } catch (e) {
                toast('Scan failed', 'error');
            } finally {
                btn.disabled = false;
            }
        }

        function getContainersFromForm() {
            const rows = document.querySelectorAll('.container-form-row');
            const containers = [];
            rows.forEach(row => {
                const name = row.querySelector('.container-name').value.trim();
                if (name) {
                    const c = { name };
                    const rdp = row.querySelector('.container-rdp').value.trim();
                    const vnc = row.querySelector('.container-vnc').value.trim();
                    const web = row.querySelector('.container-web').value.trim();
                    if (rdp) c.rdp = rdp;
                    if (vnc) c.vnc = vnc;
                    if (web) c.web = web;
                    containers.push(c);
                }
            });
            return containers;
        }

        function openDeviceModal(device = null) {
            const isHost = device?.is_host;
            document.getElementById('device-modal-title').textContent = device ? 'Edit Device' : 'Add Device';
            document.getElementById('device-id').value = device?.id || '';
            document.getElementById('device-name').value = device?.name || '';
            document.getElementById('device-ip').value = device?.ip || '';
            document.getElementById('device-icon').value = device?.icon || '';
            document.getElementById('device-mac').value = device?.wol?.mac || '';
            document.getElementById('device-broadcast').value = device?.wol?.broadcast || '';
            document.getElementById('device-rdp').value = device?.connect?.rdp || '';
            document.getElementById('device-vnc').value = device?.connect?.vnc || '';
            document.getElementById('device-web').value = device?.connect?.web || '';
            document.getElementById('device-ssh-user').value = device?.ssh?.user || '';
            document.getElementById('device-ssh-port').value = device?.ssh?.port || '';

            // Load containers
            const containersList = document.getElementById('device-containers-list');
            containersList.innerHTML = '';
            (device?.docker?.containers || []).forEach(c => addContainerRow(c));

            // Hide WOL and SSH sections for host device (not needed)
            document.getElementById('section-wol').style.display = isHost ? 'none' : 'block';
            document.getElementById('section-ssh').style.display = isHost ? 'none' : 'block';

            // Hide help accordion by default
            document.getElementById('device-help').classList.remove('visible');

            openModal('device-modal');
            refreshIcons();
        }

        function editDevice(id) {
            const device = config.devices.find(d => d.id === id);
            if (device) openDeviceModal(device);
        }

        // === Stats Modal ===
        let currentStatsDeviceId = null;

        async function openStatsModal(deviceId) {
            currentStatsDeviceId = deviceId;
            const device = config.devices.find(d => d.id === deviceId);
            if (!device) return;

            document.getElementById('stats-modal-title').textContent = device.name;
            document.getElementById('stats-loading').style.display = 'block';
            document.getElementById('stats-data').style.display = 'none';
            openModal('stats-modal');

            const res = await api(`device/${deviceId}/stats`);
            if (res.success) {
                renderStatsModal(device, res.stats, res.online);
            }
        }

        function renderStatsModal(device, stats, isOnline) {
            const alerts = device.alerts || {};

            // Hardware section
            const hwBody = document.getElementById('stats-hardware');
            const ramPercent = stats.ram_total ? Math.round(stats.ram_used / stats.ram_total * 100) : 0;
            hwBody.innerHTML = `
                <tr>
                    <td>Online</td>
                    <td><span class="status-dot ${isOnline ? 'online' : 'offline'}"></span> ${isOnline ? 'Online' : 'Offline'}</td>
                    <td><input type="checkbox" data-alert="online" ${alerts.online !== false ? 'checked' : ''}></td>
                    <td><span style="color: var(--text-secondary); font-size: 11px;">On Change</span></td>
                </tr>
                <tr>
                    <td>CPU Load</td>
                    <td>${stats.cpu || 0}%</td>
                    <td><input type="checkbox" data-alert="cpu" ${alerts.cpu ? 'checked' : ''}></td>
                    <td><input type="number" data-threshold="cpu" value="${alerts.cpu || ''}" placeholder="%" min="1" max="100"></td>
                </tr>
                <tr>
                    <td>CPU Temp</td>
                    <td>${stats.temp ? stats.temp + '°C' : '-'}</td>
                    <td><input type="checkbox" data-alert="cpu_temp" ${alerts.cpu_temp ? 'checked' : ''}></td>
                    <td><input type="number" data-threshold="cpu_temp" value="${alerts.cpu_temp || ''}" placeholder="°C" min="1" max="120"></td>
                </tr>
                <tr>
                    <td>RAM Usage</td>
                    <td>${ramPercent}%</td>
                    <td><input type="checkbox" data-alert="ram" ${alerts.ram ? 'checked' : ''}></td>
                    <td><input type="number" data-threshold="ram" value="${alerts.ram || ''}" placeholder="%" min="1" max="100"></td>
                </tr>
            `;

            // Mounts section
            const mountsBody = document.getElementById('stats-mounts');
            const mountsSection = document.getElementById('stats-mounts-section');
            const diskAlerts = alerts.disks || {};

            if (stats.disks && stats.disks.length > 0) {
                mountsSection.style.display = 'block';
                mountsBody.innerHTML = stats.disks.map(disk => {
                    const usage = Math.round(disk.used / disk.total * 100);
                    const mountAlerts = diskAlerts[disk.mount] || {};
                    const usageThreshold = mountAlerts.usage ?? alerts.disk_usage ?? '';
                    const shortMount = disk.mount.length > 20 ? '...' + disk.mount.slice(-17) : disk.mount;
                    return `
                        <tr>
                            <td title="${disk.mount}">${shortMount}</td>
                            <td>${usage}%</td>
                            <td><input type="checkbox" data-alert="disk_usage_${disk.mount}" ${usageThreshold ? 'checked' : ''}></td>
                            <td><input type="number" data-threshold="disk_usage_${disk.mount}" value="${usageThreshold}" placeholder="%" min="1" max="100"></td>
                        </tr>
                    `;
                }).join('');
            } else {
                mountsSection.style.display = 'none';
            }

            // Disks section (physical disks with SMART)
            const disksBody = document.getElementById('stats-disks');
            const disksSection = document.getElementById('stats-disks-section');
            const diskSmart = stats.disk_smart || {};
            let diskRows = '';

            Object.entries(diskSmart).forEach(([devName, smart]) => {
                if (!smart.temp && !smart.smart) return;
                const devAlerts = diskAlerts[devName] || {};
                const hasTemp = smart.temp !== null && smart.temp !== undefined;
                const hasSmart = smart.smart;
                const tempThreshold = devAlerts.temp ?? alerts.disk_temp ?? '';

                diskRows += `<tr>
                    <td>/dev/${devName}</td>
                    <td>Temp</td>
                    <td>${hasTemp ? smart.temp + '°C' : '-'}</td>
                    <td>${hasTemp ? `<input type="checkbox" data-alert="disk_temp_${devName}" ${tempThreshold ? 'checked' : ''}>` : ''}</td>
                    <td>${hasTemp ? `<input type="number" data-threshold="disk_temp_${devName}" value="${tempThreshold}" placeholder="°C" min="1" max="80" style="width:50px">` : ''}</td>
                </tr>
                <tr>
                    <td></td>
                    <td>SMART</td>
                    <td>${hasSmart ? `<span class="${smart.smart === 'ok' ? 'ok' : 'error'}">${smart.smart.toUpperCase()}</span>` : '-'}</td>
                    <td>${hasSmart ? `<input type="checkbox" data-alert="disk_smart_${devName}" ${devAlerts.smart !== false ? 'checked' : ''}>` : ''}</td>
                    <td>${hasSmart ? `<span style="color: var(--text-secondary); font-size: 11px;">On Fail</span>` : ''}</td>
                </tr>`;
            });

            if (diskRows) {
                disksSection.style.display = 'block';
                disksBody.innerHTML = diskRows;
            } else {
                disksSection.style.display = 'none';
            }

            // Containers section
            const containersBody = document.getElementById('stats-containers');
            const containersSection = document.getElementById('stats-containers-section');
            const cached = deviceStats[device.id];
            const containerStatuses = cached?.containers || {};
            const containerStats = stats.container_stats || {};
            const containers = device.docker?.containers || [];

            if (containers.length > 0) {
                containersSection.style.display = 'block';
                containersBody.innerHTML = containers.map(c => {
                    const name = typeof c === 'string' ? c : c.name;
                    const status = containerStatuses[name] || 'unknown';
                    const isRunning = status === 'running';
                    const cStats = containerStats[name];
                    const containerAlerts = alerts.containers?.[name];

                    let statsHtml = '';
                    if (cStats && isRunning) {
                        statsHtml = `<span class="container-stats-inline">${cStats.cpu.toFixed(1)}% CPU · ${cStats.mem.toFixed(1)}% RAM</span>`;
                    }

                    return `
                        <tr>
                            <td>${name}</td>
                            <td><span class="status-dot ${isRunning ? 'online' : 'offline'}"></span> ${status}${statsHtml}</td>
                            <td><input type="checkbox" data-alert="container_${name}" ${containerAlerts !== false ? 'checked' : ''}></td>
                        </tr>
                    `;
                }).join('');
            } else {
                containersSection.style.display = 'none';
            }

            document.getElementById('stats-loading').style.display = 'none';
            document.getElementById('stats-data').style.display = 'block';
        }

        async function saveStatsConfig() {
            const device = config.devices.find(d => d.id === currentStatsDeviceId);
            if (!device) return;

            // Validate: alert enabled but no threshold
            const errors = [];
            document.querySelectorAll('[data-alert]').forEach(checkbox => {
                if (!checkbox.checked) return;
                const key = checkbox.dataset.alert;
                if (key === 'online' || key.startsWith('disk_smart_') || key.startsWith('container_')) return;
                const input = document.querySelector(`[data-threshold="${key}"]`);
                if (input && !input.value) {
                    errors.push(key.replace(/_/g, ' ').replace('disk usage ', '').replace('disk temp ', ''));
                }
            });
            if (errors.length > 0) {
                toast('Missing threshold for: ' + errors.join(', '), 'error');
                return;
            }

            const alerts = {
                online: document.querySelector('[data-alert="online"]')?.checked ?? true,
                cpu: getThresholdValue('cpu'),
                cpu_temp: getThresholdValue('cpu_temp'),
                ram: getThresholdValue('ram'),
                disks: {},
                containers: {}
            };

            // Collect disk usage thresholds (by mount)
            document.querySelectorAll('[data-threshold^="disk_usage_"]').forEach(input => {
                const mount = input.dataset.threshold.replace('disk_usage_', '');
                const checkbox = document.querySelector(`[data-alert="disk_usage_${mount}"]`);
                if (!alerts.disks[mount]) alerts.disks[mount] = {};
                if (checkbox?.checked && input.value) {
                    alerts.disks[mount].usage = parseInt(input.value);
                }
            });

            // Collect disk temp thresholds (by device)
            document.querySelectorAll('[data-threshold^="disk_temp_"]').forEach(input => {
                const dev = input.dataset.threshold.replace('disk_temp_', '');
                const checkbox = document.querySelector(`[data-alert="disk_temp_${dev}"]`);
                if (!alerts.disks[dev]) alerts.disks[dev] = {};
                if (checkbox?.checked && input.value) {
                    alerts.disks[dev].temp = parseInt(input.value);
                }
            });

            // Collect disk SMART alerts (by device)
            document.querySelectorAll('[data-alert^="disk_smart_"]').forEach(checkbox => {
                const dev = checkbox.dataset.alert.replace('disk_smart_', '');
                if (!alerts.disks[dev]) alerts.disks[dev] = {};
                alerts.disks[dev].smart = checkbox.checked;
            });

            // Collect container alerts
            document.querySelectorAll('[data-alert^="container_"]').forEach(checkbox => {
                const name = checkbox.dataset.alert.replace('container_', '');
                alerts.containers[name] = checkbox.checked;
            });

            device.alerts = alerts;
            await api('config', 'POST', { config });
            closeModal('stats-modal');
            toast('Alert settings saved');
        }

        function getThresholdValue(key) {
            const checkbox = document.querySelector(`[data-alert="${key}"]`);
            const input = document.querySelector(`[data-threshold="${key}"]`);
            if (checkbox?.checked && input?.value) {
                return parseInt(input.value);
            }
            return null;
        }

        // === Tasks ===
        let wizardStep = 1;

        function renderTasks() {
            const content = document.getElementById('tasks-content');
            if (content) {
                content.innerHTML = renderTasksContent();
                refreshIcons();
            }
        }

        function formatSchedule(schedule) {
            if (!schedule) return '';
            if (schedule.type === 'hourly') return 'Hourly';
            if (schedule.type === 'daily') return `Daily ${schedule.time}`;
            if (schedule.type === 'weekly') {
                const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
                return `${days[schedule.day]} ${schedule.time}`;
            }
            if (schedule.type === 'monthly') return `Monthly ${schedule.date}${getOrdinal(schedule.date)} ${schedule.time}`;
            return '';
        }

        function getOrdinal(n) {
            const s = ['th', 'st', 'nd', 'rd'];
            const v = n % 100;
            return s[(v - 20) % 10] || s[v] || s[0];
        }

        function formatTimeUntil(isoDate) {
            const diff = new Date(isoDate) - new Date();
            if (diff < 0) return 'now';
            const hours = Math.floor(diff / 3600000);
            const mins = Math.floor((diff % 3600000) / 60000);
            if (hours > 24) return `${Math.floor(hours / 24)}d ${hours % 24}h`;
            if (hours > 0) return `${hours}h ${mins}m`;
            return `${mins}m`;
        }

        function formatLastRun(isoDate) {
            const date = new Date(isoDate);
            const now = new Date();
            const time = date.toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' });

            const dateDay = new Date(date.getFullYear(), date.getMonth(), date.getDate());
            const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
            const diffDays = Math.round((today - dateDay) / (1000 * 60 * 60 * 24));

            if (diffDays === 0) return time;
            if (diffDays === 1) return `Yesterday ${time}`;
            return date.toLocaleDateString('de-DE', { day: '2-digit', month: '2-digit' }) + ' ' + time;
        }

        function openTaskWizard(taskId = null) {
            wizardStep = 1;
            document.querySelectorAll('.wizard-step').forEach((el, i) => {
                el.style.display = i === 0 ? 'block' : 'none';
            });

            // Populate device dropdowns (devices with SSH or host)
            const sshDevices = config.devices.filter(d => d.ssh?.user || d.is_host);
            const sshDeviceOptions = sshDevices.map(d => `<option value="${d.id}">${d.name}</option>`).join('');
            document.getElementById('task-source-device').innerHTML = sshDeviceOptions;
            document.getElementById('task-dest-device').innerHTML = sshDeviceOptions;

            // Populate target device dropdown (devices with WOL for wake, SSH for shutdown)
            document.getElementById('task-target-device').innerHTML = sshDeviceOptions;

            // Populate container dropdown (all containers from all devices)
            const containers = [];
            config.devices.forEach(dev => {
                (dev.docker?.containers || []).forEach(c => {
                    const name = typeof c === 'string' ? c : c.name;
                    if (name) containers.push({ name, device: dev.name, deviceId: dev.id });
                });
            });
            const containerOptions = containers.map(c =>
                `<option value="${c.deviceId}:${c.name}">${c.name} (${c.device})</option>`
            ).join('');
            document.getElementById('task-target-container').innerHTML = containerOptions || '<option value="">No containers configured</option>';

            // Reset form
            document.getElementById('task-id').value = taskId || '';
            document.getElementById('task-name').value = '';
            document.getElementById('task-source-path').value = '';
            document.getElementById('task-dest-path').value = '';
            document.getElementById('task-delete-files').checked = false;
            document.querySelector('input[name="task-action"][value="wake"]').checked = true;
            document.querySelector('input[name="task-target"][value="device"]').checked = true;

            // Reset folder browsers
            browserState.source = { path: '/', folders: [], selected: null, filter: '' };
            browserState.dest = { path: '/', folders: [], selected: null, filter: '' };
            document.getElementById('source-list').innerHTML = '';
            document.getElementById('dest-list').innerHTML = '';
            document.getElementById('source-selected').textContent = '/';
            document.getElementById('dest-selected').textContent = '/';
            document.getElementById('source-filter').value = '';
            document.getElementById('dest-filter').value = '';

            document.getElementById('task-modal-title').textContent = taskId ? 'Edit Task' : 'New Task';
            openModal('task-modal');
            refreshIcons();
        }

        function getWizardAction() {
            return document.querySelector('input[name="task-action"]:checked').value;
        }

        function getWizardTarget() {
            return document.querySelector('input[name="task-target"]:checked').value;
        }

        // === FOLDER BROWSER ===
        const browserState = {
            source: { path: '/', folders: [], selected: null, filter: '' },
            dest: { path: '/', folders: [], selected: null, filter: '' }
        };

        async function browseFolder(type, path = '/') {
            const deviceSelect = document.getElementById(`task-${type}-device`);
            const deviceId = deviceSelect.value;
            if (!deviceId) return;

            const listEl = document.getElementById(`${type}-list`);
            const selectedEl = document.getElementById(`${type}-selected`);
            const filterEl = document.getElementById(`${type}-filter`);

            // Check if we navigated INTO this folder (has trailing slash)
            const insidePath = browserState[type].insidePath;
            browserState[type].insidePath = null; // Clear it

            // Show loading
            listEl.innerHTML = '<div class="folder-browser-loading">Loading...</div>';
            filterEl.value = '';
            browserState[type].filter = '';
            browserState[type].selected = null;

            // Set path display - show selected path or current browsing path
            if (insidePath) {
                selectedEl.textContent = `Contents: ${insidePath}`;
                document.getElementById(`task-${type}-path`).value = insidePath;
            } else {
                selectedEl.textContent = path;
                document.getElementById(`task-${type}-path`).value = '';
            }

            try {
                const res = await api(`device/${deviceId}/browse?path=${encodeURIComponent(path)}`);
                if (res.success) {
                    browserState[type].path = res.path;
                    browserState[type].folders = res.folders;
                    renderFolderList(type);
                } else {
                    listEl.innerHTML = `<div class="folder-browser-error">${res.error}</div>`;
                }
            } catch (e) {
                listEl.innerHTML = `<div class="folder-browser-error">Failed to load</div>`;
            }
        }

        function renderFolderList(type) {
            const state = browserState[type];
            const listEl = document.getElementById(`${type}-list`);
            const filter = state.filter.toLowerCase();

            // Filter folders
            const filtered = state.folders.filter(f => f.toLowerCase().includes(filter));

            // Build HTML
            let html = '';

            // Parent folder (..)
            if (state.path !== '/') {
                html += `<div class="folder-item" ondblclick="navigateUp('${type}')">
                    <svg class="folder-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M15 18l-6-6 6-6"/>
                    </svg>
                    <span class="folder-name">..</span>
                </div>`;
            }

            // Folders
            filtered.forEach(folder => {
                const isSelected = state.selected === folder;
                html += `<div class="folder-item${isSelected ? ' selected' : ''}"
                    onclick="selectFolder('${type}', '${folder.replace(/'/g, "\\'")}')"
                    ondblclick="navigateInto('${type}', '${folder.replace(/'/g, "\\'")}')">
                    <svg class="folder-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>
                    </svg>
                    <span class="folder-name">${folder}</span>
                </div>`;
            });

            if (!html) {
                html = '<div class="folder-browser-loading">No folders found</div>';
            }

            listEl.innerHTML = html;
        }

        function selectFolder(type, folder) {
            const state = browserState[type];
            state.selected = state.selected === folder ? null : folder;

            // Update path display (shown at top of browser)
            const selectedEl = document.getElementById(`${type}-selected`);
            if (state.selected) {
                const fullPath = state.path === '/' ? `/${state.selected}` : `${state.path}/${state.selected}`;
                selectedEl.textContent = `Folder: ${fullPath}`;
                document.getElementById(`task-${type}-path`).value = fullPath;
            } else {
                // Show current browsing path when deselected
                selectedEl.textContent = state.path;
                document.getElementById(`task-${type}-path`).value = '';
            }

            renderFolderList(type);
        }

        function navigateInto(type, folder) {
            const state = browserState[type];
            const newPath = state.path === '/' ? `/${folder}` : `${state.path}/${folder}`;

            // When navigating into a folder, set path WITH trailing slash (copy contents)
            // Store this so browseFolder doesn't reset it
            state.insidePath = newPath + '/';

            browseFolder(type, newPath);
        }

        function navigateUp(type) {
            const state = browserState[type];
            const parts = state.path.split('/').filter(p => p);
            parts.pop();
            const newPath = '/' + parts.join('/') || '/';
            state.selected = null;
            document.getElementById(`task-${type}-path`).value = '';
            browseFolder(type, newPath);
        }

        function filterFolders(type) {
            const filterEl = document.getElementById(`${type}-filter`);
            browserState[type].filter = filterEl.value;
            renderFolderList(type);
        }

        // === FILE MANAGER ===
        const fmState = {
            left: { device: null, path: '/', files: [], selected: new Set() },
            right: { device: null, path: '/', files: [], selected: new Set() },
            activePane: 'left',
            busy: false
        };
        let fmClickTimer = null;
        let fmClickPane = null;
        let fmClickIdx = null;

        function openFileManager() {
            const sshDevices = config.devices.filter(d => d.ssh?.user || d.is_host);
            const options = sshDevices.map(d => `<option value="${d.id}">${d.name}</option>`).join('');
            const leftSelect = document.getElementById('fm-left-device');
            const rightSelect = document.getElementById('fm-right-device');

            leftSelect.innerHTML = rightSelect.innerHTML = options;

            if (config.fm_left_device && sshDevices.some(d => d.id === config.fm_left_device)) leftSelect.value = config.fm_left_device;
            if (config.fm_right_device && sshDevices.some(d => d.id === config.fm_right_device)) rightSelect.value = config.fm_right_device;
            else if (sshDevices.length > 1) rightSelect.selectedIndex = 1;

            fmState.left = { device: null, path: '/', files: [], selected: new Set() };
            fmState.right = { device: null, path: '/', files: [], selected: new Set() };
            fmState.busy = false;

            openModal('fm-modal');
            fmSetActivePane('left');
            refreshIcons();
            fmSetupDragDrop();
            fmLoadFiles('left');
            fmLoadFiles('right');
        }

        async function fmLoadFiles(pane) {
            const deviceId = document.getElementById(`fm-${pane}-device`).value;
            const state = fmState[pane];
            const listEl = document.getElementById(`fm-${pane}-list`);
            const pathEl = document.getElementById(`fm-${pane}-path`);

            const previousPath = state.path;
            const deviceChanged = state.device !== deviceId;

            if (deviceChanged) {
                const dev = config.devices.find(d => d.id === deviceId);
                state.path = dev?.last_fm_path || '/';
            }
            state.device = deviceId;
            state.selected.clear();

            listEl.innerHTML = '<div class="fm-loading">Loading...</div>';
            pathEl.textContent = state.path;

            try {
                const res = await api(`device/${deviceId}/files?path=${encodeURIComponent(state.path)}`);
                if (!res.success) throw new Error(res.error || 'Failed to open directory');

                state.files = res.files;
                fmRenderList(pane);
                fmUpdateStorage(pane, res.storage);

                const configKey = pane === 'left' ? 'fm_left_device' : 'fm_right_device';
                const dev = config.devices.find(d => d.id === deviceId);
                let changed = false;
                if (config[configKey] !== deviceId) { config[configKey] = deviceId; changed = true; }
                if (dev && dev.last_fm_path !== state.path) { dev.last_fm_path = state.path; changed = true; }
                if (changed) saveConfig();
            } catch (e) {
                if (deviceChanged && state.path !== '/') {
                    state.path = '/';
                    return fmLoadFiles(pane);
                }
                toast(e.message || 'Failed to load directory', 'error');
                state.path = previousPath;
                state.files.length > 0 ? fmRenderList(pane) : listEl.innerHTML = '';
                pathEl.textContent = state.path;
            }

            fmUpdateButtons();
        }

        function fmRenderList(pane) {
            const state = fmState[pane];
            const listEl = document.getElementById(`fm-${pane}-list`);

            let html = '';

            // Parent directory
            if (state.path !== '/') {
                html += `<div class="fm-item" draggable="false" ondblclick="fmNavigate('${pane}', '..')">
                    <svg class="fm-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M15 18l-6-6 6-6"/>
                    </svg>
                    <span class="fm-name">..</span>
                    <span class="fm-size"></span>
                    <span class="fm-date"></span>
                </div>`;
            }

            // Files and folders
            state.files.forEach((f, idx) => {
                const isSelected = state.selected.has(idx);
                const icon = f.is_dir
                    ? '<path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>'
                    : '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/>';

                const size = f.is_dir ? '' : fmFormatSize(f.size);
                const date = fmFormatDate(f.mtime);

                html += `<div class="fm-item${isSelected ? ' selected' : ''}" draggable="false"
                    onclick="fmClick('${pane}', ${idx})">
                    <svg class="fm-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">${icon}</svg>
                    <span class="fm-name">${fmEscape(f.name)}</span>
                    <span class="fm-size">${size}</span>
                    <span class="fm-date">${date}</span>
                </div>`;
            });

            if (!html) {
                html = '<div class="fm-loading">Empty folder</div>';
            }

            listEl.innerHTML = html;
        }

        function fmSetActivePane(pane) {
            fmState.activePane = pane;
            document.getElementById('fm-left').classList.toggle('active', pane === 'left');
            document.getElementById('fm-right').classList.toggle('active', pane === 'right');
        }

        function fmUpdatePath(pane) {
            const state = fmState[pane];
            const pathEl = document.getElementById(`fm-${pane}-path`);

            // If exactly one file selected, show full path with filename
            if (state.selected.size === 1) {
                const idx = Array.from(state.selected)[0];
                const file = state.files[idx];
                if (file) {
                    const fullPath = state.path === '/' ? `/${file.name}` : `${state.path}/${file.name}`;
                    pathEl.textContent = fullPath;
                    pathEl.title = fullPath;
                    return;
                }
            }

            // Otherwise show just the directory path
            pathEl.textContent = state.path;
            pathEl.title = state.path;
        }

        function fmClick(pane, idx) {
            if (fmClickTimer && fmClickPane === pane && fmClickIdx === idx) {
                clearTimeout(fmClickTimer);
                fmClickTimer = null;
                fmDblClick(pane, idx);
            } else {
                if (fmClickTimer) clearTimeout(fmClickTimer);
                fmClickPane = pane;
                fmClickIdx = idx;
                fmClickTimer = setTimeout(() => {
                    fmClickTimer = null;
                    fmSelect(pane, idx);
                }, 250);
            }
        }

        function fmSelect(pane, idx) {
            const state = fmState[pane];
            const otherPane = pane === 'left' ? 'right' : 'left';
            fmSetActivePane(pane);

            // Clear selection in other pane
            if (fmState[otherPane].selected.size > 0) {
                fmState[otherPane].selected.clear();
                fmRenderList(otherPane);
                fmUpdatePath(otherPane);
            }

            // Toggle selection
            if (state.selected.has(idx)) {
                state.selected.delete(idx);
            } else {
                state.selected.add(idx);
            }

            fmRenderList(pane);
            fmUpdatePath(pane);
            fmUpdateButtons();
        }

        function fmDblClick(pane, idx) {
            const state = fmState[pane];
            const file = state.files[idx];

            if (file.is_dir) {
                fmNavigate(pane, file.name);
            }
        }

        function fmNavigate(pane, name) {
            const state = fmState[pane];

            if (name === '..') {
                const parts = state.path.split('/').filter(p => p);
                parts.pop();
                state.path = '/' + parts.join('/') || '/';
            } else {
                state.path = state.path === '/' ? `/${name}` : `${state.path}/${name}`;
            }

            state.selected.clear();
            fmLoadFiles(pane);
        }

        function fmUpdateButtons() {
            const leftSel = fmState.left.selected.size;
            const rightSel = fmState.right.selected.size;
            const totalSel = leftSel + rightSel;

            // Copy/Move: need selection
            document.getElementById('fm-copy').disabled = totalSel === 0 || fmState.busy;
            document.getElementById('fm-move').disabled = totalSel === 0 || fmState.busy;

            // New Folder: always enabled if not busy and pane is active
            document.getElementById('fm-newfolder').disabled = !fmState.activePane || fmState.busy;

            // Rename: exactly one selection
            document.getElementById('fm-rename').disabled = totalSel !== 1 || fmState.busy;

            // Delete/Zip: at least one selection
            document.getElementById('fm-delete').disabled = totalSel === 0 || fmState.busy;
            document.getElementById('fm-zip').disabled = totalSel === 0 || fmState.busy;

            // Extract: one archive file
            let canExtract = false;
            if (totalSel === 1) {
                const pane = leftSel === 1 ? 'left' : 'right';
                const idx = Array.from(fmState[pane].selected)[0];
                const file = fmState[pane].files[idx];
                if (file && !file.is_dir) {
                    const n = file.name.toLowerCase();
                    canExtract = n.endsWith('.zip') || n.endsWith('.tar') || n.endsWith('.tar.gz') || n.endsWith('.tgz') || n.endsWith('.tar.bz2') || n.endsWith('.tbz2') || n.endsWith('.tar.xz') || n.endsWith('.txz');
                }
            }
            document.getElementById('fm-extract').disabled = !canExtract || fmState.busy;

            // Download: one file (not folder)
            let canDownload = false;
            if (totalSel === 1) {
                const pane = leftSel === 1 ? 'left' : 'right';
                const idx = Array.from(fmState[pane].selected)[0];
                const file = fmState[pane].files[idx];
                canDownload = file && !file.is_dir;
            }
            document.getElementById('fm-download').disabled = !canDownload || fmState.busy;
        }

        async function fmCopy() {
            const from = fmState.left.selected.size > 0 ? 'left' : 'right';
            await fmTransfer('copy', from, from === 'left' ? 'right' : 'left');
        }

        async function fmMove() {
            const from = fmState.left.selected.size > 0 ? 'left' : 'right';
            await fmTransfer('move', from, from === 'left' ? 'right' : 'left');
        }

        async function fmTransfer(operation, fromPane, toPane) {
            const fromState = fmState[fromPane];
            const toState = fmState[toPane];

            const paths = Array.from(fromState.selected).map(idx => {
                const f = fromState.files[idx];
                return fromState.path === '/' ? `/${f.name}` : `${fromState.path}/${f.name}`;
            });

            if (paths.length === 0) return;

            fmState.busy = true;
            fmUpdateButtons();

            // 1. Preflight check
            const preflight = await api(`device/${fromState.device}/files`, 'POST', {
                operation: 'preflight',
                paths,
                dest_device: toState.device,
                dest_path: toState.path
            });

            if (!preflight.ok) {
                toast(preflight.error, 'error');
                fmState.busy = false;
                fmUpdateButtons();
                return;
            }

            // 2. Confirm for large transfers (>100MB) or move
            const sizeStr = fmFormatSize(preflight.src_size);
            let confirmMsg = operation === 'move' ? `Move ${sizeStr}?` : `Copy ${sizeStr}?`;
            if (preflight.needs_host_transfer) confirmMsg += ' (via host)';

            if (preflight.src_size > 100 * 1024 * 1024 || operation === 'move') {
                if (!confirm(confirmMsg)) {
                    fmState.busy = false;
                    fmUpdateButtons();
                    return;
                }
            }

            // 3. Start transfer
            const start = await api(`device/${fromState.device}/files`, 'POST', {
                operation,
                paths,
                dest_device: toState.device,
                dest_path: toState.path
            });

            if (!start.job_id) {
                toast(start.error || 'Transfer failed', 'error');
                fmState.busy = false;
                fmUpdateButtons();
                return;
            }

            // 4. Poll job
            fmPollJob(start.job_id, operation === 'move' ? 'Moving' : 'Copying', () => {
                toast(operation === 'move' ? 'Moved successfully' : 'Copied successfully');
                fromState.selected.clear();
                fmLoadFiles(fromPane);
                fmLoadFiles(toPane);
            });
        }

        function fmPollJob(jobId, action, onComplete) {
            const progressEl = document.getElementById('fm-progress');
            const progressFill = document.getElementById('fm-progress-fill');
            const progressText = document.getElementById('fm-progress-text');
            progressEl.classList.add('visible');
            progressFill.style.width = '0%';

            const poll = setInterval(async () => {
                const s = await api(`job/${jobId}`);
                if (s.status === 'running') {
                    const phase = s.phases > 1 ? `Phase ${s.phase}/${s.phases}: ` : '';
                    const speed = s.speed ? ` (${s.speed})` : '';
                    progressFill.style.width = s.progress + '%';
                    progressText.textContent = `${phase}${action}... ${s.progress}%${speed}`;
                } else {
                    clearInterval(poll);
                    progressEl.classList.remove('visible');
                    fmState.busy = false;
                    fmUpdateButtons();
                    if (s.status === 'complete') onComplete();
                    else toast(s.error || 'Transfer failed', 'error');
                }
            }, 1000);
        }

        async function fmRename() {
            const pane = fmState.left.selected.size > 0 ? 'left' : 'right';
            const state = fmState[pane];
            const idx = Array.from(state.selected)[0];
            const file = state.files[idx];

            const newName = prompt('New name:', file.name);
            if (!newName || newName === file.name) return;

            const oldPath = state.path === '/' ? `/${file.name}` : `${state.path}/${file.name}`;

            fmState.busy = true;
            fmUpdateButtons();

            try {
                const res = await api(`device/${state.device}/files`, 'POST', {
                    operation: 'rename',
                    paths: [oldPath],
                    new_name: newName
                });

                if (res.success) {
                    toast('Renamed successfully');
                    state.selected.clear();
                    fmLoadFiles(pane);
                } else {
                    toast(res.error || 'Rename failed', 'error');
                }
            } catch (e) {
                toast('Rename failed', 'error');
            }

            fmState.busy = false;
            fmUpdateButtons();
        }

        async function fmNewFolder() {
            const pane = fmState.activePane;
            const state = fmState[pane];

            const folderName = prompt('Folder name:');
            if (!folderName) return;

            if (folderName.includes('/') || folderName.includes('\0')) {
                toast('Invalid folder name', 'error');
                return;
            }

            fmState.busy = true;
            fmUpdateButtons();

            try {
                const res = await api(`device/${state.device}/files`, 'POST', {
                    operation: 'mkdir',
                    paths: [state.path],
                    new_name: folderName
                });

                if (res.success) {
                    toast('Folder created');
                    fmLoadFiles(pane);
                } else {
                    toast(res.error || 'Failed to create folder', 'error');
                }
            } catch (e) {
                toast('Failed to create folder', 'error');
            }

            fmState.busy = false;
            fmUpdateButtons();
        }

        async function fmDelete() {
            const leftPaths = Array.from(fmState.left.selected).map(idx => {
                const f = fmState.left.files[idx];
                return { pane: 'left', path: fmState.left.path === '/' ? `/${f.name}` : `${fmState.left.path}/${f.name}` };
            });
            const rightPaths = Array.from(fmState.right.selected).map(idx => {
                const f = fmState.right.files[idx];
                return { pane: 'right', path: fmState.right.path === '/' ? `/${f.name}` : `${fmState.right.path}/${f.name}` };
            });

            const allPaths = [...leftPaths, ...rightPaths];
            if (allPaths.length === 0) return;

            if (!confirm(`Delete ${allPaths.length} item(s)? This cannot be undone.`)) return;

            fmState.busy = true;
            fmUpdateButtons();
            toast('Deleting...');

            // Group by device
            const byDevice = {};
            for (const item of leftPaths) {
                const dev = fmState.left.device;
                if (!byDevice[dev]) byDevice[dev] = [];
                byDevice[dev].push(item.path);
            }
            for (const item of rightPaths) {
                const dev = fmState.right.device;
                if (!byDevice[dev]) byDevice[dev] = [];
                byDevice[dev].push(item.path);
            }

            let success = true;
            for (const [deviceId, paths] of Object.entries(byDevice)) {
                try {
                    const res = await api(`device/${deviceId}/files`, 'POST', {
                        operation: 'delete',
                        paths
                    });
                    if (!res.success) {
                        toast(res.error || 'Delete failed', 'error');
                        success = false;
                        break;
                    }
                } catch (e) {
                    toast('Delete failed', 'error');
                    success = false;
                    break;
                }
            }

            if (success) {
                toast('Deleted successfully');
                fmState.left.selected.clear();
                fmState.right.selected.clear();
                if (leftPaths.length > 0) fmLoadFiles('left');
                if (rightPaths.length > 0) fmLoadFiles('right');
            }

            fmState.busy = false;
            fmUpdateButtons();
        }

        async function fmZip() {
            // Use active pane
            const pane = fmState.left.selected.size > 0 ? 'left' : 'right';
            const state = fmState[pane];

            const paths = Array.from(state.selected).map(idx => {
                const f = state.files[idx];
                return state.path === '/' ? `/${f.name}` : `${state.path}/${f.name}`;
            });

            if (paths.length === 0) return;

            fmState.busy = true;
            fmUpdateButtons();
            toast('Creating archive...');

            try {
                const res = await api(`device/${state.device}/files`, 'POST', {
                    operation: 'zip',
                    paths
                });

                if (res.success) {
                    toast(`Archive created: ${res.archive.split('/').pop()}`);
                    state.selected.clear();
                    fmLoadFiles(pane);
                } else {
                    toast(res.error || 'Zip failed', 'error');
                }
            } catch (e) {
                toast('Zip failed', 'error');
            }

            fmState.busy = false;
            fmUpdateButtons();
        }

        async function fmExtract() {
            const srcPane = fmState.left.selected.size > 0 ? 'left' : 'right';
            const destPane = srcPane === 'left' ? 'right' : 'left';
            const srcState = fmState[srcPane];
            const destState = fmState[destPane];

            const idx = Array.from(srcState.selected)[0];
            const file = srcState.files[idx];
            const archivePath = srcState.path === '/' ? `/${file.name}` : `${srcState.path}/${file.name}`;

            fmState.busy = true;
            fmUpdateButtons();
            toast('Extracting...');

            try {
                const res = await api(`device/${srcState.device}/files`, 'POST', {
                    operation: 'extract',
                    paths: [archivePath],
                    dest_device: destState.device,
                    dest_path: destState.path
                });

                if (!res.success) {
                    toast(res.error || 'Extract failed', 'error');
                    fmState.busy = false;
                    fmUpdateButtons();
                    return;
                }

                if (res.transfer && res.job_id) {
                    fmPollJob(res.job_id, 'Extracting', () => {
                        toast('Extracted');
                        srcState.selected.clear();
                        fmLoadFiles(destPane);
                    });
                } else {
                    toast('Extracted');
                    srcState.selected.clear();
                    fmLoadFiles(destPane);
                    fmState.busy = false;
                    fmUpdateButtons();
                }
            } catch (e) {
                toast('Extract failed', 'error');
                fmState.busy = false;
                fmUpdateButtons();
            }
        }

        function fmDownload() {
            const pane = fmState.left.selected.size > 0 ? 'left' : 'right';
            const state = fmState[pane];
            const idx = Array.from(state.selected)[0];
            const file = state.files[idx];

            if (file.is_dir) {
                toast('Cannot download folders', 'error');
                return;
            }

            const filePath = state.path === '/' ? `/${file.name}` : `${state.path}/${file.name}`;
            const url = `/api/device/${state.device}/download?path=${encodeURIComponent(filePath)}`;

            // Trigger download
            const a = document.createElement('a');
            a.href = url;
            a.download = file.name;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
        }

        async function fmUploadFiles(files) {
            if (!files || files.length === 0) return;

            // Determine target pane (active or left as default)
            const pane = fmState.activePane || 'left';
            const state = fmState[pane];

            if (!state.device) {
                toast('Select a device first', 'error');
                return;
            }

            // Check for large files (>1GB) and warn if not dismissed
            const largeFiles = Array.from(files).filter(f => f.size > 1024 * 1024 * 1024);
            if (largeFiles.length > 0 && !localStorage.getItem('fm-upload-warning-dismissed')) {
                const names = largeFiles.map(f => f.name).join(', ');
                const msg = `Large file warning: ${names}\n\nHTTP uploads may be unreliable for files >1GB. Keep your source file until you verify the upload completed successfully.\n\nClick OK to continue, Cancel to abort.`;

                if (!confirm(msg)) {
                    document.getElementById('fm-upload-input').value = '';
                    return;
                }

                // Offer to dismiss future warnings
                if (confirm("Don't warn me again about large uploads?")) {
                    localStorage.setItem('fm-upload-warning-dismissed', 'true');
                }
            }

            fmState.busy = true;
            fmUpdateButtons();

            const formData = new FormData();
            for (const file of files) {
                formData.append('files', file, file.name);
            }

            const totalSize = Array.from(files).reduce((sum, f) => sum + f.size, 0);

            // Show progress bar
            const progressEl = document.getElementById('fm-progress');
            const progressFill = document.getElementById('fm-progress-fill');
            const progressText = document.getElementById('fm-progress-text');
            progressEl.classList.add('visible');
            progressFill.style.width = '0%';
            progressText.textContent = `Uploading ${files.length} file(s)... 0%`;

            const url = `/api/device/${state.device}/upload?path=${encodeURIComponent(state.path)}`;

            // Use XMLHttpRequest for progress tracking
            const xhr = new XMLHttpRequest();

            xhr.upload.onprogress = (e) => {
                if (e.lengthComputable) {
                    const percent = Math.round((e.loaded / e.total) * 100);
                    progressFill.style.width = percent + '%';
                    progressText.textContent = `Uploading... ${percent}% (${fmFormatSize(e.loaded)} / ${fmFormatSize(e.total)})`;
                }
            };

            xhr.onload = () => {
                progressEl.classList.remove('visible');
                fmState.busy = false;
                fmUpdateButtons();
                document.getElementById('fm-upload-input').value = '';

                try {
                    const data = JSON.parse(xhr.responseText);
                    if (data.success) {
                        toast(`Uploaded ${data.uploaded} file(s)`);
                        fmLoadFiles(pane);
                    } else {
                        toast(data.error || 'Upload failed', 'error');
                    }
                } catch (e) {
                    toast('Upload failed: Invalid response', 'error');
                }
            };

            xhr.onerror = () => {
                progressEl.classList.remove('visible');
                fmState.busy = false;
                fmUpdateButtons();
                document.getElementById('fm-upload-input').value = '';
                toast('Upload failed: Connection error', 'error');
            };

            xhr.open('POST', url);
            xhr.send(formData);
        }

        // Drag & drop support for file upload
        function fmSetupDragDrop() {
            ['left', 'right'].forEach(pane => {
                const el = document.getElementById(`fm-${pane}-list`);
                if (!el) return;

                el.addEventListener('dragover', (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    el.style.background = 'var(--accent)';
                    el.style.opacity = '0.7';
                });

                el.addEventListener('dragleave', (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    el.style.background = '';
                    el.style.opacity = '';
                });

                el.addEventListener('drop', (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    el.style.background = '';
                    el.style.opacity = '';

                    fmSetActivePane(pane);
                    const files = e.dataTransfer.files;
                    if (files.length > 0) {
                        fmUploadFiles(files);
                    }
                });
            });
        }

        function fmFormatSize(bytes) {
            if (bytes === 0) return '0 B';
            if (bytes < 1024) return bytes + ' B';
            if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
            if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
            if (bytes < 1024 * 1024 * 1024 * 1024) return (bytes / (1024 * 1024 * 1024)).toFixed(1) + ' GB';
            return (bytes / (1024 * 1024 * 1024 * 1024)).toFixed(1) + ' TB';
        }

        function fmUpdateStorage(pane, storage) {
            const el = document.getElementById(`fm-${pane}-storage`);
            if (!storage) {
                el.innerHTML = '';
                return;
            }
            const free = fmFormatSize(storage.free);
            const total = fmFormatSize(storage.total);
            const percent = storage.percent;
            const color = getBarColor(percent);
            el.innerHTML = `
                <span class="fm-storage-text">${free} / ${total} free</span>
                <div class="fm-storage-bar">
                    <div class="fm-storage-fill" style="width: ${percent}%; background: ${color}"></div>
                </div>
                <span class="fm-storage-percent">${percent}%</span>
            `;
        }

        function fmFormatDate(timestamp) {
            if (!timestamp) return '';
            const d = new Date(timestamp * 1000);
            const now = new Date();
            const isThisYear = d.getFullYear() === now.getFullYear();

            if (isThisYear) {
                return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
            }
            return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: '2-digit' });
        }

        function fmEscape(str) {
            return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
        }

        function showWizardStep(step) {
            document.querySelectorAll('.wizard-step').forEach(el => el.style.display = 'none');
            document.getElementById(`wizard-step-${step}`).style.display = 'block';
            wizardStep = step;
            refreshIcons();
        }

        function wizardNext() {
            const action = getWizardAction();
            const target = getWizardTarget();

            if (wizardStep === 1) {
                if (action === 'wake') {
                    document.getElementById('step2-action').textContent = 'power on';
                    document.getElementById('step2-device-desc').textContent = 'Wake via Wake-on-LAN';
                    document.getElementById('step2-docker-desc').textContent = 'Start container';
                    showWizardStep(2);
                } else if (action === 'shutdown') {
                    document.getElementById('step2-action').textContent = 'power off';
                    document.getElementById('step2-device-desc').textContent = 'Shutdown via SSH';
                    document.getElementById('step2-docker-desc').textContent = 'Stop container';
                    showWizardStep(2);
                } else if (action === 'suspend') {
                    showWizardStep(3);
                } else if (action === 'backup') {
                    showWizardStep(3);
                } else if (action === 'script') {
                    showWizardStep(3);
                }
            } else if (wizardStep === 2) {
                showWizardStep(3);
            } else if (wizardStep === 3) {
                if (action === 'wake' || action === 'shutdown') {
                    if (target === 'device') {
                        document.getElementById('target-device-group').style.display = 'block';
                        document.getElementById('target-container-group').style.display = 'none';
                        const devices = action === 'wake'
                            ? config.devices.filter(d => d.wol?.mac)
                            : config.devices.filter(d => d.ssh?.user || d.is_host);
                        const options = devices.map(d => `<option value="${d.id}">${d.name}</option>`).join('');
                        document.getElementById('task-target-device').innerHTML = options || '<option value="">No devices available</option>';
                    } else {
                        document.getElementById('target-device-group').style.display = 'none';
                        document.getElementById('target-container-group').style.display = 'block';
                    }
                    showWizardStep(4);
                } else if (action === 'suspend') {
                    document.getElementById('target-device-group').style.display = 'block';
                    document.getElementById('target-container-group').style.display = 'none';
                    const devices = config.devices.filter(d => d.ssh?.user || d.is_host);
                    const options = devices.map(d => `<option value="${d.id}">${d.name}</option>`).join('');
                    document.getElementById('task-target-device').innerHTML = options || '<option value="">No devices available</option>';
                    showWizardStep(4);
                } else if (action === 'backup') {
                    showWizardStep(5);
                    browseFolder('source');
                } else if (action === 'script') {
                    populateScriptSelect();
                    showWizardStep(8);
                }
            } else if (wizardStep === 4) {
                document.getElementById('backup-options').style.display = 'none';
                showWizardStep(7);
            } else if (wizardStep === 5) {
                showWizardStep(6);
                browseFolder('dest');
            } else if (wizardStep === 6) {
                document.getElementById('backup-options').style.display = 'block';
                showWizardStep(7);
            } else if (wizardStep === 8) {
                document.getElementById('backup-options').style.display = 'none';
                showWizardStep(7);
            }
        }

        async function populateScriptSelect() {
            const select = document.getElementById('task-script');
            select.innerHTML = '<option value="">Loading...</option>';
            try {
                const res = await api('scripts/scan');
                const scripts = res.scripts || [];
                if (scripts.length === 0) {
                    select.innerHTML = '<option value="">No scripts found</option>';
                } else {
                    select.innerHTML = scripts.map(s => `<option value="${s.path}">${s.path}</option>`).join('');
                }
            } catch (e) {
                select.innerHTML = '<option value="">Failed to load scripts</option>';
            }
        }

        function wizardBack() {
            const action = getWizardAction();

            if (wizardStep === 2) {
                showWizardStep(1);
            } else if (wizardStep === 3) {
                if (action === 'wake' || action === 'shutdown') {
                    showWizardStep(2);
                } else {
                    showWizardStep(1);
                }
            } else if (wizardStep === 4) {
                showWizardStep(3);
            } else if (wizardStep === 5) {
                showWizardStep(3);
            } else if (wizardStep === 6) {
                showWizardStep(5);
            } else if (wizardStep === 7) {
                if (action === 'backup') {
                    showWizardStep(6);
                } else if (action === 'script') {
                    showWizardStep(8);
                } else {
                    showWizardStep(4);
                }
            } else if (wizardStep === 8) {
                showWizardStep(3);
            }
        }

        function updateScheduleOptions() {
            const freq = document.getElementById('task-frequency').value;
            document.getElementById('schedule-time-group').style.display = 'block';
            document.getElementById('schedule-day-group').style.display = freq === 'weekly' ? 'block' : 'none';
            document.getElementById('schedule-date-group').style.display = freq === 'monthly' ? 'block' : 'none';
        }

        async function saveTask(e) {
            e.preventDefault();

            const id = document.getElementById('task-id').value || generateUUID();
            const action = getWizardAction();
            const target = getWizardTarget();

            const task = {
                id,
                type: action,
                target: action === 'backup' ? 'device' : target,
                name: document.getElementById('task-name').value || `${action} task`,
                enabled: true,
                schedule: {
                    type: document.getElementById('task-frequency').value,
                    time: document.getElementById('task-time').value
                }
            };

            if (task.schedule.type === 'weekly') {
                task.schedule.day = parseInt(document.getElementById('task-day').value);
            }
            if (task.schedule.type === 'monthly') {
                task.schedule.date = parseInt(document.getElementById('task-date').value);
            }

            if (action === 'backup') {
                task.source = {
                    device: document.getElementById('task-source-device').value,
                    path: document.getElementById('task-source-path').value
                };
                task.dest = {
                    device: document.getElementById('task-dest-device').value,
                    path: document.getElementById('task-dest-path').value
                };
                task.options = {
                    delete: document.getElementById('task-delete-files').checked
                };
            } else if (action === 'script') {
                task.script = document.getElementById('task-script').value;
            } else if (action === 'suspend') {
                task.device = document.getElementById('task-target-device').value;
            } else if (target === 'device') {
                task.device = document.getElementById('task-target-device').value;
            } else if (target === 'docker') {
                const containerValue = document.getElementById('task-target-container').value;
                const [deviceId, containerName] = containerValue.split(':');
                task.device = deviceId;
                task.container = containerName;
            }

            if (!config.tasks) config.tasks = [];
            const idx = config.tasks.findIndex(t => t.id === id);
            if (idx >= 0) config.tasks[idx] = task;
            else config.tasks.push(task);

            await api('config', 'POST', config);
            closeModal('task-modal');
            renderTasks();
            toast('Task saved');
        }

        async function deleteTask(id) {
            if (!confirm('Delete this task?')) return;
            config.tasks = config.tasks.filter(t => t.id !== id);
            await api('config', 'POST', config);
            renderTasks();
            toast('Task deleted');
        }

        async function toggleTask(id) {
            const task = config.tasks.find(t => t.id === id);
            if (task) {
                task.enabled = !task.enabled;
                await api('config', 'POST', config);
                renderTasks();
                toast(task.enabled ? 'Task resumed' : 'Task paused');
            }
        }

        async function runTaskNow(id) {
            // Show running state immediately
            const task = config.tasks.find(t => t.id === id);
            if (task) {
                task._running = true;
                renderTasks();
            }

            const res = await api(`task/${id}/run`, 'POST');

            if (!res.success) {
                if (task) task._running = false;
                toast(res.error || 'Failed to start task', 'error');
                renderTasks();
                return;
            }

            // Poll for completion
            toast('Task started...');
            const pollStatus = async () => {
                // Stop polling if task was deleted
                const localTask = config.tasks.find(t => t.id === id);
                if (!localTask) return;

                const status = await api(`task/${id}/status`);

                // Stop if task not found on server or not running
                if (!status.success || !status.running) {
                    if (localTask) localTask._running = false;
                    await loadConfig();
                    renderTasks();

                    const t = config.tasks.find(x => x.id === id);
                    if (!t) return; // Task was deleted

                    if (t.last_status === 'success') {
                        toast('Task completed');
                    } else if (t.last_status === 'skipped') {
                        toast(t.last_error || 'Task skipped', 'warning');
                    } else if (t.last_status === 'failed') {
                        toast(t.last_error || 'Task failed', 'error');
                    }
                } else {
                    setTimeout(pollStatus, 2000);
                }
            };
            setTimeout(pollStatus, 1000);
        }

        async function editTask(id) {
            const task = config.tasks.find(t => t.id === id);
            if (!task) return;

            openTaskWizard(id);

            // Fill in action type
            const actionRadio = document.querySelector(`input[name="task-action"][value="${task.type}"]`);
            if (actionRadio) actionRadio.checked = true;

            // Fill in target type (device/docker)
            const target = task.target || 'device';
            const targetRadio = document.querySelector(`input[name="task-target"][value="${target}"]`);
            if (targetRadio) targetRadio.checked = true;

            // Schedule
            document.getElementById('task-frequency').value = task.schedule?.type || 'daily';
            document.getElementById('task-time').value = task.schedule?.time || '03:00';
            if (task.schedule?.day) document.getElementById('task-day').value = task.schedule.day;
            if (task.schedule?.date) document.getElementById('task-date').value = task.schedule.date;
            document.getElementById('task-name').value = task.name;

            if (task.type === 'backup') {
                document.getElementById('task-source-device').value = task.source?.device || '';
                document.getElementById('task-source-path').value = task.source?.path || '';
                document.getElementById('task-dest-device').value = task.dest?.device || '';
                document.getElementById('task-dest-path').value = task.dest?.path || '';
                document.getElementById('task-delete-files').checked = task.options?.delete || false;
            } else if (task.type === 'script') {
                await populateScriptSelect();
                document.getElementById('task-script').value = task.script || '';
            } else if (target === 'device') {
                // Wake/Shutdown device - use new field or fall back to old structure
                const deviceId = task.device || task.source?.device || '';
                document.getElementById('task-target-device').value = deviceId;
            } else if (target === 'docker') {
                // Wake/Shutdown docker
                const containerValue = `${task.device}:${task.container}`;
                document.getElementById('task-target-container').value = containerValue;
            }

            updateScheduleOptions();
        }

        // === Load Data ===
        let runningTasks = [];

        async function loadConfig() {
            const res = await api('config');
            if (res.success) {
                config = res.config;
                runningTasks = res.running_tasks || [];
                if (res.auth_enabled) document.getElementById('logout-btn').style.display = '';
                initTheme();
                renderSections();
            }
        }
        
        async function loadDeviceStatus() {
            const promises = config.devices.map(dev =>
                api(`device/${dev.id}/status`)
                    .then(res => {
                        deviceStats[dev.id] = res;
                    })
                    .catch(() => {
                        deviceStats[dev.id] = { online: false, stats: null, containers: {} };
                    })
            );
            await Promise.all(promises);
            renderDevices();
        }
        
        
        // === Init ===
        document.getElementById('edit-toggle').onclick = () => {
            editMode = !editMode;
            document.body.classList.toggle('edit-mode', editMode);
            document.getElementById('edit-toggle').classList.toggle('active', editMode);
            renderSections();
        };

        document.getElementById('link-form').onsubmit = saveLink;
        document.getElementById('device-form').onsubmit = saveDevice;
        
        // Close modals on background click
        document.querySelectorAll('.modal').forEach(m => {
            m.onclick = e => { if (e.target === m) closeModal(m.id); };
        });
        
        // Polling management
        let deviceInterval = null;

        function startPolling() {
            loadDeviceStatus();
            renderTasks();
            loadExtensions();
            if (!deviceInterval) {
                deviceInterval = setInterval(() => {
                    loadDeviceStatus();
                    renderTasks();
                    loadExtensions();
                }, 5000);
            }
        }

        function stopPolling() {
            if (deviceInterval) {
                clearInterval(deviceInterval);
                deviceInterval = null;
            }
        }

        // Stop polling when tab is hidden
        document.addEventListener('visibilitychange', () => {
            if (document.hidden) {
                stopPolling();
            } else {
                startPolling();
            }
        });

        // === Onboarding ===
        let onboardingDevices = [];
        let defaultSshUser = 'root';
        const OS_ICONS = {linux: 'server', windows: 'monitor', android: 'smartphone', ios: 'smartphone', macos: 'laptop'};

        async function startOnboarding(isRescan = false) {
            document.getElementById('onboarding-title').textContent = isRescan ? 'Scan for devices' : "Welcome to DeQ!";
            document.getElementById('onboarding-loading').style.display = 'block';
            document.getElementById('onboarding-devices').style.display = 'none';
            document.getElementById('onboarding-empty').style.display = 'none';
            document.getElementById('onboarding-actions').style.display = 'none';
            document.getElementById('onboarding-empty-actions').style.display = 'none';
            openModal('onboarding-modal');

            const res = await api('network/scan');
            onboardingDevices = res.devices || [];
            defaultSshUser = res.default_ssh_user || 'root';

            // Filter out already existing devices (by IP)
            const existingIPs = new Set(config.devices.map(d => d.ip));
            if (isRescan) {
                onboardingDevices = onboardingDevices.filter(d => {
                    if (d.lan_ip && existingIPs.has(d.lan_ip)) return false;
                    if (d.tailscale_ip && existingIPs.has(d.tailscale_ip)) return false;
                    return d.lan_ip || d.tailscale_ip;
                });
            }

            document.getElementById('onboarding-loading').style.display = 'none';

            if (onboardingDevices.length === 0) {
                document.getElementById('onboarding-empty').style.display = 'block';
                document.getElementById('onboarding-empty-actions').style.display = 'flex';
                return;
            }

            const list = document.getElementById('onboarding-device-list');
            list.innerHTML = onboardingDevices.map((d, i) => {
                const isLinux = d.os === 'linux';
                const hostname = d.hostname || d.lan_ip || 'Unknown';
                const tsIp = d.tailscale_ip || '—';
                const lanIp = d.lan_ip || '—';
                const mac = d.mac || '—';
                return `<div class="onboarding-row" data-index="${i}" data-os="${d.os || ''}">
                    <input type="checkbox" ${isLinux ? 'checked' : ''}>
                    <input type="text" class="ob-name" value="${hostname}">
                    <input type="text" class="ob-ssh" value="${defaultSshUser}" placeholder="user">
                    <span class="ob-ip">${tsIp}</span>
                    <span class="ob-ip">${lanIp}</span>
                    <span class="ob-mac">${mac}</span>
                    <span class="ob-status ${d.online ? 'online' : ''}"></span>
                </div>`;
            }).join('');
            list.innerHTML = `<div class="onboarding-header">
                <span></span><span>Name</span><span>SSH</span><span>Tailscale IP</span><span>LAN IP</span><span>MAC</span><span></span>
            </div>` + list.innerHTML;

            document.getElementById('onboarding-devices').style.display = 'block';
            document.getElementById('onboarding-actions').style.display = 'flex';
            document.getElementById('onboarding-skip-btn').textContent = isRescan ? 'Cancel' : 'Skip';
        }

        function onboardingSelectAll() {
            document.querySelectorAll('#onboarding-device-list input[type="checkbox"]').forEach(cb => cb.checked = true);
        }
        function onboardingSelectNone() {
            document.querySelectorAll('#onboarding-device-list input[type="checkbox"]').forEach(cb => cb.checked = false);
        }
        function onboardingSelectLinux() {
            document.querySelectorAll('#onboarding-device-list .onboarding-row').forEach(row => {
                row.querySelector('input[type="checkbox"]').checked = row.dataset.os === 'linux';
            });
        }

        async function addOnboardingDevices() {
            const rows = document.querySelectorAll('#onboarding-device-list .onboarding-row');
            const addedDevices = [];
            rows.forEach(row => {
                const cb = row.querySelector('input[type="checkbox"]');
                if (!cb.checked) return;
                const name = row.querySelector('.ob-name').value.trim();
                const sshUser = row.querySelector('.ob-ssh').value.trim();
                const i = parseInt(row.dataset.index);
                const d = onboardingDevices[i];
                const ip = d.lan_ip || d.tailscale_ip;
                if (!ip) return;

                const device = {
                    id: generateUUID(),
                    name: name || ip,
                    ip: ip,
                    icon: OS_ICONS[d.os] || 'server'
                };
                if (d.mac && d.lan_ip) {
                    const parts = d.lan_ip.split('.');
                    const broadcast = parts.slice(0, 3).join('.') + '.255';
                    device.wol = {mac: d.mac, broadcast: broadcast};
                }
                if (d.tailscale_ip && d.lan_ip) {
                    device.connect = {web: 'http://' + d.tailscale_ip};
                }
                if (sshUser) {
                    device.ssh = {user: sshUser};
                }
                config.devices.push(device);
                addedDevices.push({...device, _online: d.online});
            });
            if (addedDevices.length > 0) {
                await saveConfig();
                renderDevices();
                toast(`Added ${addedDevices.length} device(s)`);
                startDockerScan(addedDevices);
            } else {
                closeOnboarding(true);
            }
        }

        async function closeOnboarding(markDone = false) {
            closeModal('onboarding-modal');
            if (markDone && NEEDS_ONBOARDING) {
                await api('onboarding/complete', 'POST');
            }
        }

        // === Docker Scan ===
        let dockerScanDevices = [];

        async function startDockerScan(devices) {
            dockerScanDevices = devices.filter(d => d.ssh && d.ssh.user);
            if (dockerScanDevices.length === 0) {
                closeOnboarding(true);
                return;
            }

            closeModal('onboarding-modal');
            document.getElementById('docker-scan-checking').style.display = 'block';
            document.getElementById('docker-scan-available').style.display = 'none';
            document.getElementById('docker-scan-none').style.display = 'none';
            document.getElementById('docker-scan-actions').style.display = 'none';
            document.getElementById('docker-scan-none-actions').style.display = 'none';
            openModal('docker-scan-modal');

            const sshResults = await Promise.all(dockerScanDevices.map(async d => {
                if (!d._online) {
                    return {device: d, hasSSH: false, offline: true};
                }
                const res = await api(`device/${d.id}/ssh-check`);
                return {device: d, hasSSH: res.success, offline: false};
            }));

            document.getElementById('docker-scan-checking').style.display = 'none';

            const withSSH = sshResults.filter(r => r.hasSSH);
            const withoutSSH = sshResults.filter(r => !r.hasSSH);

            if (withSSH.length === 0) {
                document.getElementById('docker-scan-none').style.display = 'block';
                document.getElementById('docker-scan-none-actions').style.display = 'flex';
                return;
            }

            const list = document.getElementById('docker-scan-list');
            list.innerHTML = [
                ...withSSH.map(r => `<div class="docker-scan-row" data-id="${r.device.id}">
                    <input type="checkbox" checked>
                    <span class="ds-name">${r.device.name}</span>
                    <span class="ds-status success">SSH OK</span>
                </div>`),
                ...withoutSSH.map(r => `<div class="docker-scan-row no-ssh">
                    <span class="ds-name">${r.device.name}</span>
                    <span class="ds-status error">${r.offline ? 'Offline' : 'No SSH access'}</span>
                </div>`)
            ].join('');

            document.getElementById('docker-scan-available').style.display = 'block';
            document.getElementById('docker-scan-actions').style.display = 'flex';
        }

        async function runDockerScan() {
            const rows = document.querySelectorAll('#docker-scan-list .docker-scan-row:not(.no-ssh)');
            let scanned = 0;
            for (const row of rows) {
                const cb = row.querySelector('input[type="checkbox"]');
                if (!cb || !cb.checked) continue;
                const deviceId = row.dataset.id;
                const device = config.devices.find(d => d.id === deviceId);
                if (!device) continue;

                row.querySelector('.ds-status').textContent = 'Scanning...';
                row.querySelector('.ds-status').className = 'ds-status';

                const res = await api(`device/${deviceId}/scan-containers`);
                if (res.success && res.containers && res.containers.length > 0) {
                    device.docker = {containers: res.containers};
                    row.querySelector('.ds-status').textContent = `Found ${res.containers.length}`;
                    row.querySelector('.ds-status').className = 'ds-status success';
                    scanned++;
                } else {
                    row.querySelector('.ds-status').textContent = res.error || 'No containers';
                    row.querySelector('.ds-status').className = 'ds-status';
                }
            }
            if (scanned > 0) {
                await saveConfig();
                renderDevices();
            }
            setTimeout(() => closeDockerScan(), 1000);
        }

        function closeDockerScan() {
            closeModal('docker-scan-modal');
            if (NEEDS_ONBOARDING) {
                api('onboarding/complete', 'POST');
            }
        }

        // Initialize icons
        document.getElementById('header-logo').innerHTML = LOGO_SVG;
        document.getElementById('onboarding-logo').innerHTML = LOGO_SVG;
        document.querySelectorAll('.modal-close').forEach(el => el.innerHTML = ICON_CLOSE);
        document.querySelectorAll('.icon-plus').forEach(el => el.innerHTML = ICON_PLUS);

        // Load everything
        loadConfig().then(() => {
            if (NEEDS_ONBOARDING) {
                startOnboarding(false);
            }
        });
        setTimeout(startPolling, 500);
    </script>
</body>
</html>'''

# PWA Manifest
def get_manifest_json():
    return json.dumps({
        "name": "DeQ",
        "short_name": "DeQ",
        "description": "Homelab Dashboard",
        "start_url": "/",
        "display": "standalone",
        "background_color": "#0a0a0a",
        "theme_color": "#0a0a0a",
        "orientation": "any",
        "icons": [
            {"src": "/icon.svg", "sizes": "any", "type": "image/svg+xml", "purpose": "any maskable"}
        ]
    })

# Icon
def get_icon_svg():
    return '''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">
  <rect width="512" height="512" fill="#0a0a0a"/>
  <!-- D -->
  <path d="M80 80 L210 80 Q230 80 230 100 L230 412 Q230 432 210 432 L80 432 Z" fill="none" stroke="#e0e0e0" stroke-width="16"/>
  <!-- e -->
  <path d="M430 155 L432 100 Q432 80 412 80 L302 80 Q282 80 282 100 L282 210 Q282 230 302 230 L430 230" fill="none" stroke="#e0e0e0" stroke-width="16" stroke-linecap="round"/>
  <line x1="400" y1="155" x2="428" y2="155" stroke="#e0e0e0" stroke-width="16" stroke-linecap="round"/>
  <!-- Q -->
  <path d="M432 380 L432 302 Q432 282 412 282 L302 282 Q282 282 282 302 L282 412 Q282 432 302 432 L380 432" fill="none" stroke="#2ed573" stroke-width="16" stroke-linecap="round"/>
  <line x1="405" y1="405" x2="435" y2="435" stroke="#2ed573" stroke-width="16" stroke-linecap="round"/>
</svg>'''

if __name__ == '__main__':
    main()
