#!/usr/bin/env python3
"""
DeQ - Homelab Admin Dashboard
Control devices, view stats, manage links and files - all in one place.
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
from datetime import datetime, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
# === CONFIGURATION ===
DEFAULT_PORT = 5050
DATA_DIR = "/opt/deq"
CONFIG_FILE = f"{DATA_DIR}/config.json"
HISTORY_DIR = f"{DATA_DIR}/history"
VERSION = "0.9.3"

# === DEFAULT CONFIG ===
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
        "accent_color": "#2ed573"
    },
    "links": [],
    "devices": [],
    "tasks": []
}

# === DATA MANAGEMENT ===
TASK_LOGS_DIR = f"{DATA_DIR}/task-logs"

def ensure_dirs():
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(HISTORY_DIR, exist_ok=True)
    os.makedirs(TASK_LOGS_DIR, exist_ok=True)

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            cfg = json.load(f)
            # Merge with defaults for missing keys
            for key in DEFAULT_CONFIG:
                if key not in cfg:
                    cfg[key] = DEFAULT_CONFIG[key]
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

ensure_dirs()
CONFIG = load_config()

# === HISTORY MANAGEMENT ===
def get_history_file(device_id):
    return f"{HISTORY_DIR}/{device_id}.json"

def load_history(device_id):
    path = get_history_file(device_id)
    if os.path.exists(path):
        with open(path, 'r') as f:
            return json.load(f)
    return {}

def save_history(device_id, history):
    # Keep only last 400 days
    cutoff = (datetime.now() - timedelta(days=400)).strftime("%Y-%m-%d")
    history = {k: v for k, v in history.items() if k >= cutoff}
    with open(get_history_file(device_id), 'w') as f:
        json.dump(history, f)

def record_stats(device_id, cpu, temp):
    history = load_history(device_id)
    today = datetime.now().strftime("%Y-%m-%d")
    hour = datetime.now().hour

    if today not in history:
        history[today] = {"hourly": {}, "totals": {"samples": 0, "cpu_sum": 0, "temp_max": 0}}

    # Record hourly (keep latest per hour)
    history[today]["hourly"][str(hour)] = {"cpu": cpu, "temp": temp}

    # Update totals
    history[today]["totals"]["samples"] += 1
    history[today]["totals"]["cpu_sum"] += cpu
    history[today]["totals"]["temp_max"] = max(history[today]["totals"].get("temp_max", 0), temp or 0)

    save_history(device_id, history)

# === SYSTEM STATS (LOCAL) ===
def get_local_stats():
    """Get stats for the device running DeQ."""
    stats = {"cpu": 0, "ram_used": 0, "ram_total": 0, "temp": None, "disks": [], "uptime": ""}
    
    try:
        # CPU load (1 min average)
        with open('/proc/loadavg', 'r') as f:
            load = float(f.read().split()[0])
            # Get CPU count for percentage
            cpu_count = os.cpu_count() or 1
            stats["cpu"] = min(100, int(load / cpu_count * 100))
        
        # RAM
        with open('/proc/meminfo', 'r') as f:
            meminfo = {}
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    meminfo[parts[0].rstrip(':')] = int(parts[1]) * 1024  # KB to bytes
            stats["ram_total"] = meminfo.get("MemTotal", 0)
            stats["ram_used"] = stats["ram_total"] - meminfo.get("MemAvailable", 0)
        
        # Temperature
        thermal_zones = ["/sys/class/thermal/thermal_zone0/temp"]
        for zone in thermal_zones:
            if os.path.exists(zone):
                with open(zone, 'r') as f:
                    stats["temp"] = int(f.read().strip()) // 1000
                break
        
        # Disks
        result = subprocess.run(["df", "-B1", "--output=target,size,used"],
                                capture_output=True, text=True, timeout=5)
        for line in result.stdout.strip().split('\n')[1:]:
            parts = line.split()
            if len(parts) >= 3 and parts[0] in ['/', '/home', '/mnt', '/media']:
                if int(parts[1]) > 1e9:  # Only show disks > 1GB
                    stats["disks"].append({
                        "mount": parts[0],
                        "total": int(parts[1]),
                        "used": int(parts[2])
                    })
        
        # Uptime
        with open('/proc/uptime', 'r') as f:
            uptime_seconds = float(f.read().split()[0])
            days = int(uptime_seconds // 86400)
            hours = int((uptime_seconds % 86400) // 3600)
            if days > 0:
                stats["uptime"] = f"{days}d {hours}h"
            else:
                stats["uptime"] = f"{hours}h"
    except Exception as e:
        print(f"Error getting local stats: {e}")
    
    return stats

# === REMOTE STATS (SSH) ===
def get_remote_stats(ip, user, port=22):
    """Get stats from remote device via SSH."""
    try:
        # Get more meminfo lines for Synology compatibility (no MemAvailable)
        cmd = "cat /proc/loadavg; echo '---'; cat /proc/meminfo | head -10; echo '---'; cat /sys/class/thermal/thermal_zone*/temp 2>/dev/null | head -1; echo '---'; df -B1 / | tail -1; echo '---'; cat /proc/uptime; echo '---'; nproc --all"
        result = subprocess.run(
            ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=3",
             "-p", str(port), f"{user}@{ip}", cmd],
            capture_output=True, text=True, timeout=10
        )

        if result.returncode != 0:
            return None

        parts = result.stdout.split('---')
        stats = {"cpu": 0, "ram_used": 0, "ram_total": 0, "temp": None, "disks": [], "uptime": ""}

        # CPU (load / cpu_count * 100)
        load = float(parts[0].strip().split()[0])
        try:
            remote_cpu_count = int(parts[-1].strip())
            cpu_count = remote_cpu_count if remote_cpu_count > 0 else 4 # Fallback to 4 if error
        except ValueError:
            cpu_count = 4 # Default fallback        
            
        stats["cpu"] = min(100, int(load / cpu_count * 100))

        # RAM - handle both modern (MemAvailable) and older kernels (MemFree+Buffers+Cached)
        meminfo = {}
        for line in parts[1].strip().split('\n'):
            if ':' in line:
                key, val = line.split(':')
                meminfo[key.strip()] = int(val.split()[0]) * 1024  # kB to bytes

        stats["ram_total"] = meminfo.get("MemTotal", 0)
        if "MemAvailable" in meminfo:
            stats["ram_used"] = stats["ram_total"] - meminfo["MemAvailable"]
        else:
            # Fallback for older kernels (Synology): Free + Buffers + Cached
            free = meminfo.get("MemFree", 0) + meminfo.get("Buffers", 0) + meminfo.get("Cached", 0)
            stats["ram_used"] = stats["ram_total"] - free

        # Temp
        temp_str = parts[2].strip()
        if temp_str.isdigit():
            stats["temp"] = int(temp_str) // 1000
        
        # Disk
        disk_parts = parts[3].strip().split()
        if len(disk_parts) >= 3:
            stats["disks"].append({
                "mount": "/",
                "total": int(disk_parts[1]),
                "used": int(disk_parts[2])
            })
        
        # Uptime
        uptime_seconds = float(parts[4].strip().split()[0])
        days = int(uptime_seconds // 86400)
        hours = int((uptime_seconds % 86400) // 3600)
        stats["uptime"] = f"{days}d {hours}h" if days > 0 else f"{hours}h"
        
        return stats
    except Exception as e:
        print(f"Error getting remote stats: {e}")
        return None

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
                ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
                 "-p", str(port), f"{user}@{ip}", cmd],
                capture_output=True, text=True, timeout=15
            )

            if result.returncode != 0 and not result.stdout:
                # Check if path exists
                check_cmd = f"test -d '{path}' && echo 'exists' || echo 'notfound'"
                check_result = subprocess.run(
                    ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
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
                ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
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
                    import calendar
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
                        ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
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
                ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
                 "-p", str(port), f"{user}@{ip}", cmd],
                capture_output=True, text=True, timeout=300
            )
            return result.returncode == 0, result.stderr

        run_cmd = run_local if is_host else run_remote

        if operation == 'delete':
            for p in paths:
                safe_path = p.replace("'", "'\\''")
                success, err = run_cmd(f"rm -rf '{safe_path}'")
                if not success:
                    return {"success": False, "error": f"Failed to delete {p}: {err}"}
            return {"success": True}

        elif operation == 'rename':
            if len(paths) != 1 or not new_name:
                return {"success": False, "error": "Rename requires exactly one file and new name"}
            old_path = paths[0].replace("'", "'\\''")
            parent = '/'.join(paths[0].rstrip('/').split('/')[:-1]) or '/'
            new_path = f"{parent}/{new_name}".replace("'", "'\\''")
            success, err = run_cmd(f"mv '{old_path}' '{new_path}'")
            if not success:
                return {"success": False, "error": f"Failed to rename: {err}"}
            return {"success": True}

        elif operation == 'mkdir':
            if not new_name:
                return {"success": False, "error": "Folder name required"}
            if '/' in new_name or '\x00' in new_name:
                return {"success": False, "error": "Invalid folder name"}
            parent = paths[0] if paths else '/'
            folder_path = f"{parent.rstrip('/')}/{new_name}".replace("'", "'\\''")
            success, err = run_cmd(f"mkdir '{folder_path}'")
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
                    ["ssh", "-o", "StrictHostKeyChecking=no", "-p", str(port), f"{user}@{ip}", check_zip],
                    capture_output=True, text=True, timeout=10
                )
                use_zip = 'zip' in result.stdout

            if len(paths) == 1:
                archive_name = f"{base_name}.zip" if use_zip else f"{base_name}.tar.gz"
            else:
                archive_name = f"archive_{int(time.time())}.zip" if use_zip else f"archive_{int(time.time())}.tar.gz"

            archive_path = f"{parent}/{archive_name}"

            # Build file list for command
            file_args = ' '.join([f"'{p.replace(chr(39), chr(39)+chr(92)+chr(39)+chr(39))}'" for p in paths])

            if use_zip:
                # For zip, we need to be in parent dir and use relative paths
                rel_names = ' '.join([f"'{p.split('/')[-1]}'" for p in paths])
                cmd = f"cd '{parent}' && zip -r '{archive_name}' {rel_names}"
            else:
                rel_names = ' '.join([f"'{p.split('/')[-1]}'" for p in paths])
                cmd = f"cd '{parent}' && tar -czf '{archive_name}' {rel_names}"

            success, err = run_cmd(cmd)
            if not success:
                return {"success": False, "error": f"Failed to create archive: {err}"}
            return {"success": True, "archive": archive_path}

        elif operation in ('copy', 'move'):
            if not dest_device or not dest_path:
                return {"success": False, "error": "Destination required"}

            dest_ssh = dest_device.get('ssh', {})
            dest_user = dest_ssh.get('user')
            dest_port = dest_ssh.get('port', 22)
            dest_ip = dest_device.get('ip')
            dest_is_host = dest_device.get('is_host', False)

            if not dest_is_host and not dest_user:
                return {"success": False, "error": "Destination SSH not configured"}

            for src_path in paths:
                safe_src = src_path.replace("'", "'\\''")
                safe_dest = dest_path.replace("'", "'\\''")

                # Determine rsync source and destination
                if is_host and dest_is_host:
                    # Local to local
                    rsync_cmd = f"rsync -a '{safe_src}' '{safe_dest}/'"
                    success, err = run_local(rsync_cmd)
                elif is_host and not dest_is_host:
                    # Local to remote
                    rsync_cmd = f"rsync -a -e 'ssh -o StrictHostKeyChecking=no -p {dest_port}' '{safe_src}' {dest_user}@{dest_ip}:'{safe_dest}/'"
                    success, err = run_local(rsync_cmd)
                elif not is_host and dest_is_host:
                    # Remote to local
                    rsync_cmd = f"rsync -a -e 'ssh -o StrictHostKeyChecking=no -p {port}' {user}@{ip}:'{safe_src}' '{safe_dest}/'"
                    success, err = run_local(rsync_cmd)
                else:
                    # Remote to remote - copy through host
                    # First copy to temp, then to dest
                    temp_path = f"/tmp/deq_transfer_{int(time.time())}"
                    rsync_cmd1 = f"rsync -a -e 'ssh -o StrictHostKeyChecking=no -p {port}' {user}@{ip}:'{safe_src}' '{temp_path}/'"
                    success, err = run_local(rsync_cmd1)
                    if success:
                        src_name = src_path.rstrip('/').split('/')[-1]
                        rsync_cmd2 = f"rsync -a -e 'ssh -o StrictHostKeyChecking=no -p {dest_port}' '{temp_path}/{src_name}' {dest_user}@{dest_ip}:'{safe_dest}/'"
                        success, err = run_local(rsync_cmd2)
                        run_local(f"rm -rf '{temp_path}'")

                if not success:
                    return {"success": False, "error": f"Failed to {operation} {src_path}: {err}"}

                # For move, delete source after successful copy
                if operation == 'move':
                    del_success, del_err = run_cmd(f"rm -rf '{safe_src}'")
                    if not del_success:
                        return {"success": False, "error": f"Copied but failed to delete source: {del_err}"}

            return {"success": True}

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
                ["ssh", "-o", "StrictHostKeyChecking=no", "-p", str(port),
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
            ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
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
                ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
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
            ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
             "-p", str(port), f"{user}@{ip}", "sudo", "shutdown", "-h", "now"],
            capture_output=True, text=True, timeout=30
        )
        return {"success": True}
    except subprocess.TimeoutExpired:
        return {"success": True}  # Expected - shutdown kills connection
    except Exception as e:
        return {"success": False, "error": str(e)}


# === HTML TEMPLATE ===
HTML_PAGE = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
    <meta name="mobile-web-app-capable" content="yes">
    <meta name="theme-color" content="#0a0a0f">
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
            --text-secondary: #8a8a8a;
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
            padding: 24px;
            font-size: 12px;
            line-height: 1.4;
        }
        
        .container {
            max-width: 800px;
            margin: 0 auto;
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

        #files-btn:hover,
        #edit-toggle:hover {
            background: var(--bg-secondary);
            color: var(--text-primary);
            border-color: var(--accent);
            box-shadow: 0 0 4px var(--accent);
        }

        .logo svg .icon-bg,
        #files-btn svg .icon-bg,
        #edit-toggle svg .icon-bg {
            fill: transparent;
        }

        .logo svg .icon-accent,
        #files-btn svg .icon-accent,
        #edit-toggle svg .icon-accent {
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

        .edit-mode .section-add,
        .edit-mode .section-add svg,
        .edit-mode .layout-btn {
            color: #fff;
        }

        .layout-btn {
            font-size: 12px;
            font-weight: 500;
            min-width: 36px;
        }

        /* Links */
        .links-grid {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
        }

        .links-grid.layout-1-4 {
            flex-direction: column;
            align-items: stretch;
        }

        .links-grid.layout-1-4 .link-item {
            justify-content: center;
        }

        .links-grid.layout-2-4 {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
        }

        .links-grid.layout-2-4 .link-item,
        .links-grid.layout-4-4 .link-item {
            min-width: 0;
            width: 100%;
        }

        .links-grid.layout-4-4 {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
        }

        .edit-mode .links-grid.layout-2-4,
        .edit-mode .links-grid.layout-4-4 {
            overflow: visible;
            padding-top: 12px;
            padding-right: 12px;
        }

        .links-grid.layout-2-4 .link-name,
        .links-grid.layout-4-4 .link-name {
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            flex: 1;
            min-width: 0;
        }

        @media (max-width: 768px) {
            .links-grid.layout-4-4 {
                grid-template-columns: repeat(2, 1fr);
            }
        }
        
        .link-item {
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
        
        .link-item:hover {
            border-color: var(--accent);
            background: var(--bg-tertiary);
        }

        .edit-mode .link-item {
            cursor: grab;
        }

        .edit-mode .link-item.dragging {
            opacity: 0.5;
            cursor: grabbing;
        }

        .edit-mode .link-item.drag-over {
            border-color: var(--accent);
            box-shadow: inset 0 0 0 2px var(--accent);
            transform: scale(1.02);
        }
        
        .link-item svg,
        .link-item .custom-icon {
            width: 22px;
            height: 22px;
            color: var(--text-secondary);
            object-fit: contain;
        }

        .icons-mono .custom-icon {
            filter: grayscale(1) brightness(0.7) contrast(1.2);
        }

        .link-text {
            display: flex;
            flex-direction: column;
            min-width: 0;
            flex: 1;
        }

        .link-name {
            font-size: 12px;
            line-height: 1.2;
        }

        .link-note {
            font-size: 10px;
            line-height: 1.2;
            color: var(--text-secondary);
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        /* Edit/Delete buttons (shared) */
        .link-edit, .link-delete,
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

        .link-edit, .task-edit, .device-edit {
            right: 28px;
            background: var(--accent-muted);
        }

        .link-delete, .task-delete, .device-delete {
            right: -10px;
            background: var(--danger-muted);
        }

        .edit-mode .link-edit, .edit-mode .link-delete,
        .edit-mode .task-edit, .edit-mode .task-delete,
        .edit-mode .device-edit, .edit-mode .device-delete {
            display: flex;
        }

        .link-edit svg, .task-edit svg, .device-edit svg {
            width: 16px;
            height: 16px;
            color: white;
        }

        .link-delete svg, .task-delete svg, .device-delete svg {
            width: 12px;
            height: 12px;
            color: white;
        }
        
        /* Devices */
        .device-card {
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 16px;
            margin-bottom: 12px;
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
        .task-card {
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 12px;
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

        .task-btn:hover {
            border-color: var(--text-secondary);
            color: var(--text-primary);
        }

        .task-btn.danger:hover {
            border-color: var(--danger);
            color: var(--danger);
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

        /* History chart */
        .device-chart {
            height: 32px;
            display: flex;
            align-items: flex-end;
            gap: 2px;
            margin-bottom: 8px;
        }
        
        .chart-bar {
            flex: 1;
            background: var(--accent);
            opacity: 0.6;
            border-radius: 2px 2px 0 0;
            min-height: 2px;
        }
        
        .chart-bar:hover {
            opacity: 1;
        }
        
        .device-chart-footer {
            display: flex;
            justify-content: space-between;
            font-size: 11px;
            color: var(--text-secondary);
            margin-bottom: 12px;
        }
        
        .chart-period-select {
            background: none;
            border: none;
            color: var(--text-secondary);
            font-family: inherit;
            font-size: 11px;
            cursor: pointer;
        }
        
        .chart-period-select:hover {
            color: var(--text-primary);
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
            border-top: 1px solid var(--border);
            margin-top: 12px;
            padding-top: 12px;
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

        body.has-wallpaper .link-item,
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
            padding: 24px;
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
            max-width: 500px;
            max-height: 80vh;
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
            word-break: break-all;
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

        .fm-pane-header select {
            width: 100%;
            margin-bottom: 8px;
        }

        .fm-storage {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 11px;
            color: var(--text-secondary);
            margin-bottom: 6px;
        }

        .fm-storage-text {
            white-space: nowrap;
        }

        .fm-storage-bar {
            flex: 1;
            height: 6px;
            background: var(--bg-primary);
            border-radius: 3px;
            overflow: hidden;
            max-width: 80px;
        }

        .fm-storage-fill {
            height: 100%;
            border-radius: 3px;
            transition: width 0.3s ease;
        }

        .fm-storage-percent {
            min-width: 32px;
            text-align: right;
        }

        .fm-path {
            font-family: monospace;
            font-size: 11px;
            color: var(--text-secondary);
            word-break: break-all;
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
            font-size: 12px;
            cursor: pointer;
            transition: all 0.15s;
            position: relative;
            z-index: 1;
        }

        @media (hover: hover) {
            .fm-btn:hover:not(:disabled) {
                background: var(--accent);
                border-color: var(--accent);
                color: var(--bg-primary);
            }
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

        @media (hover: hover) {
            .fm-btn.danger:hover:not(:disabled) {
                background: var(--danger);
                border-color: var(--danger);
            }
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

            .fm-pane-header select {
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
                font-size: 11px;
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
            padding: 10px 16px;
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
        
        .btn-danger {
            background: var(--danger);
        }
        
        .modal-actions {
            display: flex;
            gap: 8px;
            justify-content: flex-end;
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
            <a href="https://deq.rocks" target="_blank" rel="noopener" class="logo"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">
  <rect class="icon-bg" width="512" height="512" rx="96"/>
  <path d="M80 80 L210 80 Q230 80 230 100 L230 412 Q230 432 210 432 L80 432 Z" fill="none" stroke="currentColor" stroke-width="16"/>
  <path d="M430 155 L432 100 Q432 80 412 80 L302 80 Q282 80 282 100 L282 210 Q282 230 302 230 L430 230" fill="none" stroke="currentColor" stroke-width="16" stroke-linecap="round"/>
  <line x1="400" y1="155" x2="428" y2="155" stroke="currentColor" stroke-width="16" stroke-linecap="round"/>
  <path class="icon-accent" d="M432 380 L432 302 Q432 282 412 282 L302 282 Q282 282 282 302 L282 412 Q282 432 302 432 L380 432" fill="none" stroke-width="16" stroke-linecap="round"/>
  <line class="icon-accent" x1="405" y1="405" x2="435" y2="435" stroke-width="16" stroke-linecap="round"/>
</svg></a>
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
            </div>
        </header>

        <!-- Links -->
        <section class="section" id="links-section">
            <div class="section-header">
                <div class="section-header-left">
                    <span class="section-title">Links</span>
                    <button class="icon-btn section-add section-toggle" id="links-toggle" title="Hide section" onclick="toggleSection('links')">
                        <i data-lucide="eye-off"></i>
                    </button>
                    <button class="icon-btn section-add layout-btn" id="link-layout-btn" title="Change layout" onclick="cycleLinkLayout()">
                        <span id="link-layout-label">eco</span>
                    </button>
                    <button class="icon-btn section-add" id="mono-toggle" title="Toggle monochrome icons" onclick="toggleMonochrome()">
                        <i data-lucide="palette"></i>
                    </button>
                </div>
                <button class="icon-btn section-add" id="add-link" title="Add link">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <line x1="12" y1="5" x2="12" y2="19"></line>
                        <line x1="5" y1="12" x2="19" y2="12"></line>
                    </svg>
                </button>
            </div>
            <div class="links-grid" id="links-grid"></div>
        </section>

        <!-- Devices -->
        <section class="section" id="devices-section">
            <div class="section-header">
                <div class="section-header-left">
                    <span class="section-title">Devices</span>
                    <button class="icon-btn section-add section-toggle" id="devices-toggle" title="Hide section" onclick="toggleSection('devices')">
                        <i data-lucide="eye-off"></i>
                    </button>
                </div>
                <button class="icon-btn section-add" id="add-device" title="Add device">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <line x1="12" y1="5" x2="12" y2="19"></line>
                        <line x1="5" y1="12" x2="19" y2="12"></line>
                    </svg>
                </button>
            </div>
            <div id="devices-list"></div>
        </section>

        <!-- Tasks Section -->
        <section class="section" id="tasks-section">
            <div class="section-header">
                <div class="section-header-left">
                    <span class="section-title">Scheduled Tasks</span>
                    <button class="icon-btn section-add section-toggle" id="tasks-toggle" title="Hide section" onclick="toggleSection('tasks')">
                        <i data-lucide="eye-off"></i>
                    </button>
                </div>
                <button class="icon-btn section-add task-add" onclick="openTaskWizard()" title="Add task">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <line x1="12" y1="5" x2="12" y2="19"></line>
                        <line x1="5" y1="12" x2="19" y2="12"></line>
                    </svg>
                </button>
            </div>
            <div id="tasks-list"></div>
        </section>

        <!-- Theme Section (edit mode only) -->
        <section class="section theme-section" id="theme-section">
            <div class="section-header">
                <span class="section-title">Theme</span>
            </div>
            <div class="theme-grid">
                <div class="theme-group">
                    <label class="theme-label">Background</label>
                    <div class="theme-color-input">
                        <input type="color" id="theme-bg" value="#0a0a0f">
                        <input type="text" class="theme-hex" id="theme-bg-hex" value="#0a0a0f" maxlength="7">
                    </div>
                </div>
                <div class="theme-group">
                    <label class="theme-label">Cards</label>
                    <div class="theme-color-input">
                        <input type="color" id="theme-cards" value="#12121a">
                        <input type="text" class="theme-hex" id="theme-cards-hex" value="#12121a" maxlength="7">
                    </div>
                </div>
                <div class="theme-group">
                    <label class="theme-label">Border</label>
                    <div class="theme-color-input">
                        <input type="color" id="theme-border" value="#2a2a3a">
                        <input type="text" class="theme-hex" id="theme-border-hex" value="#2a2a3a" maxlength="7">
                    </div>
                </div>
                <div class="theme-group">
                    <label class="theme-label">Text</label>
                    <div class="theme-color-input">
                        <input type="color" id="theme-text" value="#e0e0e0">
                        <input type="text" class="theme-hex" id="theme-text-hex" value="#e0e0e0" maxlength="7">
                    </div>
                </div>
                <div class="theme-group">
                    <label class="theme-label">Text Muted</label>
                    <div class="theme-color-input">
                        <input type="color" id="theme-text-muted" value="#808090">
                        <input type="text" class="theme-hex" id="theme-text-muted-hex" value="#808090" maxlength="7">
                    </div>
                </div>
                <div class="theme-group">
                    <label class="theme-label">Accent</label>
                    <div class="theme-color-input">
                        <input type="color" id="theme-accent" value="#2ed573">
                        <input type="text" class="theme-hex" id="theme-accent-hex" value="#2ed573" maxlength="7">
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
                <button class="modal-close" onclick="closeModal('link-modal')">
                    <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2">
                        <line x1="18" y1="6" x2="6" y2="18"></line>
                        <line x1="6" y1="6" x2="18" y2="18"></line>
                    </svg>
                </button>
            </div>
            <form id="link-form">
                <input type="hidden" id="link-id">
                <div class="form-group">
                    <label class="form-label">Name</label>
                    <input type="text" class="form-input" id="link-name" required>
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
                    <input type="text" class="form-input" id="link-note" placeholder="Optional, e.g. Runs on NAS">
                </div>
                <div class="modal-actions">
                    <button type="button" class="btn btn-secondary" onclick="closeModal('link-modal')">Cancel</button>
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
                    <button class="modal-close" onclick="closeModal('device-modal')">
                        <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2">
                            <line x1="18" y1="6" x2="6" y2="18"></line>
                            <line x1="6" y1="6" x2="18" y2="18"></line>
                        </svg>
                    </button>
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
                <button class="modal-close" onclick="closeModal('task-modal')">
                    <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2">
                        <line x1="18" y1="6" x2="6" y2="18"></line>
                        <line x1="6" y1="6" x2="18" y2="18"></line>
                    </svg>
                </button>
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
                                    <strong>Wake</strong>
                                    <small>Power on or start</small>
                                </span>
                            </label>
                            <label class="task-type-option">
                                <input type="radio" name="task-action" value="shutdown">
                                <span class="task-type-label">
                                    <i data-lucide="power-off"></i>
                                    <strong>Shutdown</strong>
                                    <small>Power off or stop</small>
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
                        <div class="form-section-title">What do you want to <span id="step2-action">wake</span>?</div>
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
            </form>
        </div>
    </div>

    <!-- File Manager Modal -->
    <div class="modal fm-fullscreen" id="fm-modal">
        <div class="modal-content fm-modal">
            <div class="modal-header">
                <span class="modal-title">File Manager</span>
                <button class="modal-close" onclick="closeModal('fm-modal')">
                    <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2">
                        <line x1="18" y1="6" x2="6" y2="18"></line>
                        <line x1="6" y1="6" x2="18" y2="18"></line>
                    </svg>
                </button>
            </div>
            <div class="fm-container">
                <div class="fm-pane" id="fm-left">
                    <div class="fm-pane-header">
                        <select class="form-input" id="fm-left-device" onchange="fmLoadFiles('left')"></select>
                        <div class="fm-storage" id="fm-left-storage"></div>
                        <div class="fm-path" id="fm-left-path">/</div>
                    </div>
                    <div class="fm-list" id="fm-left-list"></div>
                </div>
                <div class="fm-pane" id="fm-right">
                    <div class="fm-pane-header">
                        <select class="form-input" id="fm-right-device" onchange="fmLoadFiles('right')"></select>
                        <div class="fm-storage" id="fm-right-storage"></div>
                        <div class="fm-path" id="fm-right-path">/</div>
                    </div>
                    <div class="fm-list" id="fm-right-list"></div>
                </div>
            </div>
            <div class="fm-actions">
                <button class="fm-btn" id="fm-copy-right" onclick="fmCopy('left', 'right')" disabled>Copy →</button>
                <button class="fm-btn" id="fm-copy-left" onclick="fmCopy('right', 'left')" disabled>← Copy</button>
                <button class="fm-btn" id="fm-move-right" onclick="fmMove('left', 'right')" disabled>Move →</button>
                <button class="fm-btn" id="fm-move-left" onclick="fmMove('right', 'left')" disabled>← Move</button>
                <button class="fm-btn" id="fm-newfolder" onclick="fmNewFolder()" disabled>New Folder</button>
                <button class="fm-btn" id="fm-rename" onclick="fmRename()" disabled>Rename</button>
                <button class="fm-btn danger" id="fm-delete" onclick="fmDelete()" disabled>Delete</button>
                <button class="fm-btn" id="fm-zip" onclick="fmZip()" disabled>Zip</button>
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

    <script>
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
        function toggleStatsMode(el) {
            showValues = !showValues;
            document.querySelectorAll('.device-stats-bars').forEach(bars => {
                bars.classList.toggle('show-values', showValues);
            });
        }

        // === Render Functions ===
        const LINK_LAYOUTS = ['eco', '1/4', '2/4', '4/4'];

        function applyLinkLayout() {
            const grid = document.getElementById('links-grid');
            const layout = config.settings.link_layout || 'eco';
            const label = document.getElementById('link-layout-label');

            // Remove all layout classes
            grid.classList.remove('layout-1-4', 'layout-2-4', 'layout-4-4');

            // Apply current layout
            if (layout === '1/4') grid.classList.add('layout-1-4');
            else if (layout === '2/4') grid.classList.add('layout-2-4');
            else if (layout === '4/4') grid.classList.add('layout-4-4');

            if (label) label.textContent = layout;
        }

        function cycleLinkLayout() {
            const current = config.settings.link_layout || 'eco';
            const idx = LINK_LAYOUTS.indexOf(current);
            const next = LINK_LAYOUTS[(idx + 1) % LINK_LAYOUTS.length];
            config.settings.link_layout = next;
            applyLinkLayout();
            saveConfig();
        }

        function toggleSection(section) {
            const key = `show_${section}`;
            const current = config.settings[key] !== false; // default true
            config.settings[key] = !current;
            applySectionVisibility();
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
            textMuted: '#808090',
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
            const showLinks = config.settings.show_links !== false;
            const showDevices = config.settings.show_devices !== false;
            const showTasks = config.settings.show_tasks !== false;

            const linksSection = document.getElementById('links-section');
            const devicesSection = document.getElementById('devices-section');
            const tasksSection = document.getElementById('tasks-section');

            // Hidden sections: collapsed with only header visible in edit mode
            linksSection.classList.toggle('section-hidden', !showLinks);
            devicesSection.classList.toggle('section-hidden', !showDevices);
            tasksSection.classList.toggle('section-hidden', !showTasks);

            // Update toggle icons
            const linksToggle = document.getElementById('links-toggle');
            const devicesToggle = document.getElementById('devices-toggle');
            const tasksToggle = document.getElementById('tasks-toggle');
            if (linksToggle) linksToggle.innerHTML = showLinks ? '<i data-lucide="eye-off"></i>' : '<i data-lucide="eye"></i>';
            if (devicesToggle) devicesToggle.innerHTML = showDevices ? '<i data-lucide="eye-off"></i>' : '<i data-lucide="eye"></i>';
            if (tasksToggle) tasksToggle.innerHTML = showTasks ? '<i data-lucide="eye-off"></i>' : '<i data-lucide="eye"></i>';
            refreshIcons();
        }

        function renderLinks() {
            const grid = document.getElementById('links-grid');
            grid.innerHTML = config.links.map(link => `
                <a href="${link.url}" target="_blank" class="link-item" data-id="${link.id}"
                   draggable="true" ondragstart="linkDragStart(event)" ondragover="linkDragOver(event)" ondragleave="linkDragLeave(event)" ondrop="linkDrop(event)" ondragend="linkDragEnd(event)">
                    ${getIcon(link.icon || 'link')}
                    <div class="link-text">
                        <span class="link-name">${link.name}</span>
                        ${link.note ? `<span class="link-note">${link.note}</span>` : ''}
                    </div>
                    <div class="link-edit" onclick="event.preventDefault(); editLink('${link.id}')">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M17 3a2.85 2.83 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5Z"></path>
                            <path d="m15 5 4 4"></path>
                        </svg>
                    </div>
                    <div class="link-delete" onclick="event.preventDefault(); deleteLink('${link.id}')">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <line x1="20" y1="4" x2="4" y2="20"></line>
                            <line x1="4" y1="4" x2="20" y2="20"></line>
                        </svg>
                    </div>
                </a>
            `).join('');
            applyLinkLayout();
            refreshIcons();
        }

        let draggedLinkId = null;

        function linkDragStart(e) {
            if (!document.body.classList.contains('edit-mode')) {
                e.preventDefault();
                return;
            }
            draggedLinkId = e.target.closest('.link-item').dataset.id;
            e.target.closest('.link-item').classList.add('dragging');
            e.dataTransfer.effectAllowed = 'move';
        }

        function linkDragOver(e) {
            if (!draggedLinkId) return;
            e.preventDefault();
            const target = e.target.closest('.link-item');
            if (target && target.dataset.id !== draggedLinkId) {
                target.classList.add('drag-over');
            }
        }

        function linkDragLeave(e) {
            const target = e.target.closest('.link-item');
            if (target) target.classList.remove('drag-over');
        }

        function linkDrop(e) {
            e.preventDefault();
            const target = e.target.closest('.link-item');
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
            document.querySelectorAll('.link-item').forEach(el => {
                el.classList.remove('dragging', 'drag-over');
            });
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

        function editLink(id) {
            const link = config.links.find(l => l.id === id);
            if (link) openLinkModal(link);
        }

        function renderDevices() {
            const list = document.getElementById('devices-list');
            
            list.innerHTML = config.devices.map(dev => {
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
                // Host can always shutdown, remote devices need SSH
                if (isHost || dev.ssh?.user) actions.push(`<button class="device-action danger" onclick="event.stopPropagation(); doShutdown('${dev.id}')" ${!online ? 'disabled' : ''}>Shutdown</button>`);

                // Docker containers section
                const containers = dev.docker?.containers || [];
                let containersHtml = '';
                if (containers.length > 0) {
                    containersHtml = `
                        <div class="device-containers">
                            ${containers.map(c => {
                                const cName = c.name;
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
                    `;
                }

                // RAM percentage for bar
                const ramPercent = s.ram_total ? Math.round(s.ram_used / s.ram_total * 100) : 0;

                return `
                <div class="device-card" data-id="${dev.id}" draggable="true" ondragstart="deviceDragStart(event)" ondragover="deviceDragOver(event)" ondragleave="deviceDragLeave(event)" ondrop="deviceDrop(event)" ondragend="deviceDragEnd(event)">
                    <div class="device-header">
                        <div class="device-info">
                            <div class="device-icon">${getIcon(dev.icon || 'server')}</div>
                            <span class="device-name">${dev.name}</span>
                            <span class="device-status-indicator">
                                <span class="status-dot ${online === undefined ? 'loading' : (online ? 'online' : 'offline')}"></span>
                                ${s.uptime ? `<span class="device-uptime">${s.uptime}</span>` : ''}
                            </span>
                        </div>
                    </div>
                    ${online && (s.cpu !== undefined) ? `
                        <div class="device-stats-bars" onclick="toggleStatsMode(this)">
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
                        </div>
                    ` : ''}
                    ${actions.length ? `
                        <div class="device-actions">
                            ${actions.join('<span class="action-separator">·</span>')}
                        </div>
                    ` : ''}
                    ${containersHtml}
                    <div class="device-edit" onclick="editDevice('${dev.id}')">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M17 3a2.85 2.83 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5Z"></path>
                            <path d="m15 5 4 4"></path>
                        </svg>
                    </div>
                    ${!isHost ? `<div class="device-delete" onclick="deleteDevice('${dev.id}')">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <line x1="20" y1="4" x2="4" y2="20"></line>
                            <line x1="4" y1="4" x2="20" y2="20"></line>
                        </svg>
                    </div>` : ''}
                </div>
                `;
            }).join('');
            refreshIcons();
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
            if (!confirm('Shutdown this device?')) return;
            const res = await api(`device/${id}/shutdown`);
            if (res.success) {
                toast('Shutdown command sent');
                setTimeout(loadDeviceStatus, 5000);
            } else {
                toast(res.error || 'Failed', 'error');
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

        async function saveLink(e) {
            e.preventDefault();
            const id = document.getElementById('link-id').value || generateUUID();
            const note = document.getElementById('link-note').value.trim();
            const link = {
                id,
                name: document.getElementById('link-name').value,
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
            toast('Link saved');
        }
        
        async function deleteLink(id) {
            if (!confirm('Delete this link?')) return;
            config.links = config.links.filter(l => l.id !== id);
            await api('config', 'POST', config);
            renderLinks();
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
            document.getElementById('link-name').value = link?.name || '';
            document.getElementById('link-url').value = link?.url || '';
            document.getElementById('link-icon').value = link?.icon || '';
            document.getElementById('link-note').value = link?.note || '';
            openModal('link-modal');
        }
        
        function addContainerRow(container = null) {
            const list = document.getElementById('device-containers-list');
            const row = document.createElement('div');
            row.className = 'container-form-row';
            row.innerHTML = `
                <input type="text" class="form-input container-name" placeholder="Name" value="${container?.name || ''}">
                <input type="text" class="form-input container-rdp" placeholder="RDP" value="${container?.rdp || ''}" style="max-width: 100px;">
                <input type="text" class="form-input container-vnc" placeholder="VNC" value="${container?.vnc || ''}" style="max-width: 100px;">
                <input type="text" class="form-input container-web" placeholder="Web URL" value="${container?.web || ''}">
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
        
        // === Tasks ===
        let wizardStep = 1;

        function renderTasks() {
            const list = document.getElementById('tasks-list');
            const tasks = config.tasks || [];

            if (tasks.length === 0) {
                list.innerHTML = '<div class="task-empty">No tasks configured. Click + to add one.</div>';
                return;
            }

            list.innerHTML = tasks.map(task => {
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
                                 task.type === 'shutdown' ? 'power-off' : 'power';

                return `
                <div class="task-card ${isRunning ? 'running' : ''}" data-id="${task.id}">
                    <div class="task-header">
                        <div class="task-icon">${getIcon(typeIcon)}</div>
                        <span class="task-name">${task.name}</span>
                        <span class="task-schedule">${scheduleText}</span>
                    </div>
                    <div class="task-status">
                        <span class="task-status-dot ${statusClass}"></span>
                        <span>${statusText}</span>
                        ${task.last_run ? `<span style="margin-left: auto;">${lastStatusText}${lastStatusText ? ' · ' : ''}${formatLastRun(task.last_run)}${task.last_size ? ' · ' + task.last_size : ''}</span>` : ''}
                    </div>
                    <div class="task-actions">
                        <button class="task-btn" onclick="toggleTask('${task.id}')" ${isRunning ? 'disabled' : ''}>
                            ${task.enabled ? '⏸ Pause' : '▶ Resume'}
                        </button>
                        <button class="task-btn" onclick="runTaskNow('${task.id}')" ${isRunning ? 'disabled' : ''}>
                            ${isRunning ? 'Running...' : '▷ Run Now'}
                        </button>
                    </div>
                    <div class="task-edit" onclick="editTask('${task.id}')">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M17 3a2.85 2.83 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5Z"></path>
                        </svg>
                    </div>
                    <div class="task-delete" onclick="deleteTask('${task.id}')">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <line x1="20" y1="4" x2="4" y2="20"></line>
                            <line x1="4" y1="4" x2="20" y2="20"></line>
                        </svg>
                    </div>
                </div>
                `;
            }).join('');
            refreshIcons();
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

            // Same day
            if (date.toDateString() === now.toDateString()) {
                return time;
            }

            // Yesterday
            const yesterday = new Date(now);
            yesterday.setDate(yesterday.getDate() - 1);
            if (date.toDateString() === yesterday.toDateString()) {
                return `Yesterday ${time}`;
            }

            // Older - show date
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
                    containers.push({ name: c.name, device: dev.name, deviceId: dev.id });
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

        function openFileManager() {
            // Populate device dropdowns (devices with SSH or host)
            const sshDevices = config.devices.filter(d => d.ssh?.user || d.is_host);
            const options = sshDevices.map(d => `<option value="${d.id}">${d.name}</option>`).join('');

            document.getElementById('fm-left-device').innerHTML = options;
            document.getElementById('fm-right-device').innerHTML = options;

            // Set different defaults if possible
            if (sshDevices.length > 1) {
                document.getElementById('fm-right-device').selectedIndex = 1;
            }

            // Reset state
            fmState.left = { device: null, path: '/', files: [], selected: new Set() };
            fmState.right = { device: null, path: '/', files: [], selected: new Set() };
            fmState.busy = false;

            openModal('fm-modal');
            fmSetActivePane('left');
            refreshIcons();
            fmSetupDragDrop();

            // Load files for both panes
            fmLoadFiles('left');
            fmLoadFiles('right');
        }

        async function fmLoadFiles(pane) {
            const deviceId = document.getElementById(`fm-${pane}-device`).value;
            const state = fmState[pane];
            const listEl = document.getElementById(`fm-${pane}-list`);
            const pathEl = document.getElementById(`fm-${pane}-path`);

            state.device = deviceId;
            state.selected.clear();

            listEl.innerHTML = '<div class="fm-loading">Loading...</div>';
            pathEl.textContent = state.path;

            try {
                const res = await api(`device/${deviceId}/files?path=${encodeURIComponent(state.path)}`);
                if (res.success) {
                    state.files = res.files;
                    fmRenderList(pane);
                    fmUpdateStorage(pane, res.storage);
                } else {
                    listEl.innerHTML = `<div class="fm-error">${res.error}</div>`;
                    fmUpdateStorage(pane, null);
                }
            } catch (e) {
                listEl.innerHTML = '<div class="fm-error">Failed to load</div>';
                fmUpdateStorage(pane, null);
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
                    onclick="fmSelect('${pane}', ${idx})"
                    ondblclick="fmDblClick('${pane}', ${idx})">
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
                    return;
                }
            }

            // Otherwise show just the directory path
            pathEl.textContent = state.path;
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

            // Copy/Move: need selection on source side
            document.getElementById('fm-copy-right').disabled = leftSel === 0 || fmState.busy;
            document.getElementById('fm-copy-left').disabled = rightSel === 0 || fmState.busy;
            document.getElementById('fm-move-right').disabled = leftSel === 0 || fmState.busy;
            document.getElementById('fm-move-left').disabled = rightSel === 0 || fmState.busy;

            // New Folder: always enabled if not busy and pane is active
            document.getElementById('fm-newfolder').disabled = !fmState.activePane || fmState.busy;

            // Rename: exactly one selection
            document.getElementById('fm-rename').disabled = totalSel !== 1 || fmState.busy;

            // Delete/Zip: at least one selection
            document.getElementById('fm-delete').disabled = totalSel === 0 || fmState.busy;
            document.getElementById('fm-zip').disabled = totalSel === 0 || fmState.busy;

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

        async function fmCopy(fromPane, toPane) {
            await fmTransfer('copy', fromPane, toPane);
        }

        async function fmMove(fromPane, toPane) {
            await fmTransfer('move', fromPane, toPane);
        }

        async function fmTransfer(operation, fromPane, toPane) {
            const fromState = fmState[fromPane];
            const toState = fmState[toPane];

            const paths = Array.from(fromState.selected).map(idx => {
                const f = fromState.files[idx];
                return fromState.path === '/' ? `/${f.name}` : `${fromState.path}/${f.name}`;
            });

            if (paths.length === 0) return;

            // Only confirm for move (destructive), not for copy
            if (operation === 'move') {
                const msg = `Move ${paths.length} item(s)?`;
                if (!confirm(msg)) return;
            }

            fmState.busy = true;
            fmUpdateButtons();
            toast(`${operation === 'copy' ? 'Copying' : 'Moving'}...`);

            try {
                const res = await api(`device/${fromState.device}/files`, 'POST', {
                    operation,
                    paths,
                    dest_device: toState.device,
                    dest_path: toState.path
                });

                if (res.success) {
                    toast(`${operation === 'copy' ? 'Copied' : 'Moved'} successfully`);
                    fromState.selected.clear();
                    fmLoadFiles(fromPane);
                    fmLoadFiles(toPane);
                } else {
                    toast(res.error || 'Operation failed', 'error');
                }
            } catch (e) {
                toast('Operation failed', 'error');
            }

            fmState.busy = false;
            fmUpdateButtons();
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
                if (action === 'backup') {
                    // Backup: skip step 2, go to schedule
                    showWizardStep(3);
                } else {
                    // Wake/Shutdown: show target type selection
                    document.getElementById('step2-action').textContent = action;
                    if (action === 'wake') {
                        document.getElementById('step2-device-desc').textContent = 'Wake via Wake-on-LAN';
                        document.getElementById('step2-docker-desc').textContent = 'Start a container';
                    } else {
                        document.getElementById('step2-device-desc').textContent = 'Shutdown via SSH';
                        document.getElementById('step2-docker-desc').textContent = 'Stop a container';
                    }
                    showWizardStep(2);
                }
            } else if (wizardStep === 2) {
                // After target type, go to schedule
                showWizardStep(3);
            } else if (wizardStep === 3) {
                // After schedule
                if (action === 'backup') {
                    // Backup: go to source, start browsing
                    showWizardStep(5);
                    browseFolder('source');
                } else {
                    // Wake/Shutdown: go to target selection
                    if (target === 'device') {
                        document.getElementById('target-device-group').style.display = 'block';
                        document.getElementById('target-container-group').style.display = 'none';
                        // Filter devices based on action
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
                }
            } else if (wizardStep === 4) {
                // Wake/Shutdown: go to options
                document.getElementById('backup-options').style.display = 'none';
                showWizardStep(7);
            } else if (wizardStep === 5) {
                // Backup source: go to destination, start browsing
                showWizardStep(6);
                browseFolder('dest');
            } else if (wizardStep === 6) {
                // Backup destination: go to options
                document.getElementById('backup-options').style.display = 'block';
                showWizardStep(7);
            }
        }

        function wizardBack() {
            const action = getWizardAction();

            if (wizardStep === 2) {
                showWizardStep(1);
            } else if (wizardStep === 3) {
                if (action === 'backup') {
                    showWizardStep(1);
                } else {
                    showWizardStep(2);
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
                } else {
                    showWizardStep(4);
                }
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

        function editTask(id) {
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
                applySectionVisibility();
                applyMonochrome();
                initTheme();
                renderLinks();
                renderDevices();
                renderTasks();
            }
        }
        
        async function loadDeviceStatus() {
            for (const dev of config.devices) {
                const res = await api(`device/${dev.id}/status`);
                deviceStats[dev.id] = res;
            }
            renderDevices();
        }
        
        
        // === Init ===
        document.getElementById('edit-toggle').onclick = () => {
            editMode = !editMode;
            document.body.classList.toggle('edit-mode', editMode);
            document.getElementById('edit-toggle').classList.toggle('active', editMode);
        };
        
        document.getElementById('add-link').onclick = () => openLinkModal();
        document.getElementById('add-device').onclick = () => openDeviceModal();

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
            if (!deviceInterval) {
                deviceInterval = setInterval(loadDeviceStatus, 10000);
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

        // Load everything
        loadConfig();
        setTimeout(startPolling, 500);
    </script>
</body>
</html>'''

# PWA Manifest
MANIFEST_JSON = json.dumps({
    "name": "DeQ",
    "short_name": "DeQ",
    "description": "Homelab Dashboard",
    "start_url": "/",
    "display": "standalone",
    "background_color": "#0a0a0f",
    "theme_color": "#0a0a0f",
    "orientation": "any",
    "icons": [
        {"src": "/icon.svg", "sizes": "any", "type": "image/svg+xml", "purpose": "any maskable"}
    ]
})

# Icon
ICON_SVG = '''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">
  <rect width="512" height="512" rx="96" fill="#222"/>
  <!-- D -->
  <path d="M80 80 L210 80 Q230 80 230 100 L230 412 Q230 432 210 432 L80 432 Z" fill="none" stroke="#e0e0e0" stroke-width="16"/>
  <!-- e -->
  <path d="M430 155 L432 100 Q432 80 412 80 L302 80 Q282 80 282 100 L282 210 Q282 230 302 230 L430 230" fill="none" stroke="#e0e0e0" stroke-width="16" stroke-linecap="round"/>
  <line x1="400" y1="155" x2="428" y2="155" stroke="#e0e0e0" stroke-width="16" stroke-linecap="round"/>
  <!-- Q -->
  <path d="M432 380 L432 302 Q432 282 412 282 L302 282 Q282 282 282 302 L282 412 Q282 432 302 432 L380 432" fill="none" stroke="#2ed573" stroke-width="16" stroke-linecap="round"/>
  <line x1="405" y1="405" x2="435" y2="435" stroke="#2ed573" stroke-width="16" stroke-linecap="round"/>
</svg>'''

# === TASK EXECUTION ===
def log_task(task_id, message):
    """Append a log line to the task's log file."""
    log_file = f"{TASK_LOGS_DIR}/{task_id}.log"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(log_file, 'a') as f:
        f.write(f"[{timestamp}] {message}\n")

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
        rsync_opts.extend(["-e", f"ssh -p {ssh_port} -o StrictHostKeyChecking=no -o ConnectTimeout=10"])
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
            rsync_opts.extend(["-e", f"ssh -p {ssh_port} -o StrictHostKeyChecking=no -o ConnectTimeout=10"])
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
        """Update next_run times for all tasks."""
        global CONFIG
        changed = False
        for task in CONFIG.get('tasks', []):
            if task.get('enabled', True):
                next_run = calculate_next_run(task)
                if next_run != task.get('next_run'):
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

    def do_GET(self):
        path = urlparse(self.path).path
        query = parse_qs(urlparse(self.path).query)
        
        if path == '/' or path == '':
            self.send_html(HTML_PAGE)
            return
        
        if path == '/manifest.json':
            self.send_file(MANIFEST_JSON, 'application/json')
            return
        
        if path == '/icon.svg':
            self.send_file(ICON_SVG, 'image/svg+xml')
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
                self.send_json({"success": True, "config": CONFIG, "running_tasks": list(running_tasks.keys())})
                return
            
            if api_path == 'stats/host':
                self.send_json({"success": True, "stats": get_local_stats()})
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

                    if action == 'status':
                        # Get container statuses
                        containers = dev.get('docker', {}).get('containers', [])
                        container_statuses = {}
                        is_host = dev.get('is_host', False)
                        ssh_config = dev.get('ssh', {})

                        for c in containers:
                            cname = c.get('name') if isinstance(c, dict) else c

                            if not is_valid_container_name(cname):
                                container_statuses[cname] = 'invalid'
                                continue

                            if is_host:
                                result = docker_action(cname, 'status')
                            elif ssh_config.get('user'):
                                result = remote_docker_action(
                                    dev['ip'],
                                    ssh_config['user'],
                                    ssh_config.get('port', 22),
                                    cname,
                                    'status'
                                )
                            else:
                                result = {"success": False}

                            if result.get('success'):
                                container_statuses[cname] = result.get('status', 'unknown')
                            else:
                                container_statuses[cname] = 'unknown'

                        # Host device: always online, use local stats
                        if dev.get('is_host'):
                            stats = get_local_stats()
                            self.send_json({"success": True, "online": True, "stats": stats, "containers": container_statuses})
                            return

                        online = ping_host(dev['ip'])
                        stats = None
                        if online and dev.get('ssh', {}).get('user'):
                            stats = get_remote_stats(dev['ip'], dev['ssh']['user'], dev['ssh'].get('port', 22))
                        self.send_json({"success": True, "online": online, "stats": stats, "containers": container_statuses})
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
        
        # Task execution
        if path.startswith('/api/task/') and path.endswith('/run'):
            task_id = path.split('/')[3]
            result = run_task(task_id)
            self.send_json(result)
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

            if operation in ('copy', 'move'):
                dest_dev_id = data.get('dest_device')
                dest_path = data.get('dest_path')
                dest_dev = next((d for d in CONFIG['devices'] if d['id'] == dest_dev_id), None)
                if not dest_dev:
                    self.send_json({"success": False, "error": "Destination device not found"}, 404)
                    return
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
                import re
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
              DeQ - Homelab Dashboard
================================================================
  Version: {VERSION}
  Port:    {port}

  Access URL:
  http://YOUR-IP:{port}/
================================================================
    """)
    
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


if __name__ == '__main__':
    main()

