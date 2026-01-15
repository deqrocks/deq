# /opt/deq/extensions/deq-ressource-usage.py
# ------------------------------------------------------------------------------
# Name:        deq-ressource-usage.py
# Version:     v1.2
# Author:      deqrocks
# Tested on:   Ubuntu 24.04, Debian Bookworm
# Requirements: DeQ only
# Description:
#
# This is a DeQ resource usage monitor extension.
# It uses DeQ's extension API: https://deq.rocks/documentation.html#extension-api and
#
# Features:
# - Shows a sparkline graph of DeQ's ressource usage over the last 6 hours
# - Background thread collects metrics every 30 seconds (independent of frontend 5 seconds interval)
# - CPU load calculation excludes deq-resource-usage.py own thread usage (but adds to RAM)
# - Thread-safe history storage with automatic FIFO cleanup
# - SVG sparkline with dynamic scaling for visibility
#
#
# --- CONFIGURATION ---
# To adjust collection frequency, modify LOG_INTERVAL below:
# - 30 seconds = 6 hours of history (default, recommended for debugging memory leaks)
# - 60 seconds = 12 hours of history (for long-term monitoring)
# - 10 seconds = 2 hours of history (for detailed analysis)
# ------------------------------------------------------------------------------

import os
import time
import threading

START_TIME = time.time()
START_RAM = 0
TOTAL_RAM_MB = 0
NUM_CORES = os.cpu_count() or 1  # Fallback to 1 if None
HISTORY = []
MAX_HISTORY = 720  # 6 hours (720 * 30s)
LOG_INTERVAL = 30 # seconds
HISTORY_LOCK = threading.Lock()

# Helper variables for interval-based CPU calculation
# Subtracts collector thread's own CPU usage from total process CPU
LAST_TOTAL_TICKS = 0
LAST_COLLECTOR_TICKS = 0
LAST_MEASURE_TIME = 0

collection_active = False
collection_thread = None

def get_total_ram():
    try:
        with open('/proc/meminfo', 'r') as f:
            for line in f:
                if line.startswith('MemTotal:'):
                    return int(line.split()[1]) // 1024  # kB to MB
    except: pass
    return 0

def collect_metrics():
    global collection_active, LAST_TOTAL_TICKS, LAST_COLLECTOR_TICKS, LAST_MEASURE_TIME, TOTAL_RAM_MB
    
    # Read total RAM once at startup
    if TOTAL_RAM_MB == 0:
        TOTAL_RAM_MB = get_total_ram()
    # Get native thread ID (tid) to read this collector thread's CPU ticks separately
    current_thread_id = threading.get_native_id()

    while collection_active:
        try:
            pid = os.getpid()
            now = time.time()
            ram_mb, threads, cpu_percent = 0, 0, 0

            try:
                # 1. Read RAM and Threads from /proc/[pid]/status
                with open(f'/proc/{pid}/status', 'r') as f:
                    for line in f:
                        if line.startswith('VmRSS:'):
                            ram_mb = int(line.split()[1]) // 1024
                        elif line.startswith('Threads:'):
                            threads = int(line.split()[1])

                # 2. Read total process CPU ticks from /proc/[pid]/stat
                with open(f'/proc/{pid}/stat', 'r') as f:
                    fields = f.read().split(')')[-1].split()
                    total_process_ticks = int(fields[11]) + int(fields[12])

                # 3. Read collector thread's own CPU ticks (to subtract from total)
                with open(f'/proc/{pid}/task/{current_thread_id}/stat', 'r') as f:
                    t_fields = f.read().split(')')[-1].split()
                    collector_ticks = int(t_fields[11]) + int(t_fields[12])

                # 4. Calculate CPU load (interval-based, excludes collector's own work)
                if LAST_MEASURE_TIME > 0:
                    delta_time = now - LAST_MEASURE_TIME
                    # Actual payload ticks = total ticks - collector thread ticks
                    delta_payload = (total_process_ticks - LAST_TOTAL_TICKS) - (collector_ticks - LAST_COLLECTOR_TICKS)
                    hertz = os.sysconf('SC_CLK_TCK')
                    # Divide by NUM_CORES to show total system load percentage
                    cpu_percent = (max(0, delta_payload) / hertz) / delta_time * 100 / NUM_CORES

                LAST_TOTAL_TICKS = total_process_ticks
                LAST_COLLECTOR_TICKS = collector_ticks
                LAST_MEASURE_TIME = now
            except: pass

            with HISTORY_LOCK:
                if LAST_MEASURE_TIME > 0:
                    HISTORY.append((now, ram_mb, cpu_percent, threads))
                    if len(HISTORY) > MAX_HISTORY:
                        HISTORY.pop(0)
        except: pass
        time.sleep(LOG_INTERVAL) 

def register(deq):
    global collection_active, collection_thread
    if not collection_active:
        collection_active = True
        collection_thread = threading.Thread(target=collect_metrics, daemon=True)
        collection_thread.start()
    deq.register_section(id="deq_ressource", title="DeQ Ressource Usage", icon="bug", render=render_usage)

def render_usage():
    try:
        pid = os.getpid()
        uptime = time.time() - START_TIME
        
        # Check if meminfo is available
        if TOTAL_RAM_MB == 0:
            return '<div style="padding:16px;">N/A (meminfo not available)</div>'
        
        with HISTORY_LOCK:
            history_copy = list(HISTORY)

        if not history_copy:
            return '<div style="padding:16px;">Analysing Load (30s interval)...</div>'

        _, curr_ram, curr_cpu, curr_threads = history_copy[-1]

        global START_RAM
        if START_RAM == 0: START_RAM = curr_ram
        growth = curr_ram - START_RAM

        num_points = len(history_copy)
        elapsed_min = (num_points * LOG_INTERVAL) // 60
        l_label = "Start" if num_points < MAX_HISTORY else f"-{(MAX_HISTORY * LOG_INTERVAL) / 3600:g}h"
        r_label = f"now ({elapsed_min}m)" if num_points < MAX_HISTORY else "now"

        # --- Sparkline Logic ---
        view_h, view_w = 45, MAX_HISTORY
        sparkline_svg = ""
        if num_points > 1:
            all_ram = [h[1] for h in history_copy]
            all_cpu = [h[2] for h in history_copy]
            
            # Scale RAM as percentage of total RAM with minimum range for visibility
            all_ram_percent = [(r / TOTAL_RAM_MB) * 100 for r in all_ram]
            min_rp, max_rp = min(all_ram_percent), max(all_ram_percent)
            r_range = max(max_rp, 5)  # Minimum 5% range for visibility
            c_range = max(max(all_cpu), 5)  # Minimum 5% range for visibility (CPU is now divided by cores)

            r_pts, c_pts = "", ""
            for i, (_, r, c, _) in enumerate(history_copy):
                x = i
                ram_percent = (r / TOTAL_RAM_MB) * 100
                y_r = view_h - (ram_percent / r_range * view_h)
                y_c = view_h - (c / c_range * view_h)
                r_pts += f"{x},{y_r} "
                c_pts += f"{x},{y_c} "

            sparkline_svg = f'''
            <svg width="100%" height="{view_h}" viewBox="0 0 {view_w} {view_h}" preserveAspectRatio="none" style="display:block; overflow:visible;">
                <polyline points="{r_pts}" fill="none" stroke="var(--text-primary)" stroke-width="2" stroke-opacity="0.7" stroke-linejoin="round" />
                <polyline points="{c_pts}" fill="none" stroke="var(--accent)" stroke-width="2" stroke-opacity="0.7" stroke-linejoin="round" />
            </svg>'''
        else:
            sparkline_svg = f'<div style="height:{view_h}px;"></div>'

        return f'''
        <div style="background:var(--bg-secondary); border:1px solid var(--border); border-radius:12px; padding:16px; color:var(--text-primary); font-family:DeQ Font; min-width:250px;">
            <div style="display:flex; justify-content:space-between; margin-bottom:15px;">
                <div>
                    <div style="font-size:11px; text-transform:uppercase;">RAM Usage</div>
                    <div style="font-size:20px; font-weight:700;">{curr_ram} <span style="font-size:12px; font-weight:400;">MB</span></div>
                </div>
                <div style="text-align:right;">
                    <div style="font-size:11px; text-transform:uppercase;">CPU Load</div>
                    <div style="font-size:20px; font-weight:700; color:var(--accent);">{curr_cpu:.1f}<span style="font-size:12px; font-weight:400;">%</span></div>
                </div>
            </div>
            
            <div style="margin-bottom:4px; border-bottom:1px solid var(--border); padding-bottom:2px;">
                {sparkline_svg}
            </div>
            
            <div style="display:flex; justify-content:space-between; font-size:9px; margin-bottom:16px;">
                <span>{l_label}</span>
                <span>
                    <span style="color:var(--text-primary)">● RAM</span> &nbsp; 
                    <span style="color:var(--accent)">● CPU</span>
                </span>
                <span>{r_label}</span>
            </div>
            
            <div style="display:grid; grid-template-columns: 1fr 1fr; gap:10px; font-size:12px;">
                <div>Threads: {curr_threads}</div>
                <div style="text-align:right;">Uptime: {int(uptime // 60)}m</div>
                <div style="grid-column: span 2; font-size:11px; padding-top:4px;">
                    PID: {pid} • Delta since start: {growth:+}MB
                </div>
            </div>
        </div>'''
    except Exception as e:
        return f'<div style="color:red; padding:10px;">Error: {str(e)}</div>'
