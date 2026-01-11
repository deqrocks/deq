# /opt/deq/extensions/overview.py

def register(deq):
    """Called once when extension is loaded."""
    deq.register_section(
        id="overview",
        title="Overview",
        icon="activity",
        render=lambda: render_overview(deq)
    )

def render_overview(deq):
    """Render system overview across all devices."""
    online = 0
    offline = 0
    total_cpu = 0
    cpu_count = 0

    for dev in deq.devices:
        status = deq.device_status(dev['id'])
        if status:
            if status.get('online'):
                online += 1
                stats = status.get('stats', {})
                if 'cpu' in stats:
                    total_cpu += stats['cpu']
                    cpu_count += 1
            else:
                offline += 1

    avg_cpu = int(total_cpu / cpu_count) if cpu_count else 0

    return f'''
        <div style="display:flex;gap:2rem;padding:1rem;justify-content:center">
            <div style="text-align:center">
                <div style="font-size:1.5rem;color:var(--accent)">{online}</div>
                <div style="opacity:0.7;font-size:0.8rem">Online</div>
            </div>
            <div style="text-align:center">
                <div style="font-size:1.5rem;color:#ff6b6b">{offline}</div>
                <div style="opacity:0.7;font-size:0.8rem">Offline</div>
            </div>
            <div style="text-align:center">
                <div style="font-size:1.5rem">{avg_cpu}%</div>
                <div style="opacity:0.7;font-size:0.8rem">Avg CPU</div>
            </div>
        </div>
    '''
