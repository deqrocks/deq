# /opt/deq/extensions/containers.py
# Simple Docker container status overview

HOST = "host"  # Device ID in DeQ where Docker is running

def register(deq):
    """Called once when extension is loaded."""
    deq.register_section(
        id="containers",
        title="Containers",
        icon="box",
        render=lambda: render_containers(deq)
    )

def render_containers(deq):
    """Render Docker container overview."""
    try:
        success, out, err = deq.ssh(HOST,
            "docker ps --format '{{.Names}}|{{.Status}}'"
        )
        if not success:
            return f'<div style="padding:1rem;opacity:0.5">Docker error: {err}</div>'

        if not out.strip():
            return '<div style="padding:1rem;opacity:0.5">No containers running</div>'

        lines = out.strip().split('\n')
        return f'''
            <div style="padding:1rem;">
                <div style="opacity:0.7;font-size:0.8rem;margin-bottom:0.5rem">{len(lines)} containers running</div>
                <div style="display:flex;flex-direction:column;gap:0.5rem;">
                    {format_containers(lines)}
                </div>
            </div>
        '''
    except Exception as e:
        return f'<div style="padding:1rem;opacity:0.5">Error: {str(e)}</div>'

def format_containers(lines):
    """Format container list."""
    items = []
    for line in lines[:10]:  # Show max 10 containers
        parts = line.split('|')
        if len(parts) >= 2:
            name = parts[0]
            status = parts[1]

            # Extract health status if available
            health = ""
            if "healthy" in status.lower():
                health = '<span style="color:#4ade80">●</span>'
            elif "unhealthy" in status.lower():
                health = '<span style="color:#f87171">●</span>'

            items.append(f'''
                <div style="display:flex;align-items:center;gap:0.5rem;font-size:0.9rem;">
                    {health}
                    <span style="font-family:monospace">{name}</span>
                    <span style="opacity:0.5">{status.split(" (")[0] if " (" in status else status}</span>
                </div>
            ''')

    return '\n'.join(items)
