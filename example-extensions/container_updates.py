# /opt/deq/extensions/updates.py
# Check for Docker container image updates

HOST = "host"  # Device ID in DeQ where Docker is running

def register(deq):
    """Called once when extension is loaded."""
    deq.register_section(
        id="updates",
        title="Container Updates",
        icon="download",
        render=lambda: render_updates(deq)
    )

def render_updates(deq):
    """Render container update overview."""
    try:
        # Get images with their tags
        success, out, err = deq.ssh(HOST,
            "docker images --format '{{.Repository}}:{{.Tag}}|{{.ID}}|{{.CreatedAt}}' | head -20"
        )
        if not success:
            return f'<div style="padding:1rem;opacity:0.5">Error: {err}</div>'

        if not out.strip():
            return '<div style="padding:1rem;opacity:0.5">No images found</div>'

        images = parse_images(out.strip().split('\n'))
        return format_updates(images)
    except Exception as e:
        return f'<div style="padding:1rem;opacity:0.5">Error: {str(e)}</div>'

def parse_images(lines):
    """Parse docker images output."""
    images = []
    seen = set()

    for line in lines:
        parts = line.split('|')
        if len(parts) >= 3:
            name = parts[0]
            image_id = parts[1]
            created = parts[2]

            # Skip duplicates (same image, different tags)
            if image_id in seen:
                continue
            seen.add(image_id)

            # Check if image might be outdated
            is_latest = ":latest" in name or ":release" in name
            is_old = check_if_old(created)

            images.append({
                "name": name,
                "id": image_id[:12],
                "created": created,
                "is_latest": is_latest,
                "is_old": is_old
            })

    return images

def check_if_old(created_str):
    """Check if image is old (simplified)."""
    try:
        # Parse "2025-01-05 12:34:56" format
        if "ago" in created_str.lower():
            # Docker already gives us relative time
            parts = created_str.lower().split()
            if len(parts) >= 2:
                num = int(parts[0])
                unit = parts[1]
                # Old if more than 7 days
                if "day" in unit and num > 7:
                    return True
                if "week" in unit or "month" in unit or "year" in unit:
                    return True
        return False
    except:
        return False

def format_updates(images):
    """Format update overview."""
    old_count = sum(1 for i in images if i["is_old"])

    items = []
    for img in images:
        # Priority indicator
        if img["is_old"] and img["is_latest"]:
            priority = '<span style="color:#f87171">↑ Update recommended</span>'
        elif img["is_old"]:
            priority = '<span style="color:#fbbf24">○ Old image</span>'
        else:
            priority = ''

        items.append(f'''
            <div style="display:flex;justify-content:space-between;align-items:center;font-size:0.85rem;padding:0.4rem 0;">
                <div>
                    <div style="font-family:monospace">{img["name"]}</div>
                    <div style="opacity:0.5;font-size:0.75rem">ID: {img["id"]} · {img["created"]}</div>
                </div>
                {priority}
            </div>
        ''')

    return f'''
        <div style="padding:1rem;">
            <div style="margin-bottom:1rem;">
                <div style="font-size:1.2rem;font-weight:600">{old_count} possibly outdated</div>
                <div style="opacity:0.7;font-size:0.8rem">of {len(images)} images</div>
            </div>
            <div style="display:flex;flex-direction:column;gap:0.25rem;">
                {''.join(items)}
            </div>
        </div>
    '''
