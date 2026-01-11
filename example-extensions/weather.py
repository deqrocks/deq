# /opt/deq/extensions/weather.py
import urllib.request
import json

CITY = "Berlin"
CACHE = {"data": None, "time": 0}

def register(deq):
    """Called once when extension is loaded."""
    deq.register_section(
        id="weather",
        title="Weather",
        icon="cloud-sun",
        render=render_weather
    )

def render_weather():
    """Called on every poll to render section content."""
    import time

    # Cache for 10 minutes
    if CACHE["data"] and time.time() - CACHE["time"] < 600:
        return format_weather(CACHE["data"])

    try:
        # Using wttr.in (no API key needed)
        url = f"https://wttr.in/{CITY}?format=j1"
        with urllib.request.urlopen(url, timeout=5) as r:
            data = json.loads(r.read())
            CACHE["data"] = data
            CACHE["time"] = time.time()
            return format_weather(data)
    except Exception as e:
        # On error, return old cache if available
        if CACHE["data"]:
            return format_weather(CACHE["data"])
        return f'<div style="padding:1rem;opacity:0.5">Weather unavailable: {e}</div>'

def format_weather(data):
    current = data["current_condition"][0]
    temp = current["temp_C"]
    desc = current["weatherDesc"][0]["value"]

    return f'''
        <div style="text-align:center;padding:1rem;">
            <div style="font-size:2rem;font-weight:600">{temp}°C</div>
            <div style="opacity:0.7">{CITY} · {desc}</div>
        </div>
    '''
