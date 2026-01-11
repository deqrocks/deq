# /opt/deq/extensions/dashboard.py
import urllib.request
import json
import xml.etree.ElementTree as ET
from html import unescape
from datetime import datetime, timedelta
import time
import re

# Configuration
CITY = "Berlin"  # Weather city
RSS_FEEDS = [
    "https://news.ycombinator.com/rss",
    "https://www.theverge.com/rss/index.xml",
    "https://feeds.arstechnica.com/arstechnica/index",
]

CACHE_DURATION = 600  # 10 minutes
CACHE = {"data": None, "time": 0}

def register(deq):
    deq.register_section(
        id="dashboard",
        title="Dashboard",
        icon="layout-grid",
        render=render_dashboard
    )

def render_dashboard():
    if CACHE["data"] and time.time() - CACHE["time"] < CACHE_DURATION:
        weather = CACHE["data"]["weather"]
        news = CACHE["data"]["news"]
    else:
        new_weather = get_weather()
        new_news = get_news()

        # If weather fetch failed, keep old weather cache
        if new_weather is None and CACHE["data"] and CACHE["data"]["weather"]:
            weather = CACHE["data"]["weather"]
        else:
            weather = new_weather

        # Always update news and timestamp
        CACHE["data"] = {"weather": weather, "news": new_news}
        CACHE["time"] = time.time()
        news = new_news

    return format_dashboard(weather, news)

def get_weather():
    try:
        url = f"https://wttr.in/{CITY}?format=j1"
        with urllib.request.urlopen(url, timeout=5) as r:
            data = json.loads(r.read())
            return data
    except Exception as e:
        print(f"Weather error: {e}")
        return None

def get_news():
    all_items = []
    for feed_url in RSS_FEEDS:
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (compatible; DeQ)'}
            req = urllib.request.Request(feed_url, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as response:
                xml_data = response.read().decode('utf-8', errors='ignore')
            root = ET.fromstring(xml_data)

            items = []
            if root.tag == '{http://www.w3.org/2005/Atom}feed':
                for entry in root.findall('.//{http://www.w3.org/2005/Atom}entry')[:8]:
                    items.append(parse_atom_entry(entry))
            else:
                for item in root.findall('.//item')[:8]:
                    items.append(parse_rss_item(item))

            all_items.extend(items)
        except Exception as e:
            print(f"RSS Error: {feed_url} - {e}")

    all_items.sort(key=lambda x: x.get("date", 0), reverse=True)
    return all_items[:12]

def parse_rss_item(item):
    title = item.find('title')
    link = item.find('link')
    desc = item.find('description')
    pub_date = item.find('pubDate')
    enclosure = item.find('enclosure')

    # Extract thumbnail
    thumbnail = None
    if enclosure is not None:
        thumbnail = enclosure.get('url')
    if not thumbnail and desc is not None and desc.text:
        img_match = re.search(r'<img[^>]+src="([^"]+)"', desc.text)
        if img_match:
            thumbnail = img_match.group(1)

    timestamp = 0
    if pub_date is not None and pub_date.text:
        try:
            from email.utils import parsedate_to_datetime
            timestamp = int(parsedate_to_datetime(pub_date.text).timestamp())
        except:
            pass

    return {
        "title": unescape(title.text) if title is not None else "No title",
        "link": link.text if link is not None else "#",
        "description": strip_html(desc.text if desc is not None else ""),
        "date": timestamp,
        "thumbnail": thumbnail
    }

def parse_atom_entry(entry):
    title = entry.find('{http://www.w3.org/2005/Atom}title')
    link = entry.find('.//{http://www.w3.org/2005/Atom}link')
    content = entry.find('{http://www.w3.org/2005/Atom}content')
    summary = entry.find('{http://www.w3.org/2005/Atom}summary')
    updated = entry.find('{http://www.w3.org/2005/Atom}updated')

    description = content.text if content is not None else (summary.text if summary is not None else "")

    # Extract thumbnail
    thumbnail = None
    if description:
        img_match = re.search(r'<img[^>]+src="([^"]+)"', description)
        if img_match:
            thumbnail = img_match.group(1)

    timestamp = 0
    if updated is not None and updated.text:
        try:
            dt = datetime.fromisoformat(updated.text.replace('Z', '+00:00'))
            timestamp = int(dt.timestamp())
        except:
            pass

    return {
        "title": unescape(title.text) if title is not None else "No title",
        "link": link.get('href') if link is not None else "#",
        "description": strip_html(description),
        "date": timestamp,
        "thumbnail": thumbnail
    }

def strip_html(text):
    if not text:
        return ""
    return re.sub(r'<[^>]+>', '', text).strip()

def format_dashboard(weather, news):
    # Weather card
    weather_html = ""
    if weather:
        current = weather["current_condition"][0]
        temp = current["temp_C"]
        desc = current["weatherDesc"][0]["value"]

        # Get forecast
        forecast_html = ""
        for day in weather.get("weather", [])[:3]:
            date_str = day.get("date", "")
            try:
                dt = datetime.strptime(date_str, "%Y-%m-%d")
                day_name = dt.strftime("%a")
            except:
                day_name = "N/A"

            max_temp = day.get("maxtempC", "--")
            min_temp = day.get("mintempC", "--")
            icon = day.get("hourly", [{}])[0].get("weatherDesc", [{}])[0].get("value", "")

            forecast_html += f'''
                <div class="forecast-day">
                    <div class="forecast-name">{day_name}</div>
                    <div class="forecast-temp">{max_temp}° / {min_temp}°</div>
                </div>
            '''

        weather_html = f'''
            <div class="weather-current">
                <div class="weather-temp">{temp}°C</div>
                <div class="weather-desc">{desc}</div>
                <div class="weather-city">{CITY}</div>
            </div>
            <div class="forecast-list">
                {forecast_html}
            </div>
        '''
    else:
        weather_html = '<div class="weather-error">Weather unavailable</div>'

    # News card
    news_html = ""
    if news:
        for item in news:
            if item["date"]:
                time_str = datetime.fromtimestamp(item["date"]).strftime('%H:%M')
            else:
                time_str = ""

            # Thumbnail or placeholder
            if item["thumbnail"]:
                thumb = f'<img src="{item["thumbnail"]}" class="news-thumb" style="object-fit:cover;border-radius:4px;">'
            else:
                thumb = '<div class="news-thumb" style="background:var(--bg-tertiary);border-radius:4px;display:flex;align-items:center;justify-content:center;font-size:10px;">📰</div>'

            news_html += f'''
                <a href="{item["link"]}" target="_blank" rel="noopener" class="news-item">
                    {thumb}
                    <div class="news-content">
                        <div class="news-time">{time_str}</div>
                        <div class="news-title">{item["title"]}</div>
                    </div>
                </a>
            '''
    else:
        news_html = '<div class="news-error">No news items</div>'

    return f'''
        <div class="dashboard-grid">
            <div class="dashboard-card weather-card">
                <div class="card-header">Weather</div>
                {weather_html}
            </div>
            <div class="dashboard-card news-card">
                <div class="card-header">Latest News</div>
                <div class="news-list">
                    {news_html}
                </div>
            </div>
        </div>
        <style>
        .dashboard-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 16px;
        }}
        .dashboard-card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 16px;
            backdrop-filter: blur(var(--glass-blur, 0px));
            -webkit-backdrop-filter: blur(var(--glass-blur, 0px));
            overflow-y: auto;
            max-height: 300px;
        }}
        .card-header {{
            font-size: 11px;
            font-weight: 500;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 12px;
        }}
        /* Weather */
        .weather-current {{
            text-align: center;
            padding: 16px 0;
            margin-bottom: 16px;
        }}
        .weather-temp {{
            font-size: 48px;
            font-weight: 600;
            color: var(--text-primary);
            line-height: 1;
        }}
        .weather-desc {{
            font-size: 14px;
            color: var(--text-secondary);
            margin-top: 8px;
        }}
        .weather-city {{
            font-size: 12px;
            color: var(--text-secondary);
            margin-top: 4px;
        }}
        .weather-error {{
            text-align: center;
            color: var(--text-secondary);
            padding: 32px;
        }}
        .forecast-list {{
            display: flex;
            flex-direction: column;
            gap: 8px;
        }}
        .forecast-day {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 8px 0;
        }}
        .forecast-name {{
            font-size: 13px;
            font-weight: 500;
            color: var(--text-primary);
        }}
        .forecast-temp {{
            font-size: 13px;
            color: var(--text-secondary);
        }}
        /* News */
        .news-list {{
            display: flex;
            flex-direction: column;
            gap: 4px;
        }}
        .news-item {{
            display: flex;
            gap: 10px;
            padding: 8px 10px;
            text-decoration: none;
            color: inherit;
            border-radius: 6px;
            transition: opacity 0.15s;
        }}
        .news-item:hover {{
            opacity: 0.7;
        }}
        .news-thumb {{
            width: 40px;
            height: 40px;
            flex-shrink: 0;
        }}
        .news-content {{
            flex: 1;
            min-width: 0;
        }}
        .news-time {{
            font-size: 11px;
            color: var(--text-secondary);
        }}
        .news-title {{
            font-weight: 500;
            font-size: 13px;
            line-height: 1.4;
            color: var(--text-primary);
            overflow: hidden;
            text-overflow: ellipsis;
            display: -webkit-box;
            -webkit-line-clamp: 2;
            -webkit-box-orient: vertical;
        }}
        .news-error {{
            color: var(--text-secondary);
            padding: 32px;
        }}
        @media (max-width: 800px) {{
            .dashboard-grid {{
                grid-template-columns: 1fr;
            }}
        }}
        </style>
    '''
