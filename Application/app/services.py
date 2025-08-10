import json
import requests
from bs4 import BeautifulSoup
from flask import current_app

def extract_message(body: str) -> str:
    # Prefer JSON {"message": "..."}
    try:
        node = json.loads(body)
        if isinstance(node, dict) and "message" in node:
            return str(node["message"])
    except Exception:
        pass
    # Fallback: HTML or text
    try:
        soup = BeautifulSoup(body, "html.parser")
        for sel in ["#message", ".message", "meta[name='description']"]:
            el = soup.select_one(sel)
            if el:
                return el.get("content") if el.name == "meta" else el.get_text(strip=True)
        text = soup.get_text(separator=" ", strip=True)
        return text if text else body
    except Exception:
        return body

def call_fastapi(endpoint: str, label: str) -> str:
    base = current_app.config["API_BASE"].rstrip("/")
    url = f"{base}{endpoint}"
    r = requests.get(url, timeout=60)
    r.raise_for_status()
    msg = extract_message(r.text)
    busy = "another user's request is currently being processed" in msg.lower()
    prefix = "❌" if busy else "✅"
    return f"{prefix} {label} → {msg}"
