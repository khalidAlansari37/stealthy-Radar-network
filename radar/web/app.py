from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
from datetime import datetime
import psutil
import os
import threading
import logging

from radar.database.vault import Vault
from radar.reports.aggregator import DataAggregator
from radar.config import settings
from radar.fingerprint.scanner import ArpScanner
from radar.fingerprint.tactical import ArpRedirector

logger = logging.getLogger(__name__)

app = FastAPI(title="Radar Intelligence Dashboard")

# Global tracker for live tactical interceptors
active_interceptors = {}

# CORS for local dev
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

vault = Vault()
aggregator = DataAggregator(vault)

# Serve static files
static_dir = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

# ── API ROUTES (must come BEFORE the catch-all) ──────────────────────────────

@app.get("/api/overview")
async def get_overview():
    today = datetime.now().date().isoformat()
    metrics = vault.get_system_metrics(today)
    last_metric = metrics[-1] if metrics else None
    
    apps = vault.get_app_activity(today)
    last_app = apps[-1] if apps else None
    
    all_devices = vault.get_network_devices()
    active_today = [d for d in all_devices if d.last_seen.date().isoformat() == today]
    
    return {
        "system": {
            "cpu": last_metric.cpu_percent if last_metric else 0,
            "ram": last_metric.ram_percent if last_metric else 0,
            "disk": last_metric.disk_percent if last_metric else 0,
            "battery": last_metric.battery_percent if last_metric else 0,
            "battery_charging": last_metric.battery_charging if last_metric else True,
            "wifi_ssid": last_metric.wifi_ssid if last_metric else "Unknown",
            "wifi_signal": last_metric.wifi_signal_dbm if last_metric else -100
        },
        "app_focus": {
            "current": last_app.app_name if last_app else "Idle",
            "window": last_app.window_title if last_app else "N/A",
            "is_idle": last_app.is_idle if last_app else True
        },
        "network_stats": {
            "total_known": len(all_devices),
            "active_today": len(active_today)
        }
    }

@app.get("/api/devices")
async def get_devices():
    devices = vault.get_network_devices()
    # Filter out ghosts
    valid_devices = [d for d in devices if d.ip_address and d.ip_address != "0.0.0.0" and not d.ip_address.startswith("127.")]
    # Sort by last seen, recent first
    sorted_devices = sorted(valid_devices, key=lambda d: d.last_seen, reverse=True)
    return sorted_devices

@app.get("/api/device/{mac:path}/flows")
async def get_device_flows(mac: str):
    """Returns the granular flow history for a device."""
    devices = vault.get_network_devices()
    device = next((d for d in devices if d.mac_address == mac), None)
    if not device:
        return []
    
    # Get flows for this device's IP
    if not device.ip_address:
        return []
        
    flows = vault.get_device_flows(device.ip_address, limit=50)
    return flows

@app.get("/api/device/{mac:path}/stats")
async def get_device_stats(mac: str):
    """Returns aggregated traffic intelligence for a device."""
    devices = vault.get_network_devices()
    device = next((d for d in devices if d.mac_address == mac), None)
    if not device or not device.ip_address:
        return {"top_domains": [], "total_bytes": 0}
    
    flows = vault.get_device_flows(device.ip_address, limit=200)
    
    # Aggregate top domains
    domains = {}
    total_bytes = 0
    for f in flows:
        label = f.get('service_label') or f.get('protocol')
        domains[label] = domains.get(label, 0) + 1
        total_bytes += f.get('byte_count') or 0
        
    top_domains = [{"name": k, "count": v} for k, v in sorted(domains.items(), key=lambda x: x[1], reverse=True)]
    
    return {
        "top_domains": top_domains[:10],
        "total_bytes": total_bytes,
        "flow_count": len(flows)
    }

@app.get("/api/bandwidth/leaderboard")
async def get_bandwidth_leaderboard():
    """Returns the top devices sorted by total cumulative bandwidth usage."""
    devices = vault.get_network_devices()
    # Filter out ghosts and sort by total_bytes
    valid = [d for d in devices if d.ip_address and d.ip_address != "0.0.0.0" and not d.ip_address.startswith("127.")]
    
    # Sort descending by total_bytes (which might be None in old schemas, so fallback to 0)
    # The dictionary conversion handles the new DB column dynamically if the model isn't strictly typed yet
    device_dicts = []
    for d in valid:
        # Access the raw dict underlying the record to catch new columns
        raw = d.__dict__ if hasattr(d, '__dict__') else {}
        total = raw.get('total_bytes', 0)
        
        # Determine name
        name = d.device_name
        if not name or name in ["Unknown", "Unknown Device"]:
            name = d.mdns_hostname or (f"{d.manufacturer.split()[0]} Device" if d.manufacturer and d.manufacturer != "Unknown" else f"Device-{d.mac_address.split(':')[-2].upper()}{d.mac_address.split(':')[-1].upper()}")
            
        device_dicts.append({
            "mac": d.mac_address,
            "name": name,
            "ip": d.ip_address,
            "total_bytes": total
        })
        
    sorted_devices = sorted(device_dicts, key=lambda x: x["total_bytes"], reverse=True)
    return sorted_devices[:5]  # Top 5 consumers

# --- TACTICAL INTERCEPTOR ROUTES ---

@app.post("/api/tactical/{mac:path}/start")
async def start_interception(mac: str):
    if mac in active_interceptors:
        return {"status": "already running"}
        
    devices = vault.get_network_devices()
    device = next((d for d in devices if d.mac_address == mac), None)
    if not device or not device.ip_address:
        raise HTTPException(status_code=404, detail="Device or IP not found")
        
    try:
        redirector = ArpRedirector(target_ip=device.ip_address)
        # Start in background
        redirector.running = True
        redirector.thread = threading.Thread(target=redirector._poison, daemon=True)
        redirector.thread.start()
        
        active_interceptors[mac] = redirector
        return {"status": "started", "target_ip": device.ip_address}
    except Exception as e:
        logger.error(f"Failed to start interceptor: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/tactical/{mac:path}/stop")
async def stop_interception(mac: str):
    if mac not in active_interceptors:
        return {"status": "not running"}
        
    redirector = active_interceptors[mac]
    try:
        redirector.stop()
    except Exception as e:
        logger.error(f"Error stopping interceptor: {e}")
    
    del active_interceptors[mac]
    return {"status": "stopped"}

@app.get("/api/tactical/{mac:path}/status")
async def get_interception_status(mac: str):
    is_running = mac in active_interceptors
    return {"intercepting": is_running}


@app.get("/api/device/{mac:path}")
async def get_device_detail(mac: str):
    devices = vault.get_network_devices()
    device = next((d for d in devices if d.mac_address == mac), None)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    
    # Get sessions for this specific MAC address (not by date)
    today = datetime.now().date().isoformat()
    all_sessions = vault.get_device_sessions(today)
    device_sessions = [s for s in all_sessions if s.mac_address == mac]
    
    return {
        "info": device,
        "sessions": device_sessions[-10:] if device_sessions else []
    }

@app.get("/api/system/history")
async def get_system_history():
    today = datetime.now().date().isoformat()
    summary = aggregator.get_daily_summary(today)
    return summary["system"]["trends"]

@app.get("/api/apps/top")
async def get_top_apps():
    today = datetime.now().date().isoformat()
    summary = aggregator.get_daily_summary(today)
    return summary["apps"]["top_10"]

@app.post("/api/scan")
async def trigger_scan():
    """Triggers a manual ARP scan of the network."""
    try:
        if os.geteuid() != 0:
            return {
                "status": "error", 
                "message": "Scan requires root privileges. Please restart the daemon/server with sudo to enable network discovery."
            }
            
        scanner = ArpScanner(vault=vault)
        results = scanner.scan()
        return {"status": "success", "found": len(results)}
    except Exception as e:
        logger.error(f"Manual scan failed: {e}")
        return {"status": "error", "message": str(e)}

# ── SPA CATCH-ALL (must be LAST) ─────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def get_index():
    index_path = static_dir / "index.html"
    if not index_path.exists():
        raise HTTPException(status_code=404, detail="Frontend not found")
    return index_path.read_text()
