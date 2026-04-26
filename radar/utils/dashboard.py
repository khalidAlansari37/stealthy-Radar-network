"""
Radar Live Intelligence Dashboard
===================================
Terminal-based real-time view of all monitored intelligence streams:
  - App Focus (current & today's top apps)
  - System Health (CPU, RAM, Battery, Network I/O)
  - Network Reconnaissance (all devices with OUI manufacturer + DPI intel)
"""

import time
import os
import sys
import psutil
from datetime import datetime
from radar.database.vault import Vault
from radar.utils.helpers import format_duration

# ── ANSI colour helpers ───────────────────────────────────────────────────────
R   = "\033[0m"          # reset
BLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[1;31m"
GRN = "\033[1;32m"
YLW = "\033[1;33m"
BLU = "\033[1;34m"
CYN = "\033[1;36m"
WHT = "\033[1;37m"
GRY = "\033[0;90m"

def _bar(pct: float, width: int = 20) -> str:
    """Builds a colored ASCII progress bar for a percentage value."""
    filled = int(width * pct / 100)
    bar    = "█" * filled + "░" * (width - filled)
    if pct >= 85:
        color = RED
    elif pct >= 60:
        color = YLW
    else:
        color = GRN
    return f"{color}{bar}{R} {pct:5.1f}%"


def _fmt_bytes(b: int) -> str:
    """Formats bytes into human-readable KB/MB/GB."""
    for unit in ("B", "KB", "MB", "GB"):
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} TB"


def clear_screen():
    os.system("clear")


def draw_dashboard():
    """Main dashboard render loop — refreshes every 2 seconds."""
    print(f"\n{CYN}{BLD}🚀 DASHBOARD HAS MOVED TO THE WEB!{R}")
    print(f"{WHT}Open your browser at: {BLD}http://localhost:8000{R}")
    print(f"{DIM}Press Ctrl+C to continue anyway or exit.{R}\n")
    time.sleep(3)
    
    vault = Vault()

    # Track per-session network counters for delta calculations
    _prev_net = psutil.net_io_counters()
    _prev_time = time.time()

    while True:
        try:
            clear_screen()
            now   = datetime.now()
            today = now.date().isoformat()

            # ── Header ────────────────────────────────────────────────────────
            print(f"{BLD}{BLU}╔══════════════════════════════════════════════════════════╗{R}")
            print(f"{BLD}{BLU}║   ██████╗  █████╗ ██████╗  █████╗ ██████╗               ║{R}")
            print(f"{BLD}{BLU}║   ██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔══██╗              ║{R}")
            print(f"{BLD}{BLU}║   ██████╔╝███████║██║  ██║███████║██████╔╝              ║{R}")
            print(f"{BLD}{BLU}║   ██╔══██╗██╔══██║██║  ██║██╔══██║██╔══██╗              ║{R}")
            print(f"{BLD}{BLU}║   ██║  ██║██║  ██║██████╔╝██║  ██║██║  ██║              ║{R}")
            print(f"{BLD}{BLU}║   ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝              ║{R}")
            print(f"{BLD}{BLU}║   {CYN}INTELLIGENCE DAEMON{BLU}  │  {WHT}{now.strftime('%A %d %b %Y  %H:%M:%S')}{BLU}   ║{R}")
            print(f"{BLD}{BLU}╚══════════════════════════════════════════════════════════╝{R}")
            print()

            # ── Section 1: App Focus & Browser Audit ──────────────────────────
            print(f"{GRN}{BLD}[APP FOCUS MONITOR]{R}")
            activity_log = vault.get_app_activity(today)
            if activity_log:
                last = activity_log[-1]
                idle_tag = f"  {YLW}[IDLE]{R}" if last.is_idle else f"  {GRN}[ACTIVE]{R}"
                print(f"  Current App  : {WHT}{last.app_name}{R}{idle_tag}")
                title_disp = last.window_title[:55] if last.window_title else "—"
                print(f"  Window Title : {DIM}{title_disp}{R}")
                print(f"  Duration     : {format_duration(last.duration_seconds)}")

                # Browser Audit: Check for background browsers
                browsers = ["chrome", "google-chrome", "firefox", "brave", "opera", "msedge"]
                found_browsers = []
                for p in psutil.process_iter(['name']):
                    p_name = p.info['name'].lower()
                    if any(b in p_name for b in browsers):
                        b_name = next(b for b in browsers if b in p_name)
                        if b_name not in found_browsers:
                            found_browsers.append(b_name)
                
                if found_browsers:
                    browser_list = ", ".join([f"{CYN}{b.title()}{R}" for b in found_browsers])
                    print(f"  Background Browsers: {browser_list}")

                # Top 5 apps today
                app_totals: dict = {}
                for rec in activity_log:
                    app_totals[rec.app_name] = app_totals.get(rec.app_name, 0) + rec.duration_seconds
                top_apps = sorted(app_totals.items(), key=lambda x: x[1], reverse=True)[:5]
                print(f"\n  {DIM}── Today's Top Apps ──────────────────────{R}")
                for app, secs in top_apps:
                    print(f"  {CYN}{'  ' + app[:24]:26}{R}  {format_duration(secs)}")
            else:
                print(f"  {GRY}Waiting for first sample...{R}")

            # ── Section 2: System Health ──────────────────────────────────────
            print(f"\n{GRN}{BLD}[SYSTEM HEALTH]{R}")
            metrics = vault.get_system_metrics(today)
            if metrics:
                m = metrics[-1]
                print(f"  CPU      {_bar(m.cpu_percent)}")
                print(f"  RAM      {_bar(m.ram_percent)}")
                print(f"  Disk     {_bar(m.disk_percent)}")

                # Battery with charging indicator
                bat_icon = "⚡" if m.battery_charging else "🔋"
                bat_color = GRN if m.battery_percent > 30 else RED
                print(f"  Battery  {bat_color}{bat_icon} {m.battery_percent:.1f}%{R}")

                # Network I/O delta
                curr_net  = psutil.net_io_counters()
                curr_time = time.time()
                elapsed   = max(curr_time - _prev_time, 1)
                tx_rate   = (curr_net.bytes_sent - _prev_net.bytes_sent) / elapsed
                rx_rate   = (curr_net.bytes_recv - _prev_net.bytes_recv) / elapsed
                _prev_net  = curr_net
                _prev_time = curr_time
                print(f"  Network  {CYN}↑ {_fmt_bytes(tx_rate)}/s   ↓ {_fmt_bytes(rx_rate)}/s{R}")

                if m.wifi_ssid:
                    sig_color = GRN if (m.wifi_signal_dbm or -90) > -65 else YLW
                    print(f"  WiFi     {sig_color}{m.wifi_ssid}{R}  {GRY}{m.wifi_signal_dbm} dBm{R}")
            else:
                print(f"  {GRY}Waiting for first snapshot...{R}")

            # ── Section 3: Network Reconnaissance ────────────────────────────
            print(f"\n{GRN}{BLD}[NETWORK RECONNAISSANCE — TOTAL SURVEILLANCE]{R}")
            devices = vault.get_network_devices()
            active_today = [d for d in devices if d.last_seen.date().isoformat() == today]
            print(
                f"  Total Known Devices: {WHT}{len(devices)}{R}  │  "
                f"Active Today: {WHT}{len(active_today)}{R}"
            )
            print()

            # Column headers
            print(
                f"  {BLD}"
                f"{'IP':16} {'MAC':17} {'MANUFACTURER':14} "
                f"{'NAME':22} {'STATUS/LAST SEEN'}"
                f"{R}"
            )
            print(f"  {GRY}{'─'*92}{R}")

            # Show all devices, gateway first
            sorted_devices = sorted(
                devices,
                key=lambda d: (
                    0 if "hotspot" in (d.device_name or "").lower() or "gateway" in (d.device_name or "").lower() else 1,
                    d.last_seen
                ),
                reverse=True
            )

            for d in sorted_devices[:15]:  # show top 15 (most recent/important)
                name        = (d.device_name or d.mdns_hostname or "Unknown Device")[:21]
                manufacturer = (d.manufacturer or "Unknown")[:13]
                
                # Human-readable last seen
                seen_delta = (now - d.last_seen).total_seconds()
                if seen_delta < 120:
                    status = f"{GRN}● ONLINE{R}"
                elif seen_delta < 3600:
                    status = f"{YLW}{int(seen_delta//60)}m ago{R}"
                else:
                    status = f"{GRY}{int(seen_delta//3600)}h ago{R}"

                # Activity overlay if available
                if d.last_activity and d.last_activity != "Idle / Passive":
                    status = f"{CYN}{d.last_activity[:15]}{R}"

                # Colour-code by device type / gateway
                if "hotspot" in name.lower() or "gateway" in name.lower():
                    name_col = f"{YLW}{name}{R}"
                    mfr_col  = f"{YLW}{manufacturer}{R}"
                elif manufacturer not in ("Unknown", ""):
                    name_col = f"{CYN}{name}{R}"
                    mfr_col  = f"{CYN}{manufacturer}{R}"
                else:
                    name_col = f"{WHT}{name}{R}"
                    mfr_col  = f"{GRY}{manufacturer}{R}"

                print(
                    f"  {d.ip_address:16} {d.mac_address:17} "
                    f"{mfr_col:23} {name_col:31} {status}"
                )
                
                # Extra Detail Row: Traffic Summary
                if d.traffic_summary:
                    print(f"    {GRY}└─ Intelligence: {R}{DIM}{d.traffic_summary}{R}")

            # ── Footer ────────────────────────────────────────────────────────
            print(f"\n{GRY}{'─'*62}{R}")
            print(f"{GRY}  Daemon running stealth as kworker/sys  │  Ctrl+C to exit dashboard{R}")

            time.sleep(2)

        except KeyboardInterrupt:
            print(f"\n{YLW}Exiting dashboard. Daemon remains hidden.{R}")
            break
        except Exception as e:
            print(f"{RED}Dashboard error: {e}{R}")
            time.sleep(5)


if __name__ == "__main__":
    draw_dashboard()
