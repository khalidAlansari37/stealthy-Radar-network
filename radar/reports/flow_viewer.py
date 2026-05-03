"""
Network Flow Viewer — Detailed Traffic Breakdown
================================================
Queries the database for all recorded traffic flows belonging
to a specific IP address and displays them in a rich table.

Usage:
    PYTHONPATH=. .venv/bin/python3 -m radar.reports.flow_viewer <ip_address>
"""

import sys
from datetime import datetime
from radar.database.vault import Vault

def format_bytes(n):
    for unit in ['B', 'KB', 'MB', 'GB']:
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"

def view_flows(ip):
    vault = Vault()
    flows = vault.get_device_flows(ip, limit=100)

    if not flows:
        print(f"\\n[!] No traffic flows found for {ip} in the database.")
        return

    print(f"\\n📡 Detailed Traffic Log for {ip}")
    print("=" * 100)
    print(f"{'Timestamp':<22} | {'Destination':<20} | {'Port':<6} | {'Proto':<8} | {'Service/Domain':<25} | {'Size'}")
    print("-" * 100)

    for f in flows:
        ts = f['timestamp'].split('.')[0].replace('T', ' ')
        dest = f['dst_ip']
        port = f['dst_port']
        proto = f['protocol']
        label = f['service_label'] or "Unknown"
        size = format_bytes(f['byte_count'] or 0)

        print(f"{ts:<22} | {dest:<20} | {port:<6} | {proto:<8} | {label:<25} | {size}")

    print("-" * 100)
    print(f"Showing last {len(flows)} unique connections.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: make flows IP=<ip_address>")
        sys.exit(1)
    
    view_flows(sys.argv[1])
