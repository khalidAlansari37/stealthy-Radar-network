import psutil
import logging
import subprocess
from datetime import datetime
from typing import Optional
from radar.config import settings
from radar.database.vault import Vault
from radar.database.models import SystemMetricRecord
from radar.utils.helpers import get_wifi_interface

logger = logging.getLogger(__name__)

class SystemMonitor:
    """Collects system health and connectivity metrics for Project Radar."""
    
    def __init__(self, vault: Vault = None):
        self.vault = vault or Vault()

    def _get_wifi_details(self) -> tuple[Optional[str], Optional[int]]:
        """Returns (SSID, SignalDBM) using nmcli on Linux."""
        try:
            # nmcli -t -f active,ssid,signal dev wifi | grep '^yes'
            # Format: yes:Home-SSID:85
            cmd = ["nmcli", "-t", "-f", "active,ssid,signal", "dev", "wifi"]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=3)
            for line in result.stdout.splitlines():
                if line.startswith("yes:"):
                    parts = line.split(":")
                    if len(parts) >= 3:
                        ssid = parts[1]
                        # signal to dbm approximation: (signal / 2) - 100
                        signal_pct = int(parts[2])
                        dbm = (signal_pct // 2) - 100
                        return ssid, dbm
            return None, None
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError, ValueError):
            return None, None

    def snapshot(self) -> Optional[SystemMetricRecord]:
        """Takes a system metric snapshot and writes it to the vault."""
        try:
            # Metrics using psutil
            cpu_pct = psutil.cpu_percent(interval=1)
            ram_pct = psutil.virtual_memory().percent
            disk_pct = psutil.disk_usage('/').percent
            
            # Battery check
            battery = psutil.sensors_battery()
            bat_pct = battery.percent if battery else 100.0
            bat_charging = battery.power_plugged if battery else True
            
            # Network throughput
            net_io = psutil.net_io_counters()
            
            # WiFi info
            ssid, signal = self._get_wifi_details()

            record = SystemMetricRecord(
                timestamp=datetime.now(),
                cpu_percent=cpu_pct,
                ram_percent=ram_pct,
                disk_percent=disk_pct,
                battery_percent=bat_pct,
                battery_charging=bat_charging,
                net_bytes_sent=net_io.bytes_sent,
                net_bytes_recv=net_io.bytes_recv,
                wifi_ssid=ssid,
                wifi_signal_dbm=signal
            )
            
            self.vault.insert_system_metric(record)
            return record
        except Exception as e:
            logger.error(f"Failed to capture system metric snapshot: {e}")
            return None

# Stand-alone test
if __name__ == "__main__":
    monitor = SystemMonitor()
    print("Capturing system snapshot...")
    record = monitor.snapshot()
    if record:
        print(f"CPU: {record.cpu_percent}% | RAM: {record.ram_percent}%")
        print(f"WiFi: {record.wifi_ssid} ({record.wifi_signal_dbm} dBm)")
