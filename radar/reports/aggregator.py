import logging
from datetime import datetime, date as date_type
from typing import Dict, Any, List
from collections import Counter
from radar.database.vault import Vault
from radar.database.models import AppActivityRecord, TerminalCommandRecord, NetworkDeviceRecord

logger = logging.getLogger(__name__)

class DataAggregator:
    """Aggregates daily monitoring data into a reporting-ready structure."""
    
    def __init__(self, vault: Vault = None):
        self.vault = vault or Vault()

    def get_daily_summary(self, target_date: str = None) -> Dict[str, Any]:
        """Collects and summarizes all activity for a specific date."""
        if not target_date:
            target_date = date_type.today().isoformat()
            
        logger.info(f"Aggregating data for {target_date}...")
        
        # 1. App Activity
        apps = self.vault.get_app_activity(target_date)
        app_durations = Counter()
        window_durations = Counter()
        hourly_app_usage = [0] * 24
        
        for record in apps:
            app_label = record.app_name or "Unknown Process"
            app_durations[app_label] += record.duration_seconds
            
            # Sub-track window titles (e.g., Code -> "main.py")
            if record.window_title and record.window_title != "N/A":
                window_label = f"{app_label}: {record.window_title}"
                window_durations[window_label] += record.duration_seconds
            
            hour = record.timestamp.hour
            hourly_app_usage[hour] += record.duration_seconds
            
        top_apps = sorted(app_durations.items(), key=lambda x: x[1], reverse=True)[:10]
        top_windows = sorted(window_durations.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # 2. Terminal Commands
        commands = self.vault.get_terminal_commands(target_date)
        cmd_counts = Counter(c.command.split()[0] for c in commands if c.command)
        top_cmds = sorted(cmd_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # 3. Network Reconnaissance
        all_devices = self.vault.get_network_devices()
        new_devices = [d for d in all_devices if d.first_seen.date().isoformat() == target_date]
        # Active today: seen today OR first seen today
        active_devices = [d for d in all_devices if d.last_seen.date().isoformat() == target_date]
        
        # 4. System Metrics
        metrics = self.vault.get_system_metrics(target_date)
        hourly_metrics = {h: {"cpu": [], "ram": [], "battery": []} for h in range(24)}
        for m in metrics:
            h = m.timestamp.hour
            hourly_metrics[h]["cpu"].append(m.cpu_percent)
            hourly_metrics[h]["ram"].append(m.ram_percent)
            hourly_metrics[h]["battery"].append(m.battery_percent)
            
        system_trends = []
        for h in range(24):
            m_set = hourly_metrics[h]
            system_trends.append({
                "hour": h,
                "cpu": sum(m_set["cpu"]) / len(m_set["cpu"]) if m_set["cpu"] else None,
                "ram": sum(m_set["ram"]) / len(m_set["ram"]) if m_set["ram"] else None,
                "battery": sum(m_set["battery"]) / len(m_set["battery"]) if m_set["battery"] else None
            })

        avg_cpu = sum(m.cpu_percent for m in metrics) / len(metrics) if metrics else 0
        avg_ram = sum(m.ram_percent for m in metrics) / len(metrics) if metrics else 0
        
        return {
            "date": target_date,
            "apps": {
                "total_seconds": sum(app_durations.values()),
                "top_10": [{"name": name, "minutes": round(secs/60, 1)} for name, secs in top_apps],
                "top_windows": [{"title": title, "minutes": round(secs/60, 1)} for title, secs in top_windows],
                "hourly_usage": [round(s/60, 1) for s in hourly_app_usage]
            },
            "terminal": {
                "total_count": len(commands),
                "top_commands": [{"command": cmd, "count": count} for cmd, count in top_cmds],
                "recent": [c.command for c in commands[-15:]]
            },
            "network": {
                "new_count": len(new_devices),
                "active_count": len(active_devices),
                "inventory": [
                    {
                        "name": d.device_name or d.mdns_hostname or "Unnamed Hardware",
                        "type": d.device_type or "Unknown",
                        "ip": d.ip_address,
                        "mac": d.mac_address,
                        "manufacturer": d.manufacturer or "Unknown Vendor",
                        "confidence": d.confidence
                    } for d in active_devices
                ]
            },
            "system": {
                "avg_cpu": round(avg_cpu, 1),
                "avg_ram": round(avg_ram, 1),
                "trends": system_trends
            }
        }

if __name__ == "__main__":
    agg = DataAggregator()
    summary = agg.get_daily_summary()
    print(f"Summary for {summary['date']}:")
    print(f"Top App: {summary['apps']['top_5'][0]['name'] if summary['apps']['top_5'] else 'None'}")
    print(f"New Devices: {summary['network']['new_count']}")
