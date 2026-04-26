import os
import logging
from pathlib import Path
from typing import List
from radar.database.vault import Vault
from radar.database.models import NetworkDeviceRecord
from radar.utils.helpers import sanitize_filename, get_radar_data_dir

logger = logging.getLogger(__name__)

class DeviceExporter:
    """Generates individual text profile files for every detected device."""
    
    def __init__(self, vault: Vault = None):
        self.vault = vault or Vault()
        self.device_dir = get_radar_data_dir() / "devices"
        self.device_dir.mkdir(parents=True, exist_ok=True)

    def export_device_profile(self, device: NetworkDeviceRecord):
        """Creates or updates a text file for a single device with full history."""
        # Sanitize filename (e.g., "Ahmed's-iPhone (Apple)" -> "Ahmeds-iPhone_Apple.txt")
        filename = f"{sanitize_filename(device.device_name)}_{device.mac_address.replace(':', '')}.txt"
        file_path = self.device_dir / filename
        
        try:
            with open(file_path, "w") as f:
                f.write(f"--- PROJECT RADAR: DEVICE PROFILE ---\n")
                f.write(f"Device Name:  {device.device_name}\n")
                f.write(f"Device Type:  {device.device_type}\n")
                f.write(f"MAC Address:  {device.mac_address}\n")
                f.write(f"Last Known IP: {device.ip_address}\n")
                f.write(f"Confidence:   {device.confidence}%\n")
                f.write(f"First Seen:    {device.first_seen}\n")
                f.write(f"Last Seen:     {device.last_seen}\n")
                f.write("-" * 40 + "\n")
                f.write("RECENT ACTIVITY LOG:\n")
                
                # Fetch recent sessions (this table will be filled in Sprint 4)
                # For now, we'll just log the current snapshot
                f.write(f"[{device.last_seen}] Observed on network at {device.ip_address}\n")
                
            logger.debug(f"Exported profile for {device.mac_address} to {filename}")
        except Exception as e:
            logger.error(f"Failed to export device profile {device.mac_address}: {e}")

    def export_all(self):
        """Exports profile files for all devices in the vault."""
        devices = self.vault.get_network_devices()
        for dev in devices:
            self.export_device_profile(dev)
        logger.info(f"Exported profiles for {len(devices)} devices to {self.device_dir}")

if __name__ == "__main__":
    exporter = DeviceExporter()
    exporter.export_all()
    print(f"Profiles exported to {exporter.device_dir}")
