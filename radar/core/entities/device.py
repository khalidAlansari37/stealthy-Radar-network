from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

@dataclass
class Device:
    mac_address: str
    ip_address: str
    device_name: Optional[str] = None
    device_type: str = "Unknown"
    manufacturer: Optional[str] = None
    confidence: int = 0
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    mdns_hostname: Optional[str] = None
    mdns_services: Optional[str] = None
    ssdp_info: Optional[str] = None
    last_activity: Optional[str] = None
    traffic_summary: Optional[str] = None
    total_bytes: int = 0
    ttl: Optional[int] = None
    netbios_name: Optional[str] = None
    os_guess: Optional[str] = None
    open_ports: Optional[str] = None

    @property
    def display_name(self) -> str:
        if self.device_name and self.device_name not in ["Unknown", "Unknown Device"]:
            return self.device_name
        if self.mdns_hostname:
            return self.mdns_hostname
        if self.manufacturer and self.manufacturer != "Unknown":
            return f"{self.manufacturer.split()[0]} Device"
        return f"Device-{self.mac_address.split(':')[-2].upper()}{self.mac_address.split(':')[-1].upper()}"
