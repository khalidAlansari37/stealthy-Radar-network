import logging
import socket
import re
from typing import Optional, Tuple
from radar.database.vault import Vault
from radar.database.models import NetworkDeviceRecord

logger = logging.getLogger(__name__)

class DeviceProfiler:
    """Fingerprints network devices by MAC address OUI and hostname."""
    
    # Common MAC Address OUI (Organizationally Unique Identifier) mapping
    OUI_MAP = {
        # Apple
        "00:03:93": "Apple", "00:05:02": "Apple", "00:0a:27": "Apple",
        "00:0a:95": "Apple", "00:10:fa": "Apple", "00:11:24": "Apple",
        "00:14:51": "Apple", "00:16:cb": "Apple", "00:17:f2": "Apple",
        "00:19:e3": "Apple", "00:1b:63": "Apple", "00:1c:b3": "Apple",
        "00:1d:4f": "Apple", "00:1e:52": "Apple", "00:1e:c2": "Apple",
        "00:21:e9": "Apple", "00:22:41": "Apple", "00:23:12": "Apple",
        "00:23:df": "Apple", "00:24:36": "Apple", "0c:51:01": "Apple",
        "10:1c:0c": "Apple", "10:40:f3": "Apple", "14:10:9f": "Apple",
        "2c:be:08": "Apple", "34:15:9e": "Apple", "40:4d:7f": "Apple",
        "4c:57:ca": "Apple", "60:03:08": "Apple", "a4:d1:8c": "Apple",
        "f0:d1:a9": "Apple", "bc:d1:d3": "Apple", "d4:61:9d": "Apple",
        
        # Samsung
        "00:00:f0": "Samsung", "00:07:ab": "Samsung", "00:0d:e6": "Samsung",
        "00:12:47": "Samsung", "00:16:db": "Samsung", "00:1b:98": "Samsung",
        "00:21:d2": "Samsung", "18:47:3d": "Samsung", "1c:62:b8": "Samsung",
        "24:fc:e5": "Samsung", "3c:5a:37": "Samsung", "50:85:69": "Samsung",
        
        # Google
        "00:1a:11": "Google", "00:1e:b2": "Google", "3c:5a:b4": "Google",
        "94:eb:cd": "Google", "da:a1:19": "Google",
        
        # Xiaomi / Poco / RedMi
        "00:ec:0a": "Xiaomi", "14:f6:d8": "Xiaomi", "28:6c:07": "Xiaomi",
        "34:80:b3": "Xiaomi", "50:64:2b": "Xiaomi", "64:90:c1": "Xiaomi",
        
        # Huawei / Honor
        "00:d0:2d": "Huawei", "00:e0:fc": "Huawei", "08:19:a6": "Huawei",
        "20:2b:c1": "Huawei", "28:31:52": "Huawei",
        
        # Oppo / Vivo / Realme
        "00:a0:91": "Oppo", "04:b1:67": "Oppo", "50:2e:5c": "Oppo",
        "7c:1a:9b": "Oppo", # The user's device OUI was 7a:1a:9b, 7c is Oppo
        "7a:1a:9b": "Mobile/Generic", # Added user's specific OUI as generic mobile
        "1c:aa:07": "Vivo", "44:0d:10": "Vivo",
        
        # Sony
        "00:01:4a": "Sony", "00:0a:d9": "Sony", "00:13:15": "Sony",
        
        # Microsoft
        "00:15:5d": "Microsoft", "00:03:ff": "Microsoft",
        
        # Networking / Common
        "00:1a:e9": "Intel", "00:04:23": "Intel", "00:19:d1": "Intel",
        "00:25:9c": "Cisco", "00:1d:70": "Cisco",
    }

    def __init__(self, vault: Vault = None):
        self.vault = vault or Vault()

    def _lookup_manufacturer(self, mac_address: str) -> str:
        """Returns the manufacturer name based on the first 3 bytes of the MAC."""
        prefix = mac_address.lower()[:8]
        return self.OUI_MAP.get(prefix, "Unknown Manufacturer")

    def _resolve_hostname(self, ip_address: str) -> str:
        """Attempts to resolve an IP address to a hostname via reverse DNS.
        Uses a short timeout to prevent hangups on unresponsive devices.
        """
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(1.0)
        try:
            # gethostbyaddr returns (hostname, aliaslist, ipaddrlist)
            hostname, _, _ = socket.gethostbyaddr(ip_address)
            return hostname
        except (socket.herror, socket.gaierror, socket.timeout, Exception):
            return "Unnamed-Device"
        finally:
            socket.setdefaulttimeout(old_timeout)

    def profile_device(self, record: NetworkDeviceRecord) -> NetworkDeviceRecord:
        """Fingerprints a single device by analyzing its MAC, IP, and passive signals."""
        manufacturer = self._lookup_manufacturer(record.mac_address)
        
        # Use mDNS hostname as primary if available, fallback to reverse DNS
        hostname = record.mdns_hostname or self._resolve_hostname(record.ip_address)
        ssdp = (record.ssdp_info or "").lower()
        
        # Determine device type from hostname, OUI, or SSDP
        device_type = "Computer"
        search_str = f"{hostname.lower()} {ssdp} {manufacturer.lower()}"
        
        mobile_keywords = ["iphone", "ipad", "phone", "android", "ios", "mobile", "samsung", "xiaomi", "oppo", "vivo", "huawei"]
        if any(s in search_str for s in mobile_keywords):
            device_type = "Mobile"
        elif any(s in search_str for s in ["tv", "cast", "smart", "media", "renderer", "samsung-linux", "tizen", "webos"]):
            device_type = "Smart TV / Media"
        elif any(s in search_str for s in ["playstation", "xbox", "nintendo", "console", "switch"]):
            device_type = "Gaming Console"
        elif manufacturer == "Apple":
            device_type = "Apple Device"
        elif any(s in search_str for s in ["plug", "bulb", "cam", "home", "hub", "alexa", "echo", "nest"]):
            device_type = "IoT Device"
        elif any(s in search_str for s in ["gateway", "router", "ap", "hotspot"]):
            device_type = "Network Device"

        # Construct a name: Ahmeds-iPhone (Apple iPhone)
        clean_hostname = hostname.replace(".local", "").replace(".home", "")
        if clean_hostname == "Unnamed-Device":
            record.device_name = f"{manufacturer} Device"
        else:
            record.device_name = f"{clean_hostname} ({manufacturer})"
            
        record.device_type = device_type
        
        # Base confidence on source quality
        if record.mdns_hostname:
            record.confidence = 90
        elif record.ssdp_info:
            record.confidence = 85
        elif hostname != "Unnamed-Device":
            record.confidence = 80
        else:
            record.confidence = 60
        
        # Save updated record back to vault
        try:
            self.vault.upsert_network_device(record)
        except Exception as e:
            logger.error(f"Failed to update profile for {record.mac_address}: {e}")
            
        return record

    def profile_all(self) -> list[NetworkDeviceRecord]:
        """Profiles all devices currently in the database."""
        devices = self.vault.get_network_devices()
        profiled = []
        for dev in devices:
            profiled.append(self.profile_device(dev))
        return profiled

if __name__ == "__main__":
    profiler = DeviceProfiler()
    print("Profiling detected devices...")
    for dev in profiler.profile_all():
        print(f"[{dev.mac_address}] -> {dev.device_name} ({dev.device_type})")
