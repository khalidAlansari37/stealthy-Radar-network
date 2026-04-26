import socket
import struct
import logging
import threading
from typing import Dict, Optional
from radar.database.vault import Vault
from radar.database.models import NetworkDeviceRecord

logger = logging.getLogger(__name__)

class PassiveSentinel:
    """
    Listens for passive network signals (mDNS, SSDP) to identify devices
    without active scanning.
    """
    
    MDNS_GROUP = "224.0.0.251"
    MDNS_PORT = 5353
    SSDP_GROUP = "239.255.255.250"
    SSDP_PORT = 1900

    def __init__(self, vault: Vault = None):
        self.vault = vault or Vault()
        self.running = False
        # In-memory cache of identified data to batch updates
        self.device_cache: Dict[str, Dict] = {}

    def _setup_multicast_socket(self, group: str, port: int):
        """Creates a socket joined to a multicast group."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('', port))
        
        mreq = struct.pack("4sl", socket.inet_aton(group), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        sock.settimeout(2.0)
        return sock

    def _listen_mdns(self):
        """Passively listens for mDNS packets."""
        sock = self._setup_multicast_socket(self.MDNS_GROUP, self.MDNS_PORT)
        logger.info("mDNS listener started.")
        
        while self.running:
            try:
                data, addr = sock.recvfrom(2048)
                ip = addr[0]
                
                # Basic mDNS parsing (looking for hostnames/services)
                # mDNS is DNS over multicast. We look for PTR/SRV records.
                # For now, we just tag the device as 'Seen' and if data contains 
                # identifiable strings like 'iPhone' or 'TV', we log it.
                content = data.decode('utf-8', errors='ignore')
                
                if ".local" in content:
                    # Attempt to extract hostname
                    import re
                    match = re.search(r"([a-zA-Z0-9\-\_]+)\.local", content)
                    if match:
                        hostname = match.group(1)
                        self._update_device_info(ip, mdns_hostname=hostname)
                
            except socket.timeout:
                continue
            except Exception as e:
                logger.debug(f"mDNS parse error: {e}")

    def _listen_ssdp(self):
        """Passively listens for SSDP NOTIFY messages."""
        sock = self._setup_multicast_socket(self.SSDP_GROUP, self.SSDP_PORT)
        logger.info("SSDP listener started.")
        
        while self.running:
            try:
                data, addr = sock.recvfrom(2048)
                ip = addr[0]
                content = data.decode('utf-8', errors='ignore')
                
                if "NOTIFY" in content:
                    # Look for SERVER or deviceType
                    info = {}
                    for line in content.splitlines():
                        if ":" in line:
                            key, val = line.split(":", 1)
                            info[key.strip().upper()] = val.strip()
                    
                    details = info.get("SERVER") or info.get("ST") or ""
                    if details:
                        self._update_device_info(ip, ssdp_info=details[:255])
                        
            except socket.timeout:
                continue
            except Exception as e:
                logger.debug(f"SSDP parse error: {e}")

    def _update_device_info(self, ip: str, mdns_hostname: str = None, ssdp_info: str = None):
        """Queues device info for the database."""
        # Note: Passive listeners only see IP. We need the MAC from ArpScanner to upsert properly.
        # This info will be merged during the next ArpScanner run or via a join in the vault.
        # For now, we'll store it in a temporary table or specialized 'Passive' record.
        # Implementing a simple IP-to-Hostname cache for the ArpScanner.
        
        if ip not in self.device_cache:
            self.device_cache[ip] = {}
        
        if mdns_hostname: self.device_cache[ip]['mdns_hostname'] = mdns_hostname
        if ssdp_info: self.device_cache[ip]['ssdp_info'] = ssdp_info

    def start(self):
        """Starts listeners in background threads."""
        self.running = True
        threading.Thread(target=self._listen_mdns, name="mDNS-Listener", daemon=True).start()
        threading.Thread(target=self._listen_ssdp, name="SSDP-Listener", daemon=True).start()

    def stop(self):
        self.running = False

    def get_info(self, ip: str) -> dict:
        """Returns collected passive info for an IP."""
        return self.device_cache.get(ip, {})
