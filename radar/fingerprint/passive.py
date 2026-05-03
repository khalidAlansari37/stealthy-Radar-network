import logging
import requests
import socket
import struct
import threading
import time
import re
from datetime import datetime
from typing import Dict, Optional
from scapy.all import sniff, IP, TCP, UDP, DHCP, NBNSQueryRequest, Raw, Ether
from radar.database.vault import Vault
from radar.database.models import NetworkDeviceRecord

logger = logging.getLogger("radar.passive")

# ── SSDP Device Model Parser ──────────────────────────────────────────────────
# Maps common SSDP SERVER string patterns to clean device model names.
_SSDP_MODEL_MAP = [
    (r"Samsung.*SmartTV", "Samsung Smart TV"),
    (r"Samsung.*Tizen", "Samsung Smart TV (Tizen)"),
    (r"LG.*WebOS", "LG Smart TV (WebOS)"),
    (r"Sony.*BRAVIA", "Sony BRAVIA TV"),
    (r"Philips Hue", "Philips Hue Bridge"),
    (r"Sonos", "Sonos Speaker"),
    (r"Amazon.*Fire", "Amazon Fire TV"),
    (r"Roku", "Roku Streaming Device"),
    (r"Xbox", "Xbox Console"),
    (r"PlayStation", "PlayStation Console"),
    (r"Chromecast", "Google Chromecast"),
    (r"Nintendo", "Nintendo Switch"),
    (r"D-Link", "D-Link Router"),
    (r"TP-LINK", "TP-Link Router"),
    (r"Ubiquiti", "Ubiquiti AP"),
    (r"MikroTik", "MikroTik Router"),
    (r"Synology", "Synology NAS"),
    (r"QNAP", "QNAP NAS"),
    (r"Canon", "Canon Printer"),
    (r"Brother", "Brother Printer"),
    (r"HP.*Printer", "HP Printer"),
    (r"Ring", "Ring Doorbell/Camera"),
    (r"Nest", "Google Nest Device"),
    (r"Echo", "Amazon Echo"),
    (r"Windows", "Windows PC"),
    (r"macOS|Mac OS", "macOS Device"),
    (r"Linux.*Android", "Android Device"),
]

# ── mDNS Service Announcement Types ──────────────────────────────────────────
_MDNS_SERVICE_MAP = {
    "_airplay._tcp": "Apple AirPlay (Apple TV / Mac)",
    "_airport._tcp": "Apple AirPort Base Station",
    "_homekit._tcp": "Apple HomeKit Device",
    "_spotify-connect._tcp": "Spotify Connect Speaker",
    "_http._tcp": "Web Server",
    "_ftp._tcp": "FTP Server",
    "_ssh._tcp": "SSH Server",
    "_smb._tcp": "Windows File Sharing",
    "_raop._tcp": "AirPlay Audio (Receiver)",
    "_printer._tcp": "Network Printer",
    "_ipp._tcp": "Network Printer (IPP)",
    "_googlecast._tcp": "Google Chromecast",
    "_matter._tcp": "Matter Smart Home Device",
    "_hap._tcp": "HomeKit Accessory",
    "_workstation._tcp": "Workstation",
    "_daap._tcp": "iTunes Media Server",
    "_rfb._tcp": "VNC Remote Desktop",
    "_androidtvremote._tcp": "Android TV",
    "_adb._tcp": "Android Debug Bridge",
    "_amzn-wplay._tcp": "Amazon Fire TV",
    "_nvstream._tcp": "NVIDIA Shield / GeForce Now",
    "_pstorage._tcp": "PlayStation",
}


def _parse_ssdp_model(server_str: str) -> Optional[str]:
    """Extracts a clean device model name from a raw SSDP SERVER string."""
    for pattern, label in _SSDP_MODEL_MAP:
        if re.search(pattern, server_str, re.IGNORECASE):
            return label
    return None


class PassiveSentinel:
    """
    Passive Intelligence Sentinel — Enterprise Grade.
    Combines mDNS/SSDP listening with deep packet sniffing:
      - DHCP PRL Fingerprinting (100% accurate OS detection)
      - mDNS Service Type Discovery (AirPlay, Chromecast, etc.)
      - SSDP Device Model Extraction (Samsung TV, Sonos, etc.)
      - HTTP Host Header Extraction (exact website from plaintext traffic)
      - User-Agent OS Override (highest-priority OS signal)
      - NetBIOS Hostname Discovery (Windows devices)
      - Credential & Cookie Sniffing (during MITM intercepts)
      - GeoIP Tracking for outbound flows
    """

    MDNS_GROUP = "224.0.0.251"
    MDNS_PORT = 5353
    SSDP_GROUP = "239.255.255.250"
    SSDP_PORT = 1900

    def __init__(self, vault: Vault = None):
        self.vault = vault or Vault()
        self.running = False
        self.geoip_cache = {}
        self.device_cache: Dict[str, Dict] = {}

        # Regex patterns
        self.cookie_re = re.compile(r"Cookie: (.*?)\r\n", re.IGNORECASE)
        self.auth_re = re.compile(r"Authorization: (.*?)\r\n", re.IGNORECASE)
        self.user_agent_re = re.compile(r"User-Agent: (.*?)\r\n", re.IGNORECASE)
        self.host_re = re.compile(r"Host: (.*?)\r\n", re.IGNORECASE)

    # ── Multicast Listeners (mDNS / SSDP) ─────────────────────────────────────

    def _setup_multicast_socket(self, group: str, port: int):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('', port))
        mreq = struct.pack("4sl", socket.inet_aton(group), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        sock.settimeout(2.0)
        return sock

    def _listen_mdns(self):
        """Passively listens for mDNS packets and extracts hostnames + service types."""
        try:
            sock = self._setup_multicast_socket(self.MDNS_GROUP, self.MDNS_PORT)
            logger.info("mDNS listener started.")
        except Exception as e:
            logger.error(f"Failed to start mDNS listener: {e}")
            return

        while self.running:
            try:
                data, addr = sock.recvfrom(4096)
                ip = addr[0]
                content = data.decode('utf-8', errors='ignore')

                # 1. Hostname extraction from .local names
                if ".local" in content:
                    match = re.search(r"([a-zA-Z0-9\-\_]+)\.local", content)
                    if match:
                        hostname = match.group(1)
                        self._update_device_info(ip, mdns_hostname=hostname)

                        # 2. Android mDNS fingerprint — android-XXXX hostnames
                        if re.match(r"android-[a-f0-9]+", hostname, re.IGNORECASE):
                            self._update_device_info(ip, ua_os="Android (UA)")
                            logger.info(f"[mDNS-FP] {ip} → Android (android-* mDNS name)")

                # 3. Service type announcements
                for svc_type, label in _MDNS_SERVICE_MAP.items():
                    if svc_type in content:
                        self._update_device_info(ip, ssdp_info=label)
                        logger.info(f"[mDNS-SVC] {ip} advertises: {label}")
                        break

            except socket.timeout:
                continue
            except (StopIteration, KeyboardInterrupt):
                break
            except Exception as e:
                logger.debug(f"mDNS parse error: {e}")

    def _listen_ssdp(self):
        """Passively listens for SSDP announcements and extracts clean device models."""
        try:
            sock = self._setup_multicast_socket(self.SSDP_GROUP, self.SSDP_PORT)
            logger.info("SSDP listener started.")
        except Exception as e:
            logger.error(f"Failed to start SSDP listener: {e}")
            return

        while self.running:
            try:
                data, addr = sock.recvfrom(4096)
                ip = addr[0]
                content = data.decode('utf-8', errors='ignore')

                if "NOTIFY" in content or "HTTP/1.1 200 OK" in content:
                    info = {}
                    for line in content.splitlines():
                        if ":" in line:
                            parts = line.split(":", 1)
                            if len(parts) == 2:
                                info[parts[0].strip().upper()] = parts[1].strip()

                    server_str = info.get("SERVER") or info.get("X-USER-AGENT") or ""
                    device_type = info.get("ST") or info.get("NT") or ""

                    # Try to parse a clean model name
                    clean_model = _parse_ssdp_model(server_str) or _parse_ssdp_model(device_type)
                    raw_info = clean_model or (server_str[:255] if server_str else device_type[:255])

                    if raw_info:
                        self._update_device_info(ip, ssdp_info=raw_info)
                        logger.info(f"[SSDP] {ip} → {raw_info}")

            except socket.timeout:
                continue
            except (StopIteration, KeyboardInterrupt):
                break
            except Exception as e:
                logger.debug(f"SSDP parse error: {e}")

    def _update_device_info(self, ip: str, mdns_hostname: str = None,
                             ssdp_info: str = None, ua_os: str = None):
        """Caches device info and flushes high-confidence data to DB immediately."""
        if ip not in self.device_cache:
            self.device_cache[ip] = {}
        if mdns_hostname:
            self.device_cache[ip]['mdns_hostname'] = mdns_hostname
        if ssdp_info:
            self.device_cache[ip]['ssdp_info'] = ssdp_info
        if ua_os:
            # This is a high-confidence OS signal — persist it immediately
            self.device_cache[ip]['ua_os'] = ua_os
            try:
                all_devices = self.vault.get_network_devices()
                device = next((d for d in all_devices if d.ip_address == ip), None)
                if device:
                    device.os_guess = ua_os
                    self.vault.upsert_network_device(device)
            except Exception as e:
                logger.debug(f"Failed to persist UA OS for {ip}: {e}")

    def get_info(self, ip: str) -> dict:
        return self.device_cache.get(ip, {})

    # ── GeoIP ─────────────────────────────────────────────────────────────────

    def get_geoip(self, ip: str):
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
        except Exception:
            pass
        return "Unknown Location"

    # ── Main Packet Processor ─────────────────────────────────────────────────

    def process_packet(self, pkt):
        """Main packet processor for the Scapy sniffer."""
        if not pkt.haslayer(IP):
            return

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        ttl = pkt[IP].ttl

        # Safely get MAC (may not have Ethernet layer)
        src_mac = None
        if pkt.haslayer(Ether):
            src_mac = pkt[Ether].src.upper()
        if not src_mac or src_mac == "FF:FF:FF:FF:FF:FF":
            return

        # 1. OS Fingerprinting by TTL (Baseline, overrideable)
        os_guess = None
        if ttl > 64 and ttl <= 128:
            os_guess = "Windows"
        elif ttl <= 64:
            os_guess = "Linux / Android / Unix"

        # 2. Load or create device record
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
            # Only set baseline if no existing higher-confidence guess
            if os_guess and not device.os_guess:
                device.os_guess = os_guess
            device.last_seen = datetime.now()

        # 3. DHCP PRL Fingerprinting (High Confidence)
        if pkt.haslayer(DHCP):
            prl = None
            for opt in pkt[DHCP].options:
                if isinstance(opt, tuple):
                    if opt[0] == 'hostname':
                        device.device_name = opt[1].decode(errors='ignore')
                        logger.info(f"🏷️  DHCP Name: {src_mac} -> {device.device_name}")
                    elif opt[0] == 'param_req_list':
                        if isinstance(opt[1], (bytes, bytearray)):
                            prl = ",".join(str(int(b)) for b in opt[1])
                        elif isinstance(opt[1], str):
                            prl = ",".join(str(ord(c)) for c in opt[1])
                        else:
                            try:
                                prl = ",".join(str(int(b)) for b in opt[1])
                            except Exception:
                                pass

            # DHCP Option 55 OS Fingerprinting — definitive signal
            if prl:
                dhcp_os = None
                if prl.startswith("1,121,3,6,15,114,119,252") or prl.startswith("1,3,6,15,114,119,252,95"):
                    dhcp_os = "iOS (iPhone/iPad) (DHCP)"
                elif prl.startswith("1,3,6,15,119,252,95,44,46"):
                    dhcp_os = "macOS (DHCP)"
                elif prl.startswith("1,3,6,15,31,33,43,44,46,47"):
                    dhcp_os = "Windows (DHCP)"
                elif "1,3,6,15,26,28,51,58,59,43" in prl or prl.startswith("1,3,6,28,51,58,59"):
                    dhcp_os = "Android (DHCP)"
                elif prl.startswith("1,28,2,3,15,6,119,12,44,47"):
                    dhcp_os = "ChromeOS / Linux (DHCP)"
                elif "1,3,6,12,15" in prl:
                    dhcp_os = "Linux (DHCP)"

                if dhcp_os:
                    device.os_guess = dhcp_os
                    logger.info(f"[DHCP-FP] {src_mac} → {dhcp_os}")

        # 4. NetBIOS Discovery (Windows-specific)
        if pkt.haslayer(NBNSQueryRequest):
            try:
                nb_name = pkt[NBNSQueryRequest].QUESTION_NAME.decode(errors='ignore').strip()
                if nb_name:
                    device.device_name = nb_name
                    device.os_guess = "Windows (NetBIOS)"
            except Exception:
                pass

        # 5. HTTP Header Analysis (User-Agent, Host, Cookies, Auth)
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            try:
                payload = pkt[Raw].load.decode(errors='ignore')

                # 5a. User-Agent — HIGHEST PRIORITY OS signal
                ua_match = self.user_agent_re.search(payload)
                if ua_match:
                    ua = ua_match.group(1)
                    ua_os = None
                    try:
                        from ua_parser import user_agent_parser
                        parsed = user_agent_parser.Parse(ua)
                        os_family = parsed.get('os', {}).get('family', 'Other')
                        device_family = parsed.get('device', {}).get('family', 'Other')
                        browser_family = parsed.get('user_agent', {}).get('family', 'Other')

                        if os_family and os_family != 'Other':
                            ua_os = f"{os_family} (UA)"
                        if not device.device_name and device_family and device_family not in ('Other', 'Generic Smartphone', 'Spider'):
                            device.device_name = f"{device_family} ({browser_family})"
                    except ImportError:
                        # Fallback regex UA matching
                        if "Android" in ua:
                            ua_os = "Android (UA)"
                        elif "iPhone" in ua or "iPad" in ua:
                            ua_os = "iOS (UA)"
                        elif "Macintosh" in ua:
                            ua_os = "macOS (UA)"
                        elif "Windows NT" in ua:
                            ua_os = "Windows (UA)"
                        elif "CrOS" in ua:
                            ua_os = "ChromeOS (UA)"
                        elif "Linux" in ua:
                            ua_os = "Linux (UA)"

                    # UA is highest confidence — always override
                    if ua_os:
                        device.os_guess = ua_os
                        logger.info(f"[UA-FP] {src_ip} → {ua_os}")

                # 5b. HTTP Host header — exact website visited
                host_match = self.host_re.search(payload)
                if host_match:
                    host = host_match.group(1).strip().lower()
                    # Store in DNS log for history tracking
                    try:
                        self.vault.insert_dns_log(src_ip, f"[HTTP-HOST] {host}")
                    except Exception:
                        pass
                    logger.debug(f"[HTTP-HOST] {src_ip} → {host}")

                # 5c. Cookie Sniffing
                cookie_match = self.cookie_re.search(payload)
                if cookie_match:
                    self.vault.insert_credential(
                        src_ip, dst_ip, "Cookie",
                        cookie_match.group(1)[:500], payload[:200]
                    )
                    logger.warning(f"🍪 Cookie Captured from {src_ip} for {dst_ip}")

                # 5d. Authorization Header Sniffing
                auth_match = self.auth_re.search(payload)
                if auth_match:
                    self.vault.insert_credential(
                        src_ip, dst_ip, "Authorization",
                        auth_match.group(1)[:500], payload[:200]
                    )
                    logger.warning(f"🔑 Auth Header Captured from {src_ip}")
            except Exception:
                pass

        # 6. Save device record
        try:
            self.vault.upsert_network_device(device)
        except Exception as e:
            logger.debug(f"Failed to upsert device {src_mac}: {e}")

        # 7. GeoIP Tracking for outbound flows
        try:
            if not dst_ip.startswith(("192.168.", "10.", "172.16.", "127.")):
                location = self.get_geoip(dst_ip)
                if location not in ("Unknown Location", "Local Network"):
                    dst_port = pkt[TCP].dport if pkt.haslayer(TCP) else (pkt[UDP].dport if pkt.haslayer(UDP) else 0)
                    self.vault.insert_network_flow(
                        datetime.now(), src_ip, dst_ip,
                        dst_port, "TCP", f"Geo: {location}", len(pkt)
                    )
        except Exception:
            pass

    def _sniff_loop(self, interface: str):
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
        if self.running:
            return
        self.running = True
        threading.Thread(target=self._listen_mdns, name="mDNS-Listener", daemon=True).start()
        threading.Thread(target=self._listen_ssdp, name="SSDP-Listener", daemon=True).start()
        threading.Thread(target=self._sniff_loop, args=(interface,), name="PassiveSniffer", daemon=True).start()
        logger.info("PassiveSentinel started (mDNS + SSDP + DPI).")

    def stop(self):
        self.running = False
        logger.info("PassiveSentinel stopped.")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    ps = PassiveSentinel()
    ps.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        ps.stop()
