"""
TrafficSentinel — Deep Packet Inspection Engine
================================================
Passively sniffs ALL network traffic to log:
  - Every unique destination IP + Port + Protocol (SSH, DNS, HTTP, HTTPS, etc.)
  - Per-device activity classification via DNS / TLS SNI
  - OUI hardware manufacturer lookups for every discovered MAC address
  - Hotspot / Gateway auto-labeling

Resilient TLS loading: gracefully falls back if scapy-tls is unavailable.
"""

import logging
import threading

# Suppress noisy Scapy runtime warnings (like Unknown TLS cipher suites)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import socket
import struct
import re
from typing import Dict, Optional, Set, Tuple
from datetime import datetime

# ── Scapy core import ────────────────────────────────────────────────────────
from scapy.all import sniff, DNS, DNSQR, IP, TCP, UDP, Ether, ARP

# ── Resilient TLS layer loading ───────────────────────────────────────────────
HAS_TLS = False
TLSClientHello = None

try:
    from scapy.all import load_layer
    load_layer("tls")
    from scapy.layers.tls.handshake import TLSClientHello as _TLSClientHello
    TLSClientHello = _TLSClientHello
    HAS_TLS = True
except Exception as _tls_err:
    logging.getLogger(__name__).warning(
        f"TLS layer unavailable ({_tls_err}). SNI extraction disabled; DNS-only mode active."
    )

from radar.database.vault import Vault

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# OUI Manufacturer Database
# Built-in lightweight prefix → vendor map (top 200 most common OUIs).
# Falls back gracefully if mac-vendor-lookup is not installed.
# ─────────────────────────────────────────────────────────────────────────────

_OUI_MAP: Dict[str, str] = {
    # Apple
    "00:1A:E3": "Apple", "00:26:08": "Apple", "08:6D:41": "Apple",
    "10:40:F3": "Apple", "18:65:90": "Apple", "1C:91:48": "Apple",
    "20:AB:37": "Apple", "28:CF:E9": "Apple", "34:12:98": "Apple",
    "38:C9:86": "Apple", "3C:15:C2": "Apple", "40:A6:D9": "Apple",
    "44:65:0D": "Apple", "48:43:7C": "Apple", "4C:57:CA": "Apple",
    "50:ED:3C": "Apple", "54:26:96": "Apple", "58:1F:AA": "Apple",
    "5C:59:48": "Apple", "60:03:08": "Apple", "64:A3:CB": "Apple",
    "68:96:7B": "Apple", "6C:72:20": "Apple", "70:73:CB": "Apple",
    "78:4F:43": "Apple", "7C:6D:62": "Apple", "80:82:23": "Apple",
    "84:85:06": "Apple", "88:1F:A1": "Apple", "8C:2D:AA": "Apple",
    "90:72:40": "Apple", "94:BF:2D": "Apple", "98:01:A7": "Apple",
    "9C:35:EB": "Apple", "A0:99:9B": "Apple", "A4:5E:60": "Apple",
    "A8:51:AB": "Apple", "AC:3C:0B": "Apple", "B0:34:95": "Apple",
    "B4:18:D1": "Apple", "B8:09:8A": "Apple", "BC:52:B7": "Apple",
    "C0:9F:42": "Apple", "C4:2C:03": "Apple", "C8:BC:C8": "Apple",
    "CC:08:8D": "Apple", "D0:03:4B": "Apple", "DC:2B:61": "Apple",
    "E0:5F:45": "Apple", "E4:25:E7": "Apple", "E8:04:62": "Apple",
    "F0:CB:A1": "Apple", "F4:F1:5A": "Apple", "F8:1E:DF": "Apple",
    # Samsung
    "00:07:AB": "Samsung", "00:12:47": "Samsung", "00:15:B9": "Samsung",
    "00:1A:8A": "Samsung", "00:1D:25": "Samsung", "00:21:19": "Samsung",
    "00:23:39": "Samsung", "00:26:37": "Samsung", "08:08:C2": "Samsung",
    "08:D4:2B": "Samsung", "0C:14:20": "Samsung", "10:1D:C0": "Samsung",
    "14:32:D1": "Samsung", "18:22:7E": "Samsung", "1C:5A:3E": "Samsung",
    "20:64:32": "Samsung", "24:92:0E": "Samsung", "28:27:BF": "Samsung",
    "2C:AE:2B": "Samsung", "34:14:5F": "Samsung", "38:0A:94": "Samsung",
    "3C:62:00": "Samsung", "40:16:3B": "Samsung", "44:F4:59": "Samsung",
    "48:44:F7": "Samsung", "4C:BC:A5": "Samsung", "50:01:BB": "Samsung",
    "54:88:0E": "Samsung", "5C:0A:5B": "Samsung", "60:6B:BD": "Samsung",
    "64:B3:10": "Samsung", "68:C0:B7": "Samsung", "6C:83:36": "Samsung",
    "70:F9:27": "Samsung", "78:59:5E": "Samsung", "7C:13:80": "Samsung",
    "80:18:A7": "Samsung", "84:11:9E": "Samsung", "88:83:BF": "Samsung",
    "8C:77:12": "Samsung", "94:63:D1": "Samsung", "98:52:B1": "Samsung",
    "9C:02:98": "Samsung", "A0:07:98": "Samsung", "A4:EB:D3": "Samsung",
    "A8:04:60": "Samsung", "AC:5A:14": "Samsung", "B0:47:BF": "Samsung",
    "B4:79:A7": "Samsung", "B8:5A:73": "Samsung", "BC:20:A4": "Samsung",
    "C0:BD:D1": "Samsung", "C4:42:02": "Samsung", "CC:07:AB": "Samsung",
    "D0:17:6A": "Samsung", "D4:87:D8": "Samsung", "D8:31:CF": "Samsung",
    "DC:71:96": "Samsung", "E0:CB:EE": "Samsung", "E4:40:E2": "Samsung",
    "E8:E5:D6": "Samsung", "EC:9B:F3": "Samsung", "F0:25:B7": "Samsung",
    "F4:7B:5E": "Samsung", "F8:04:2E": "Samsung", "FC:A1:3E": "Samsung",
    # Huawei
    "00:9A:CD": "Huawei", "04:02:1F": "Huawei", "04:BD:70": "Huawei",
    "08:19:A6": "Huawei", "0C:96:BF": "Huawei", "10:C6:1F": "Huawei",
    "1C:1D:67": "Huawei", "20:A6:80": "Huawei", "28:6E:D4": "Huawei",
    "2C:AB:00": "Huawei", "30:45:96": "Huawei", "34:6B:D3": "Huawei",
    "38:37:8B": "Huawei", "3C:47:11": "Huawei", "40:4D:8E": "Huawei",
    "48:FB:7E": "Huawei", "4C:1F:CC": "Huawei", "54:51:1B": "Huawei",
    "5A:87:9C": "Huawei", "60:DE:A4": "Huawei", "68:26:08": "Huawei",
    "70:7B:E8": "Huawei", "78:D7:52": "Huawei", "80:FB:06": "Huawei",
    "88:3F:D3": "Huawei", "8C:34:FD": "Huawei", "90:17:AC": "Huawei",
    "94:DB:DA": "Huawei", "98:C7:06": "Huawei", "9C:74:1A": "Huawei",
    "A0:08:6F": "Huawei", "A4:BA:DB": "Huawei", "AC:E2:15": "Huawei",
    "B4:CD:27": "Huawei", "DC:D2:FC": "Huawei", "E8:CD:2D": "Huawei",
    "F4:9F:F3": "Huawei", "F8:98:EF": "Huawei",
    # Xiaomi
    "00:9E:C8": "Xiaomi", "28:6C:07": "Xiaomi", "34:80:B3": "Xiaomi",
    "50:8F:4C": "Xiaomi", "58:44:98": "Xiaomi", "64:09:80": "Xiaomi",
    "6C:C7:EC": "Xiaomi", "74:51:BA": "Xiaomi", "78:11:DC": "Xiaomi",
    "8C:BE:BE": "Xiaomi", "9C:99:A0": "Xiaomi", "A4:C1:38": "Xiaomi",
    "AC:C1:EE": "Xiaomi", "B0:E2:35": "Xiaomi", "BC:9D:42": "Xiaomi",
    "D4:97:0B": "Xiaomi", "F8:A4:5F": "Xiaomi", "FC:64:BA": "Xiaomi",
    # Intel (laptops / Wi-Fi adapters)
    "00:02:B3": "Intel", "00:11:75": "Intel", "00:13:02": "Intel",
    "08:11:96": "Intel", "18:5E:0F": "Intel", "20:16:B9": "Intel",
    "30:3A:64": "Intel", "34:02:86": "Intel", "3C:A9:F4": "Intel",
    "40:25:C2": "Intel", "54:27:1E": "Intel", "60:57:18": "Intel",
    "64:5D:86": "Intel", "68:5D:43": "Intel", "78:0C:B8": "Intel",
    "8C:8D:28": "Intel", "90:61:AE": "Intel", "94:65:2D": "Intel",
    "A4:C3:F0": "Intel", "AC:12:03": "Intel", "D4:BE:D9": "Intel",
    "F4:06:69": "Intel", "F8:16:54": "Intel",
    # Raspberry Pi / Arduino / generic IoT
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi", "28:CD:C1": "Raspberry Pi",
    # Amazon (Echo, FireTV)
    "00:FC:8B": "Amazon", "34:D2:70": "Amazon", "40:B4:CD": "Amazon",
    "44:65:0D": "Amazon", "68:54:FD": "Amazon", "74:75:48": "Amazon",
    "78:E1:03": "Amazon", "84:D6:D0": "Amazon", "A4:08:01": "Amazon",
    "C8:9C:DC": "Amazon", "E4:75:DC": "Amazon", "F0:27:2D": "Amazon",
    # Google (Chromecast, Nest, Pixel)
    "00:1A:11": "Google", "08:9E:08": "Google", "3C:5A:B4": "Google",
    "A4:77:33": "Google", "D4:F5:47": "Google", "F4:F5:D8": "Google",
    # Common Network Gear
    "00:0C:42": "MikroTik", "00:1F:1F": "Edimax", "00:21:27": "Cisco",
    "00:25:9C": "Cisco", "18:E8:29": "Cisco", "2C:33:11": "Ubiquiti",
    "70:A7:41": "Ubiquiti", "80:2A:A8": "Ubiquiti", "B4:FB:E4": "Ubiquiti",
    "00:31:92": "MikroTik", "04:18:D6": "Ubiquiti", "04:18:D6": "Ubiquiti",
    "00:14:D1": "TP-Link", "00:1D:0F": "TP-Link", "00:23:CD": "TP-Link",
    "18:D6:C7": "TP-Link", "30:B5:C2": "TP-Link", "34:96:72": "TP-Link",
    "50:C7:BF": "TP-Link", "60:E3:27": "TP-Link", "70:4F:57": "TP-Link",
    "84:16:F9": "TP-Link", "98:DE:D0": "TP-Link", "A0:F3:C1": "TP-Link",
    "C0:4A:00": "TP-Link", "D8:07:37": "TP-Link", "E8:94:F6": "TP-Link",
    "F4:3E:61": "TP-Link", "F8:1A:67": "TP-Link",
    "00:14:6C": "Netgear", "00:18:4D": "Netgear", "00:1B:2F": "Netgear",
    "00:1E:2A": "Netgear", "00:1F:33": "Netgear", "00:22:3F": "Netgear",
    "00:24:B2": "Netgear", "00:26:F2": "Netgear", "04:A1:51": "Netgear",
    "08:BD:43": "Netgear", "10:0D:7F": "Netgear", "10:DA:43": "Netgear",
    "14:0B:5D": "Netgear", "14:59:C0": "Netgear", "20:4E:7F": "Netgear",
    "28:80:88": "Netgear", "2C:30:33": "Netgear", "2C:B0:5D": "Netgear",
    "30:46:9A": "Netgear", "44:94:FC": "Netgear", "50:6A:03": "Netgear",
    "54:A0:50": "Netgear", "6C:F3:7F": "Netgear", "78:D2:94": "Netgear",
    "84:1B:5E": "Netgear", "90:F6:52": "Netgear", "9C:3D:CF": "Netgear",
    "A0:21:B7": "Netgear", "A0:40:A0": "Netgear", "A4:2B:B0": "Netgear",
    "B0:B9:8A": "Netgear", "B4:75:0E": "Netgear", "BC:4D:FB": "Netgear",
    "C0:3F:0E": "Netgear", "C0:FF:D4": "Netgear", "C4:04:15": "Netgear",
    "E0:46:9A": "Netgear", "E0:91:53": "Netgear", "EC:F0:FE": "Netgear",
    # Others
    "00:11:32": "Synology", "00:08:9B": "QNAP", "00:16:6C": "Linksys",
    "00:10:75": "Seagate", "00:11:09": "Western Digital",
    "00:24:D4": "Xerox", "00:00:AA": "Xerox",
}


def lookup_oui(mac: str) -> str:
    """Looks up the hardware manufacturer for a given MAC address.

    Uses the built-in OUI prefix map first, then attempts python-mac-vendor-lookup
    if installed, otherwise returns 'Unknown'.
    """
    if not mac:
        return "Unknown"

    # Normalise MAC → uppercase colon-separated
    mac_upper = mac.upper().replace("-", ":").replace(".", ":")
    prefix = ":".join(mac_upper.split(":")[:3])

    # 1. Built-in fast lookup
    vendor = _OUI_MAP.get(prefix)
    if vendor:
        return vendor

    # 2. Try mac-vendor-lookup library (optional dependency)
    try:
        from mac_vendor_lookup import MacLookup  # type: ignore
        return MacLookup().lookup(mac) or "Unknown"
    except Exception:
        pass

    return "Unknown"


# ─────────────────────────────────────────────────────────────────────────────
# Protocol classification helpers
# ─────────────────────────────────────────────────────────────────────────────

_PORT_PROTO_MAP: Dict[int, str] = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET",
    25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    80: "HTTP", 110: "POP3", 119: "NNTP", 123: "NTP",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    500: "IKE-VPN", 514: "SYSLOG", 587: "SMTP-TLS",
    993: "IMAPS", 995: "POP3S", 1194: "OpenVPN",
    1701: "L2TP", 1723: "PPTP", 3389: "RDP",
    3478: "STUN/WebRTC", 4500: "IPsec-NAT-T",
    5353: "mDNS", 5555: "ADB", 8080: "HTTP-ALT",
    8443: "HTTPS-ALT", 8883: "MQTT-TLS", 9001: "Tor",
}

_DOMAIN_ACTIVITY_MAP: Dict[str, str] = {
    # Streaming / Video
    "netflix": "Watching Netflix", "nflx": "Watching Netflix",
    "youtube": "Watching YouTube", "googlevideo": "Watching YouTube", "ytimg": "Watching YouTube",
    "twitch": "Watching Twitch", "ttvnw": "Watching Twitch",
    "tiktok": "Watching TikTok", "byteoversea": "Watching TikTok",
    "disneyplus": "Watching Disney+", "dssott": "Watching Disney+",
    "hulu": "Watching Hulu", "hbomax": "Watching HBO Max", "primevideo": "Watching Prime Video",
    "vimeo": "Watching Vimeo", "dailymotion": "Watching Dailymotion",
    "peloton": "Streaming (Peloton)",
    
    # Social Media
    "facebook": "On Facebook", "fbcdn": "On Facebook", "fbsbx": "On Facebook",
    "instagram": "On Instagram", "cdninstagram": "On Instagram",
    "whatsapp": "On WhatsApp", "wa.me": "On WhatsApp",
    "telegram": "Using Telegram", "t.me": "Using Telegram",
    "snapchat": "On Snapchat", "sc-static": "On Snapchat",
    "twitter": "On Twitter/X", "x.com": "On Twitter/X", "twimg": "On Twitter/X",
    "linkedin": "On LinkedIn", "licdn": "On LinkedIn",
    "reddit": "Browsing Reddit", "redditmedia": "Browsing Reddit",
    "pinterest": "On Pinterest", "tumblr": "On Tumblr",
    "discord": "On Discord", "discordapp": "On Discord",
    "beereal": "On BeReal",
    
    # Music / Audio
    "spotify": "Listening to Spotify", "scdn": "Listening to Spotify",
    "apple.com/apple-music": "Apple Music", "itunes": "Apple Music",
    "soundcloud": "On SoundCloud", "deezer": "On Deezer",
    "tidal": "On Tidal", "pandora": "On Pandora",
    
    # Productivity / Work
    "slack": "On Slack", "slack-edge": "On Slack",
    "github": "Coding (GitHub)", "githubusercontent": "Coding (GitHub)",
    "gitlab": "Coding (GitLab)", "bitbucket": "Coding (BitBucket)",
    "stackoverflow": "Researching (StackOverflow)",
    "atlassian": "Using Jira/Confluence", "jira": "Using Jira",
    "zoom": "On Zoom Call", "teams.microsoft": "On Microsoft Teams",
    "webex": "On Webex Call", "notion": "Using Notion",
    "trello": "Using Trello", "asana": "Using Asana",
    "figma": "Designing (Figma)", "canva": "Designing (Canva)",
    "office365": "Using Office 365", "sharepoint": "Using SharePoint",
    "dropbox": "Syncing Dropbox", "box.com": "Syncing Box",
    
    # Search / General Browsing
    "google": "Browsing Google", "bing": "Browsing Bing", "duckduckgo": "Browsing DuckDuckGo",
    "baidu": "Browsing Baidu", "yandex": "Browsing Yandex",
    "wikipedia": "Reading Wikipedia", "medium.com": "Reading Medium",
    "quora": "Reading Quora",
    
    # Shopping
    "amazon": "Shopping (Amazon)", "ebay": "Shopping (eBay)",
    "aliexpress": "Shopping (AliExpress)", "alibaba": "Shopping (Alibaba)",
    "walmart": "Shopping (Walmart)", "target": "Shopping (Target)",
    "shopee": "Shopping (Shopee)", "lazada": "Shopping (Lazada)",
    
    # Mobile OS / Services
    "apple.com": "Apple Services", "icloud": "iCloud Sync", "mzstatic": "App Store",
    "android.com": "Android Services", "googleapis": "Google Services",
    "gvt1.com": "Android System Update", "play.google": "Google Play Store",
    "windowsupdate": "Windows Update", "microsoft.com": "Microsoft Services",
    
    # Gaming
    "playstation": "On PlayStation", "psnprofiles": "On PlayStation",
    "xbox": "On Xbox", "xboxlive": "On Xbox",
    "steam": "Gaming (Steam)", "steampowered": "Gaming (Steam)",
    "epicgames": "Gaming (Epic)", "riotgames": "Gaming (Riot)",
    "valorant": "Gaming (Valorant)", "roblox": "Gaming (Roblox)",
    "minecraft": "Gaming (Minecraft)", "nintendo": "On Nintendo Switch",
    "blizzard": "Gaming (Battle.net)", "ea.com": "Gaming (EA)",
    
    # Artificial Intelligence
    "openai": "Using ChatGPT", "chatgpt": "Using ChatGPT",
    "anthropic": "Using Claude", "claude.ai": "Using Claude",
    "gemini.google": "Using Gemini", "perplexity": "Using Perplexity",
}


def classify_protocol(pkt) -> str:
    """Returns a human-readable protocol name from a packet."""
    if pkt.haslayer(DNS):
        return "DNS"
    if pkt.haslayer(TCP):
        dport = pkt[TCP].dport
        sport = pkt[TCP].sport
        return _PORT_PROTO_MAP.get(dport) or _PORT_PROTO_MAP.get(sport) or f"TCP/{dport}"
    if pkt.haslayer(UDP):
        dport = pkt[UDP].dport
        sport = pkt[UDP].sport
        return _PORT_PROTO_MAP.get(dport) or _PORT_PROTO_MAP.get(sport) or f"UDP/{dport}"
    return "IP"


# ─────────────────────────────────────────────────────────────────────────────
# TrafficSentinel
# ─────────────────────────────────────────────────────────────────────────────

class TrafficSentinel:
    """
    Deep Packet Inspection (DPI) sentinel.

    Captures ALL routed traffic and maintains per-device intelligence:
      • activity_map  : IP → last classified activity string (DNS/SNI)
      • dpi_log       : IP → set of (dst_ip, port, protocol) tuples
      • mac_vendor    : MAC → manufacturer string
    """

    def __init__(self, vault: Vault = None):
        self.vault = vault or Vault()
        self.running = False
        self._thread: Optional[threading.Thread] = None
        self._sync_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

        # Per-device activity label (DNS / SNI derived)
        self.activity_map: Dict[str, str] = {}

        # DPI log: src_ip → set of (dst_ip, dst_port, proto_str)
        self.dpi_log: Dict[str, Set[Tuple[str, int, str]]] = {}
        
        # DNS Cache: IP → Hostname (for website detection)
        self.dns_cache: Dict[str, str] = {}

        # MAC → Manufacturer cache
        self.mac_vendor: Dict[str, str] = {}

        # IP → MAC cache (needed to upsert new devices seen purely via traffic)
        self.ip_to_mac: Dict[str, str] = {}

        # Initialize OS fingerprint cache
        self.os_fingerprints: Dict[str, str] = {}

        # Gateway IP (set externally by ArpScanner)
        self.gateway_ip: Optional[str] = None

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self):
        """Starts the DPI sniffer and sync loops in background threads."""
        if self.running:
            return
        self.running = True
        
        # 1. Main Sniff Loop
        self._thread = threading.Thread(
            target=self._sniff_loop, name="TrafficSentinel-DPI", daemon=True
        )
        self._thread.start()
        
        # 2. Database Sync Loop (Every 10 seconds)
        self._sync_thread = threading.Thread(
            target=self._sync_loop, name="TrafficSentinel-Sync", daemon=True
        )
        self._sync_thread.start()
        
        logger.info("TrafficSentinel (DPI + Sync) started.")

    def _sync_loop(self):
        """Periodically flushes in-memory DPI state to the Vault database."""
        from radar.database.models import NetworkDeviceRecord
        while self.running:
            try:
                # Get a snapshot of current IPs
                with self._lock:
                    ips = list(self.dpi_log.keys())
                    mac_map_copy = dict(self.ip_to_mac)
                
                for ip in ips:
                    activity = self.get_activity(ip)
                    summary = self.get_dpi_summary(ip)
                    mac = mac_map_copy.get(ip)
                    
                    if mac:
                        # Upsert directly if we captured their MAC (handles devices that missed ARP)
                        record = NetworkDeviceRecord(
                            mac_address=mac,
                            ip_address=ip,
                            last_activity=activity,
                            traffic_summary=summary,
                        )
                        vendor = self.mac_vendor.get(mac)
                        if vendor and vendor != "Unknown":
                            record.manufacturer = vendor
                            
                        try:
                            self.vault.upsert_network_device(record)
                        except Exception as e:
                            logger.debug(f"Failed to upsert DPI for {ip}: {e}")
                    else:
                        # Fallback for devices where we somehow missed the Ethernet frame
                        self._update_db_by_ip(ip, activity, summary)
                
            except Exception as e:
                logger.error(f"TrafficSentinel sync loop error: {e}")
            
            time.sleep(2)

    def _update_db_by_ip(self, ip: str, activity: str, summary: str):
        """Updates the vault for a device identified by IP."""
        try:
            # We use a custom SQL update in Vault for this to be efficient
            query = """
            UPDATE network_devices 
            SET last_activity = ?, traffic_summary = ?, last_seen = datetime('now')
            WHERE ip_address = ?
            """
            # We bypass the model objects here for raw speed in the sync loop
            self.vault._execute(query, (activity, summary, ip))
        except Exception as e:
            logger.debug(f"Failed to sync DPI for {ip}: {e}")

    def stop(self):
        self.running = False
        logger.info("TrafficSentinel stopped.")

    # ── Sniff loop ────────────────────────────────────────────────────────────

    def _sniff_loop(self):
        """Main sniffer. Captures ALL IP traffic (no BPF filter restriction)."""
        try:
            # Broad capture: include DNS, SSH, HTTP, HTTPS, and all TCP/UDP
            # Using a permissive filter to give us visibility into every flow
            sniff(
                filter="ip",          # capture all IPv4 packets
                prn=self._process_packet,
                store=0,
                stop_filter=lambda _: not self.running,
            )
        except PermissionError:
            logger.error(
                "TrafficSentinel requires CAP_NET_RAW / root. Sniffing disabled."
            )
        except Exception as e:
            logger.error(f"TrafficSentinel sniff loop crashed: {e}", exc_info=True)

    # ── Packet processor ──────────────────────────────────────────────────────

    def _process_packet(self, pkt):
        """Analyses each captured packet for DPI intelligence."""
        if not pkt.haslayer(IP):
            return

        src_ip: str = pkt[IP].src
        dst_ip: str = pkt[IP].dst

        # Skip localhost / loopback / DHCP broadcast ghosts
        if src_ip.startswith("127.") or dst_ip.startswith("127.") or src_ip == "0.0.0.0":
            return

        # Determine destination port
        dst_port = 0
        if pkt.haslayer(TCP):
            dst_port = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            dst_port = pkt[UDP].dport

        proto = classify_protocol(pkt)

        # ── 1. DPI Log — record every unique (dst_ip, port, protocol) ─────────
        flow_key: Tuple[str, int, str] = (dst_ip, dst_port, proto)
        with self._lock:
            if src_ip not in self.dpi_log:
                self.dpi_log[src_ip] = set()
            is_new = flow_key not in self.dpi_log[src_ip]
            self.dpi_log[src_ip].add(flow_key)

        if is_new:
            logger.debug(
                f"[DPI] {src_ip} → {dst_ip}:{dst_port} [{proto}]"
            )
            # Persist flow to database for granular history
            try:
                # Try to get a hostname for the destination IP
                hostname = self.dns_cache.get(dst_ip)
                service_label = hostname if hostname else proto
                
                self.vault.insert_network_flow(
                    datetime.now(),
                    src_ip,
                    dst_ip,
                    dst_port,
                    proto,
                    service=service_label,
                    bytes=len(pkt)
                )
            except Exception as e:
                logger.debug(f"Failed to persist flow: {e}")

        # ── 2. MAC → OUI Manufacturer ─────────────────────────────────────────
        if pkt.haslayer(Ether):
            mac = pkt[Ether].src
            with self._lock:
                self.ip_to_mac[src_ip] = mac
            if mac and mac not in self.mac_vendor:
                vendor = lookup_oui(mac)
                with self._lock:
                    self.mac_vendor[mac] = vendor
                if vendor != "Unknown":
                    logger.info(f"[OUI] {mac} → {vendor} ({src_ip})")

        # ── 3. DNS Analysis ───────────────────────────────────────────────────
        if pkt.haslayer(DNS):
            dns = pkt.getlayer(DNS)
            # a) Query analysis (for activity + DNS log)
            if dns.qr == 0:
                try:
                    query = pkt.getlayer(DNSQR).qname.decode("utf-8", errors="ignore").rstrip(".").lower()
                    # Log every raw domain to the database
                    try:
                        self.vault.insert_dns_log(src_ip, query)
                    except Exception:
                        pass
                    activity = self._classify_domain(query)
                    if activity:
                        with self._lock:
                            self.activity_map[src_ip] = activity
                        logger.debug(f"[DNS] {src_ip} → {activity} via {query}")
                except Exception:
                    pass
            # b) Response analysis (for IP → Domain mapping)
            elif dns.qr == 1:
                try:
                    for i in range(dns.ancount):
                        res = dns.an[i]
                        if res.type == 1: # A record (IPv4)
                            name = res.rrname.decode("utf-8", errors="ignore").rstrip(".").lower()
                            ip_val = res.rdata
                            with self._lock:
                                self.dns_cache[ip_val] = name
                except Exception:
                    pass

        # ── 4. DNS-over-HTTPS (DoH) Detection ─────────────────────────────────
        if dst_port == 443 and dst_ip in ("1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112"):
            with self._lock:
                self.activity_map[src_ip] = "Encrypted DNS (DoH)"
            logger.info(f"[DoH] {src_ip} -> {dst_ip} (Encrypted DNS)")

        # ── 5. TLS SNI & Application Fingerprinting (if TLS layer available) ──────
        if HAS_TLS and TLSClientHello and pkt.haslayer(TLSClientHello):
            try:
                ch = pkt[TLSClientHello]
                
                # A. SNI Extraction
                sni_raw = getattr(ch, "servername", None)
                if sni_raw:
                    sni = sni_raw.decode("utf-8", errors="ignore").lower()
                    with self._lock:
                        self.dns_cache[dst_ip] = sni
                    activity = self._classify_domain(sni)
                    if activity:
                        with self._lock:
                            self.activity_map[src_ip] = activity
                        logger.debug(f"[SNI] {src_ip} → {activity} via {sni}")

                # B. Basic TLS Application Fingerprinting (JA3-Lite)
                ciphers = getattr(ch, "ciphers", [])
                if ciphers:
                    # Chrome/Chromium uses GREASE ciphers (0x0A0A, 0x1A1A, etc)
                    is_chrome = any((c & 0x0F0F) == 0x0A0A for c in ciphers)
                    num_ciphers = len(ciphers)
                    
                    app_guess = None
                    if is_chrome:
                        app_guess = "Chrome / Chromium"
                    elif num_ciphers == 17:
                        app_guess = "Safari / Apple WebKit"
                    elif num_ciphers == 14:
                        app_guess = "Firefox"
                    elif num_ciphers in (38, 39):
                        app_guess = "Command Line (curl/wget)"
                    elif num_ciphers <= 6:
                        app_guess = "Script (Python/Go/Bot)"

                    if app_guess:
                        with self._lock:
                            curr_activity = self.activity_map.get(src_ip, "")
                            # Don't overwrite high-value domain intelligence
                            if not curr_activity or curr_activity == "Idle / Passive":
                                self.activity_map[src_ip] = f"Using {app_guess}"
                        logger.debug(f"[TLS-FP] {src_ip} -> {app_guess} ({num_ciphers} ciphers)")

            except Exception as e:
                pass

        # ── 6. Advanced Passive OS Fingerprinting (TTL + TCP Window + Options) ────
        if pkt.haslayer(TCP) and pkt[TCP].flags == 0x02:  # SYN packets only
            ttl = pkt[IP].ttl
            window = pkt[TCP].window
            opts = pkt[TCP].options

            os_guess = "Unknown OS"

            # Extract TCP options
            mss = None
            wscale = None
            has_timestamps = False
            for opt in opts:
                if opt[0] == 'MSS': mss = opt[1]
                elif opt[0] == 'WScale': wscale = opt[1]
                elif opt[0] == 'Timestamp': has_timestamps = True

            if ttl <= 64:  # Linux / Unix / macOS / Android / iOS family
                if window == 65535:
                    # macOS/iOS use wscale=5 or 6 with MSS=1460
                    # ANDROID can also produce window=65535 but uses wscale=8 or 9
                    # This is the key differentiation point
                    if wscale in (8, 9, 10, 11, 12):
                        os_guess = "Android"
                    elif wscale in (5, 6) and mss in (1460, 1380):
                        os_guess = "macOS / iOS"
                    elif wscale in (5, 6):
                        os_guess = "iOS (Possible)"
                    else:
                        os_guess = "Linux / Android / BSD"
                elif window == 29200:
                    os_guess = "Linux (Ubuntu/Debian)"
                elif window == 64240:
                    # Android on many kernels uses this window
                    os_guess = "Android"
                elif window in (5840, 14600, 29400):
                    os_guess = "Linux (Kernel 2.x)"
                elif window >= 29000:
                    os_guess = "Linux / Android"
                else:
                    os_guess = "Linux (IoT / Custom)"
            elif ttl <= 128:  # Windows
                if window == 8192:
                    os_guess = "Windows (7 / 8)"
                elif window in (64240, 65535):
                    os_guess = "Windows (10 / 11)"
                elif window == 16384:
                    os_guess = "Windows (Legacy)"
                else:
                    os_guess = "Windows"
            elif ttl <= 255:
                os_guess = "Network Equipment (Cisco/Router)"

            # Only update if we don't have a high-confidence UA-based guess already
            with self._lock:
                current = self.os_fingerprints.get(src_ip, "")
                # High-confidence signals like User-Agent contain "(UA)" tag
                is_ua_confirmed = "(UA)" in current
                if not is_ua_confirmed and current != os_guess and os_guess != "Unknown OS":
                    self.os_fingerprints[src_ip] = os_guess
                    logger.info(f"[OS-FP] {src_ip} → {os_guess} (TTL={ttl}, WIN={window}, WScale={wscale})")
                    try:
                        self.vault.update_os_guess(src_ip, os_guess)
                    except Exception:
                        pass

    # ── Classification helpers ────────────────────────────────────────────────

    def _classify_domain(self, domain: str) -> Optional[str]:
        """Maps a domain name to a human-friendly activity label."""
        for key, label in _DOMAIN_ACTIVITY_MAP.items():
            if key in domain:
                return label
        return None

    # ── Public query API ──────────────────────────────────────────────────────

    def get_activity(self, ip: str) -> str:
        """Returns the last classified activity for a given IP address."""
        # 1. Try friendly map first
        friendly = self.activity_map.get(ip)
        if friendly:
            return friendly
            
        # 2. Try the last captured domain name (DPI hostname)
        # We look for the most recent entry in dns_cache that matches any flow for this IP
        flows = self.dpi_log.get(ip, set())
        for dst_ip, _, _ in flows:
            hostname = self.dns_cache.get(dst_ip)
            if hostname:
                return f"Browsing {hostname}"
                
        return "Idle / Passive"

    def get_manufacturer(self, mac: str) -> str:
        """Returns the hardware manufacturer for a given MAC address."""
        cached = self.mac_vendor.get(mac)
        if cached:
            return cached
        vendor = lookup_oui(mac)
        with self._lock:
            self.mac_vendor[mac] = vendor
        return vendor

    def get_dpi_summary(self, ip: str) -> str:
        """Returns a concise DPI summary string for a given source IP."""
        flows = self.dpi_log.get(ip, set())
        if not flows:
            return "No traffic observed"

        # Collect unique protocols
        protocols = sorted({proto for _, _, proto in flows})
        dst_ips = {dst for dst, _, _ in flows}

        return (
            f"{len(flows)} unique flows | {len(dst_ips)} destinations | "
            f"Protocols: {', '.join(protocols[:6])}"
        )

    def get_all_flows(self, ip: str) -> list:
        """Returns the full DPI flow list for a given source IP as dicts."""
        flows = self.dpi_log.get(ip, set())
        return [
            {"dst_ip": dst, "dst_port": port, "protocol": proto}
            for dst, port, proto in sorted(flows)
        ]


# ── Standalone test ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    import os
    import time

    logging.basicConfig(level=logging.DEBUG)

    if os.getuid() != 0:
        print("ERROR: TrafficSentinel requires sudo / CAP_NET_RAW.")
    else:
        print("Starting DPI sniffing... (Ctrl+C to stop)\n")
        sentinel = TrafficSentinel()
        sentinel.start()

        try:
            while True:
                time.sleep(15)
                print("\n── DPI Activity Snapshot ──────────────────────────")
                for ip, flows in sentinel.dpi_log.items():
                    print(f"  {ip:16s} : {sentinel.get_activity(ip)}")
                    print(f"             {sentinel.get_dpi_summary(ip)}")
                print("────────────────────────────────────────────────────")
        except KeyboardInterrupt:
            sentinel.stop()
