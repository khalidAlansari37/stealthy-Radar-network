"""
Radar Cleartext Data Auditor — Insecure Protocol Sniffer
========================================================
Audits the network for sensitive data (credentials, tokens, personal info) 
being transmitted without encryption.

Usage:
    sudo make hijack [IP=target_ip]
"""

import sys
import logging
import re
import json
from scapy.all import sniff, IP, TCP, Raw
from radar.database.vault import Vault

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("auditor")

class CleartextAuditor:
    def __init__(self, target_ip: str = None):
        self.target_ip = target_ip
        self.vault = Vault()
        self.captured_count = 0
        
        # Regex for sensitive fields in forms/JSON
        self.sensitive_patterns = [
            r"user", r"pass", r"login", r"email", r"pwd", r"token", 
            r"secret", r"key", r"auth", r"account", r"credential"
        ]
        self.field_re = re.compile(rf"({'|'.join(self.sensitive_patterns)})", re.IGNORECASE)

    def _extract_post_data(self, body):
        """Attempts to parse form data or JSON for sensitive fields."""
        found = []
        # Try JSON first
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                for k, v in data.items():
                    if self.field_re.search(k):
                        found.append(f"{k}={v}")
        except:
            # Fallback to form-urlencoded
            pairs = body.split('&')
            for pair in pairs:
                if '=' in pair:
                    k, v = pair.split('=', 1)
                    if self.field_re.search(k):
                        found.append(pair)
        return found

    def _process_packet(self, pkt):
        if not pkt.haslayer(Raw) or not pkt.haslayer(IP):
            return

        try:
            payload = pkt[Raw].load.decode(errors='ignore')
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            dport = pkt[TCP].dport

            # --- 1. HTTP AUDIT (Port 80/8080) ---
            if dport in [80, 8080] and "HTTP" in payload:
                # Identify Host
                host = "Unknown"
                for line in payload.splitlines():
                    if line.lower().startswith("host:"):
                        host = line.split(":", 1)[1].strip()
                        break

                # Captured Headers (Cookie/Auth)
                if "Cookie:" in payload:
                    cookie = next((l for l in payload.splitlines() if l.lower().startswith("cookie:")), "")
                    self._report_leak(src_ip, host, "Insecure Cookie", cookie, payload[:100])
                
                if "Authorization:" in payload:
                    auth = next((l for l in payload.splitlines() if l.lower().startswith("authorization:")), "")
                    self._report_leak(src_ip, host, "Cleartext Auth", auth, payload[:100])

                # Captured Form/POST Data
                if "POST" in payload:
                    parts = payload.split("\r\n\r\n")
                    if len(parts) > 1:
                        leaks = self._extract_post_data(parts[1])
                        if leaks:
                            self._report_leak(src_ip, host, "Cleartext Form Data", ", ".join(leaks), parts[1])

            # --- 2. FTP AUDIT (Port 21) ---
            elif dport == 21:
                if "USER " in payload or "PASS " in payload:
                    self._report_leak(src_ip, dst_ip, "FTP Credential", payload.strip(), "FTP Protocol")

            # --- 3. TELNET AUDIT (Port 23) ---
            elif dport == 23:
                # Telnet is character-by-character usually, but we catch simple strings
                if len(payload.strip()) > 1:
                    self._report_leak(src_ip, dst_ip, "Telnet Traffic", payload.strip(), "Telnet Protocol")

        except Exception:
            pass

    def _report_leak(self, ip, host, leak_type, value, context):
        """Logs the security leak and saves it to the database."""
        print(f"\n[!] SECURITY ALERT: {leak_type} from {ip}")
        print(f"    Target: {host}")
        print(f"    Leaked Data: {value[:120]}...")
        
        self.vault.insert_credential(ip, host, leak_type, value, context)
        self.captured_count += 1

    def start(self):
        filter_str = "tcp port 80 or tcp port 8080 or tcp port 21 or tcp port 23"
        if self.target_ip:
            filter_str = f"({filter_str}) and host {self.target_ip}"
            logger.info(f"🛡️  Auditing all data for {self.target_ip}...")
        else:
            logger.info("🛡️  Auditing all network data for security leaks...")

        try:
            sniff(filter=filter_str, prn=self._process_packet, store=0)
        except KeyboardInterrupt:
            logger.info(f"\nAudit complete. Total security leaks found: {self.captured_count}")
            sys.exit(0)

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else None
    auditor = CleartextAuditor(target)
    auditor.start()
