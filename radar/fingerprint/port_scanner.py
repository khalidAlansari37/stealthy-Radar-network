"""
Port Scanner — Active Service Discovery
========================================
Scans discovered devices for open TCP ports using parallel connection
attempts. Identifies running services (SSH, HTTP, RDP, etc.) and stores
the results back into the device record in the Vault.

Usage:
    from radar.fingerprint.port_scanner import PortScanner
    scanner = PortScanner("192.168.1.50")
    open_ports = scanner.scan()
    print(open_ports)  # [{"port": 22, "service": "SSH"}, ...]

Standalone:
    sudo PYTHONPATH=. .venv/bin/python3 -m radar.fingerprint.port_scanner 192.168.1.50
"""

import socket
import sys
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Well-known port → service name mapping
# ─────────────────────────────────────────────────────────────────────────────
COMMON_PORTS: Dict[int, str] = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    135:  "MS-RPC",
    139:  "NetBIOS",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    548:  "AFP (Apple Filing)",
    554:  "RTSP (Camera)",
    993:  "IMAPS",
    995:  "POP3S",
    1883: "MQTT (IoT)",
    3306: "MySQL",
    3389: "RDP (Remote Desktop)",
    5900: "VNC",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    9100: "Printer (RAW)",
}


class PortScanner:
    """
    Threaded TCP port scanner for a single target IP.
    Uses non-blocking connect_ex() for speed — no root required.
    """

    def __init__(self, target_ip: str, timeout: float = 0.5, max_workers: int = 20):
        self.target_ip = target_ip
        self.timeout = timeout
        self.max_workers = max_workers
        self.open_ports: List[Dict] = []

    def _probe_port(self, port: int) -> Optional[Dict]:
        """Attempts a TCP connection to a single port. Returns result dict or None."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            result = sock.connect_ex((self.target_ip, port))
            if result == 0:
                service = COMMON_PORTS.get(port, f"Unknown-TCP/{port}")
                return {"port": port, "service": service}
        except (socket.timeout, OSError):
            pass
        finally:
            sock.close()
        return None

    def scan(self, ports: Optional[List[int]] = None) -> List[Dict]:
        """
        Scans all common ports in parallel using a thread pool.
        Returns a list of dicts: [{"port": int, "service": str}, ...]
        """
        target_ports = ports or list(COMMON_PORTS.keys())
        logger.info(f"[PortScanner] Scanning {len(target_ports)} ports on {self.target_ip}...")

        self.open_ports = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self._probe_port, p): p for p in target_ports}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.open_ports.append(result)
                    logger.info(f"[PortScanner] OPEN  {self.target_ip}:{result['port']} → {result['service']}")

        # Sort by port number for clean output
        self.open_ports.sort(key=lambda x: x["port"])
        logger.info(f"[PortScanner] Done. {len(self.open_ports)} open ports on {self.target_ip}.")
        return self.open_ports

    def summary(self) -> str:
        """Returns a compact string summary of open ports."""
        if not self.open_ports:
            return "No open ports found"
        parts = [f"{p['port']}/{p['service']}" for p in self.open_ports]
        return "Open ports: " + ", ".join(parts)


# ── Standalone CLI ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    if len(sys.argv) < 2:
        print("Usage: sudo PYTHONPATH=. .venv/bin/python3 -m radar.fingerprint.port_scanner <target_ip>")
        sys.exit(1)

    target = sys.argv[1]
    print(f"\n🔍 Scanning {target} for open ports...\n")
    scanner = PortScanner(target)
    results = scanner.scan()

    if results:
        print(f"\n{'PORT':<8} {'SERVICE'}")
        print("-" * 28)
        for r in results:
            print(f"{r['port']:<8} {r['service']}")
        print(f"\n✅ {len(results)} open port(s) found on {target}")
    else:
        print(f"\n✅ No common ports open on {target}")
