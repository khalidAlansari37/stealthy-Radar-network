import logging
from typing import List, Dict, Optional, TYPE_CHECKING
if TYPE_CHECKING:
    from radar.fingerprint.traffic import TrafficSentinel
from scapy.all import ARP, Ether, srp
from radar.config import settings
from radar.database.vault import Vault
from radar.database.models import NetworkDeviceRecord
from radar.fingerprint.passive import PassiveSentinel
from radar.utils.helpers import get_local_subnet, get_wifi_interface
from radar.fingerprint.traffic import lookup_oui

logger = logging.getLogger(__name__)

# Port scan runs in a thread pool so it never blocks the ARP sweep.
import concurrent.futures
_port_scan_executor = concurrent.futures.ThreadPoolExecutor(max_workers=4, thread_name_prefix="radar-portscan")

class ArpScanner:
    """Performs ARP scanning to identify active devices on the local network."""
    
    def __init__(self, vault: Vault = None, passive_sentinel: PassiveSentinel = None, traffic_sentinel: Optional['TrafficSentinel'] = None):
        self.vault = vault or Vault()
        self.passive_sentinel = passive_sentinel
        self.traffic_sentinel = traffic_sentinel

    def _get_gateway_ip(self) -> Optional[str]:
        """Returns the default gateway IP address."""
        try:
            import netifaces
            gateways = netifaces.gateways()
            return gateways.get('default', {}).get(netifaces.AF_INET, [None])[0]
        except Exception:
            return None

    def _send_mdns_wake_pulse(self, interface: str):
        """Sends a broadcast mDNS query to wake up sleeping clients (phones)."""
        try:
            from scapy.all import IP, UDP, DNS, DNSQR, send
            pulse = IP(dst="224.0.0.251")/UDP(sport=5353, dport=5353)/DNS(rd=1, qd=DNSQR(qname="_services._dns-sd._udp.local", qtype="PTR"))
            send(pulse, iface=interface, verbose=False)
            logger.info("Sent mDNS wake-up pulse to network.")
        except Exception as e:
            logger.debug(f"Failed to send mDNS pulse: {e}")

    def scan(self, interface: Optional[str] = None) -> List[NetworkDeviceRecord]:
        """Runs an ARP scan on the current subnet and returns a list of detected devices."""
        if not interface:
            interface = get_wifi_interface()
            
        subnet = get_local_subnet(interface)
        if not subnet:
            logger.error(f"Could not determine subnet for interface: {interface}")
            return []

        # Step 0: Wake up the network
        self._send_mdns_wake_pulse(interface)
        gateway_ip = self._get_gateway_ip()

        # Inform TrafficSentinel of the gateway so it can tag it in DPI logs
        if self.traffic_sentinel and gateway_ip:
            self.traffic_sentinel.gateway_ip = gateway_ip

        logger.info(f"Starting ARP scan on {subnet} via {interface}...")
        
        try:
            ans, unans = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
                timeout=settings.network.scan_timeout,
                iface=interface,
                verbose=False
            )
            
            detected_devices = []
            for send_pkt, receive in ans:
                ip = receive.psrc
                mac = receive.hwsrc
                
                if ip == "0.0.0.0" or ip.startswith("127."):
                    continue
                
                # ── OUI Manufacturer Lookup ───────────────────────────────────
                # Try TrafficSentinel cache first (populated by DPI sniffer),
                # then fall back to direct OUI lookup.
                manufacturer = "Unknown"
                if self.traffic_sentinel:
                    manufacturer = self.traffic_sentinel.get_manufacturer(mac)
                if manufacturer == "Unknown":
                    manufacturer = lookup_oui(mac)

                record = NetworkDeviceRecord(
                    mac_address=mac,
                    ip_address=ip,
                    device_name="Unknown Device",
                    manufacturer=manufacturer,
                    confidence=50
                )
                
                # ── Gateway / Hotspot Auto-label ──────────────────────────────
                if ip == gateway_ip:
                    record.device_name = "Phone Hotspot / Gateway"
                    record.device_type = "Mobile"
                    record.confidence = 90
                    logger.info(f"Gateway detected: {ip} ({mac}) → Phone Hotspot")
                elif manufacturer != "Unknown":
                    # Give a named device label based on manufacturer
                    record.device_name = f"{manufacturer} Device"
                    record.confidence = 70
                
                # ── Passive Sentinel Enrichment (mDNS / SSDP) ────────────────
                if self.passive_sentinel:
                    info = self.passive_sentinel.get_info(ip)
                    record.mdns_hostname = info.get('mdns_hostname')
                    record.ssdp_info = info.get('ssdp_info')
                    if record.mdns_hostname:
                        record.device_name = record.mdns_hostname
                        record.confidence = 85
                
                # ── Live Traffic Activity (DPI) ───────────────────────────────
                if self.traffic_sentinel:
                    activity = self.traffic_sentinel.get_activity(ip)
                    if activity != "Idle / Passive":
                        logger.info(f"[DPI] {ip} Activity: {activity}")
                        record.last_activity = activity
                    
                    # Also store DPI summary in ssdp_info field as extra intel
                    dpi_summary = self.traffic_sentinel.get_dpi_summary(ip)
                    if dpi_summary != "No traffic observed":
                        # Append DPI summary to ssdp_info (overwrite only if empty)
                        if not record.ssdp_info:
                            record.ssdp_info = f"DPI: {dpi_summary}"
                
                # ── Upsert into database ──────────────────────────────────────
                try:
                    self.vault.upsert_network_device(record)
                    detected_devices.append(record)
                    logger.info(
                        f"Device: {ip} | {mac} | {manufacturer} | "
                        f"{record.device_name} | {record.last_activity or 'Idle'}"
                    )
                    # ── Background Port Scan ──────────────────────────────────
                    _port_scan_executor.submit(self._scan_ports_bg, mac, ip)
                except Exception as e:
                    logger.error(f"Failed to upsert network device {mac}: {e}")
            
            logger.info(f"Scan complete. Found {len(detected_devices)} devices.")
            return detected_devices

        except PermissionError:
            logger.error("ARP scanning requires root/sudo privileges.")
            return []
        except Exception as e:
            logger.error(f"Unexpected error during scan: {e}")
            return []

    def _scan_ports_bg(self, mac: str, ip: str):
        """Runs a port scan for a device in the background and stores results."""
        try:
            import json
            from radar.fingerprint.port_scanner import PortScanner
            scanner = PortScanner(ip)
            results = scanner.scan()
            if results:
                self.vault.update_open_ports(mac, json.dumps(results))
                logger.info(f"[PortScan] {ip} → {scanner.summary()}")
        except Exception as e:
            logger.debug(f"Background port scan failed for {ip}: {e}")


# Stand-alone test
if __name__ == "__main__":
    import os
    if os.geteuid() != 0:
        print("Error: Scanner must be run with sudo.")
    else:
        scanner = ArpScanner()
        results = scanner.scan()
        for dev in results:
            print(f"  {dev.ip_address:16s} | {dev.mac_address} | {dev.manufacturer:12s} | {dev.device_name}")
