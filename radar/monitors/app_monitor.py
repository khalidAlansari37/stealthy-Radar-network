import subprocess
import logging
import os
import time
from datetime import datetime
import psutil
from typing import Optional, Tuple
from radar.config import settings
from radar.database.vault import Vault
from radar.database.models import AppActivityRecord
from radar.monitors.idle_detector import IdleDetector

logger = logging.getLogger(__name__)

# ── X11 environment bootstrap ──────────────────────────────────────────────────
# When running as a systemd service, the process has no X11 display set.
# We inject DISPLAY/:0 and XAUTHORITY so xdotool can query the desktop session.

def _build_x11_env() -> dict:
    """
    Builds a subprocess environment dict with X11 variables injected.

    Priority order (first found wins):
      1. Values already present in the process environment
      2. Hardcoded fallbacks for the primary desktop user session
    """
    env = os.environ.copy()

    # DISPLAY — try :0, :1 in that order if not already set
    if not env.get("DISPLAY"):
        env["DISPLAY"] = ":0"

    # XAUTHORITY — try the current user's home first, then common paths
    if not env.get("XAUTHORITY"):
        home = os.path.expanduser("~")
        candidates = [
            f"{home}/.Xauthority",
            "/run/user/1000/gdm/Xauthority",   # GDM (GNOME)
            "/var/run/lightdm/root/:0",          # LightDM
        ]
        for path in candidates:
            if os.path.exists(path):
                env["XAUTHORITY"] = path
                break

    return env


_X11_ENV = _build_x11_env()


class AppMonitor:
    """Tracks application usage by sampling the active window focus on Linux (X11)."""
    
    def __init__(self, vault: Vault = None, idle_detector: IdleDetector = None):
        self.vault = vault or Vault()
        self.idle_detector = idle_detector or IdleDetector()
        self.last_sample_time: Optional[float] = None
        self._x11_ok: Optional[bool] = None  # None = not yet tested

    def _get_active_window_info(self) -> Tuple[Optional[int], str]:
        """Returns (PID, WindowTitle) using xdotool with injected X11 environment.

        Gracefully degrades:
        - If X11 is unreachable → returns (None, "System / Locked")
        - If window has no PID  → returns (None, title)
        """
        try:
            # Check for WAYLAND_DISPLAY first to warn about xdotool incompatibility
            if os.environ.get("WAYLAND_DISPLAY") and self._x11_ok is None:
                logger.warning("Wayland detected. xdotool may not work correctly.")

            pid_res = subprocess.run(
                ["xdotool", "getactivewindow", "getwindowpid"],
                capture_output=True, text=True, timeout=3,
                env=_X11_ENV
            )
            title_res = subprocess.run(
                ["xdotool", "getactivewindow", "getwindowname"],
                capture_output=True, text=True, timeout=3,
                env=_X11_ENV
            )

            pid_raw = pid_res.stdout.strip()
            title = title_res.stdout.strip() or "Unknown"

            # xdotool returns exit-code 1 when screen is locked / no window active
            if pid_res.returncode != 0 or not pid_raw:
                if self._x11_ok is None:
                    # First failure: log the display variable for diagnostics
                    logger.warning(
                        f"xdotool could not get active window "
                        f"(DISPLAY={_X11_ENV.get('DISPLAY')}, "
                        f"XAUTHORITY={_X11_ENV.get('XAUTHORITY')}). "
                        "Will retry on next sample."
                    )
                self._x11_ok = False
                return None, "System / Locked"

            self._x11_ok = True
            pid = int(pid_raw)
            return pid, title

        except FileNotFoundError:
            logger.error("xdotool not found. Install with: sudo apt install xdotool")
            return None, "System / Locked"
        except (subprocess.TimeoutExpired, ValueError, Exception) as e:
            logger.debug(f"_get_active_window_info error: {e}")
            return None, "System / Locked"

    def sample(self) -> Optional[AppActivityRecord]:
        """Samples the current active window and writes a record to the database."""
        current_time = time.time()
        pid, title = self._get_active_window_info()
        is_idle = self.idle_detector.is_idle()
        
        # Determine process name from PID
        process_name = "System"
        if pid:
            try:
                process = psutil.Process(pid)
                process_name = process.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                process_name = "Unknown"

        # Fallback for Chrome/Browsers if the process name is generic but title is specific
        app_name = process_name if process_name != "System" else "Idle/System"
        if "google-chrome" in title.lower() or "google chrome" in title.lower():
            app_name = "Google Chrome"
        elif "firefox" in title.lower():
            app_name = "Firefox"

        duration = 0
        if self.last_sample_time:
            duration = int(current_time - self.last_sample_time)
        
        record = AppActivityRecord(
            timestamp=datetime.fromtimestamp(current_time),
            app_name=app_name,
            window_title=title,
            process_name=process_name,
            process_pid=pid or 0,
            is_idle=is_idle,
            duration_seconds=duration
        )
        
        try:
            self.vault.insert_app_activity(record)
            self.last_sample_time = current_time
            return record
        except Exception as e:
            logger.error(f"Failed to record app activity: {e}")
            return None


# Simple stand-alone runner for testing
if __name__ == "__main__":
    monitor = AppMonitor()
    print(f"X11 env: DISPLAY={_X11_ENV.get('DISPLAY')} XAUTHORITY={_X11_ENV.get('XAUTHORITY')}")
    print("Sampling active window focus...")
    record = monitor.sample()
    if record:
        print(f"Captured: {record.app_name} | {record.window_title} | Idle: {record.is_idle}")
