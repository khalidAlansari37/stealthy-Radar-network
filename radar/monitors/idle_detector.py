import subprocess
import logging
import os
from radar.config import settings

logger = logging.getLogger(__name__)

# ── Re-use the same X11 env helper used by AppMonitor ─────────────────────────
# Avoids circular import by rebuilding it inline (same logic, no shared import).
def _build_x11_env() -> dict:
    env = os.environ.copy()
    if not env.get("DISPLAY"):
        env["DISPLAY"] = ":0"
    if not env.get("XAUTHORITY"):
        home = os.path.expanduser("~")
        candidates = [
            f"{home}/.Xauthority",
            "/run/user/1000/gdm/Xauthority",
            "/var/run/lightdm/root/:0",
        ]
        for path in candidates:
            if os.path.exists(path):
                env["XAUTHORITY"] = path
                break
    return env

_X11_ENV = _build_x11_env()


class IdleDetector:
    """Detects system idle time (no user input) using xprintidle (Linux/X11)."""
    
    def __init__(self):
        # Convert threshold from seconds to milliseconds
        self.threshold_ms = settings.monitoring.idle_threshold * 1000
        self._tool_missing = False  # avoid spamming warnings

    def get_idle_time_ms(self) -> int:
        """Returns the idle time in milliseconds via xprintidle.

        Passes the correct DISPLAY/XAUTHORITY so the call works even when
        the process is running as a headless systemd service.
        """
        if self._tool_missing:
            return 0
        try:
            result = subprocess.run(
                ["xprintidle"],
                capture_output=True, text=True,
                timeout=2,
                env=_X11_ENV
            )
            if result.returncode == 0 and result.stdout.strip():
                return int(result.stdout.strip())
            return 0
        except FileNotFoundError:
            if not self._tool_missing:
                logger.warning(
                    "xprintidle not found — idle detection disabled. "
                    "Install with: sudo apt install xprintidle"
                )
            self._tool_missing = True
            return 0
        except (subprocess.TimeoutExpired, ValueError, Exception) as e:
            logger.debug(f"xprintidle error: {e}")
            return 0

    def is_idle(self) -> bool:
        """Returns True if system idle time exceeds the configured threshold."""
        if self.threshold_ms <= 0:
            return False
        return self.get_idle_time_ms() >= self.threshold_ms


# Unit test
if __name__ == "__main__":
    detector = IdleDetector()
    print(f"X11 env: DISPLAY={_X11_ENV.get('DISPLAY')} XAUTHORITY={_X11_ENV.get('XAUTHORITY')}")
    print(f"Current idle time: {detector.get_idle_time_ms()} ms")
    print(f"Is idle: {detector.is_idle()}")
