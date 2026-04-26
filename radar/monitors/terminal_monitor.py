import os
import time
import logging
import re
from typing import List, Dict, Optional
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from radar.config import settings
from radar.database.vault import Vault
from radar.database.models import TerminalCommandRecord

logger = logging.getLogger(__name__)

class TerminalMonitor:
    """Monitors shell history files (Bash, Zsh, Fish) for new commands."""
    
    def __init__(self, vault: Vault = None):
        self.vault = vault or Vault()
        self.history_paths = self._discover_history_files()
        # Track offset to read only new lines
        self.offsets: Dict[str, int] = {}
        for path in self.history_paths:
            if os.path.exists(path):
                self.offsets[path] = os.path.getsize(path)

    def _discover_history_files(self) -> List[str]:
        """Identifies common shell history file paths on Linux."""
        home = str(Path.home())
        candidates = [
            os.path.join(home, ".bash_history"),
            os.path.join(home, ".zsh_history"),
            os.path.join(home, ".histfile"), # some Zsh configs
            os.path.join(home, ".local/share/fish/fish_history")
        ]
        return [c for c in candidates if os.path.exists(c)]

    def _read_new_lines(self, path: str) -> List[str]:
        """Reads only the newly appended lines from a history file."""
        try:
            current_size = os.path.getsize(path)
            last_offset = self.offsets.get(path, 0)
            
            if current_size <= last_offset:
                # File was truncated/rotated or no new data
                self.offsets[path] = current_size
                return []
                
            with open(path, "r", errors="replace") as f:
                f.seek(last_offset)
                new_data = f.read()
            
            self.offsets[path] = current_size
            return new_data.splitlines()
        except Exception as e:
            logger.error(f"Error reading history file {path}: {e}")
            return []

    def _parse_zsh_line(self, line: str) -> Optional[str]:
        """Parses Zsh extended history format: ': <epoch>:0;<command>'."""
        if line.startswith(":"):
            # Format: : 1712512345:0;ls -la
            match = re.match(r":\s\d+:0;(.*)", line)
            if match:
                return match.group(1)
        return line

    def process_file_change(self, path: str):
        """Processes a detected file change, parses new commands, and inserts into DB."""
        lines = self._read_new_lines(path)
        shell = "bash" if "bash" in path else "zsh" if "zsh" in path else "fish"
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            command = line
            if shell == "zsh":
                command = self._parse_zsh_line(line)
            
            # Simple placeholder for redaction (will be expanded)
            if any(s in command for s in ["password", "secret", "token", "key"]):
                command = "[REDACTED]"
            
            record = TerminalCommandRecord(
                shell=shell,
                command=command,
                working_dir=os.getcwd()
            )
            try:
                self.vault.insert_terminal_command(record)
            except Exception as e:
                logger.error(f"Failed to record command: {e}")

class HistoryEventHandler(FileSystemEventHandler):
    """Watchdog event handler that triggers TerminalMonitor processing."""
    def __init__(self, monitor: TerminalMonitor):
        self.monitor = monitor

    def on_modified(self, event):
        if not event.is_directory:
            self.monitor.process_file_change(event.src_path)

def start_terminal_monitoring(vault: Vault = None):
    """Initialize and start the background watchdog observer for history files."""
    monitor = TerminalMonitor(vault)
    handler = HistoryEventHandler(monitor)
    observer = Observer()
    
    for path in monitor.history_paths:
        parent_dir = os.path.dirname(path)
        observer.schedule(handler, parent_dir, recursive=False)
        logger.info(f"Monitoring history file: {path}")

    observer.start()
    return observer

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print("Starting Terminal History Monitor Watchdog...")
    obs = start_terminal_monitoring()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        obs.stop()
    obs.join()
