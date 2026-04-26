import os
import ctypes
import logging
import sys
from radar.config import settings

logger = logging.getLogger(__name__)

def obfuscate_process_name():
    """
    Renames the current process to a decoy name for stealth.
    Only works on Linux.
    """
    try:
        new_name = settings.stealth.process_name
        if sys.platform.startswith("linux"):
            # Use prctl to set the process name visible in htop/ps
            # 15 is PR_SET_NAME
            libc = ctypes.CDLL("libc.so.6")
            libc.prctl(15, new_name.encode('utf-8'), 0, 0, 0)
            logger.info(f"Process name obfuscated to: {new_name}")
        else:
            logger.warning("Process obfuscation only supported on Linux.")
    except Exception as e:
        logger.error(f"Failed to obfuscate process name: {e}")

def set_low_priority():
    """
    Sets the process to lowest CPU and I/O priority.
    """
    try:
        # 1. CPU Nice Priority
        # 19 is the lowest priority on Linux
        os.nice(19)
        logger.info("CPU priority set to nice (19)")
        
        # 2. I/O Priority (Only on Linux)
        if sys.platform.startswith("linux"):
            # Using ionice via subprocess (simplest for stealth)
            # or we could use libc.syscall(251, ...) for ioprio_set
            # We'll stick to a simple check/log for now as ionice requires root or CAP_SYS_ADMIN
            # But the systemd service file will handle this more robustly.
            pass
            
    except Exception as e:
        logger.error(f"Failed to set process priority: {e}")

def configure_stealth_logging():
    """
    Configures logging to be invisible (file-only, no stdout).
    """
    try:
        from radar.utils.helpers import get_radar_data_dir
        
        log_dir = get_radar_data_dir()
        log_file = log_dir / "radar.log"
        
        # Remove existing handlers
        root_logger = logging.getLogger()
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
            
        # Add file handler
        file_handler = logging.FileHandler(log_file)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
        
        # Set level from config
        root_logger.setLevel(getattr(logging, settings.general.log_level.upper(), logging.WARNING))
        
        # Prevent output to stderr
        sys.stdout = open(os.devnull, 'w')
        sys.stderr = open(os.devnull, 'w')
        
    except Exception as e:
        # If logging fails, we can't really log it stealthily, so we just pass
        pass
