import os
import platform
import socket
from typing import Optional
from datetime import datetime
from pathlib import Path
import netifaces

def detect_os() -> str:
    """Returns the current operating system family."""
    system = platform.system().lower()
    if "linux" in system:
        return "linux"
    elif "darwin" in system:
        return "macos"
    elif "windows" in system:
        return "windows"
    return "unknown"

def format_duration(seconds: int) -> str:
    """Formats a duration in seconds into a human-readable string (e.g. 4h 23m)."""
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    if hours > 0:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"

def get_local_subnet(interface: Optional[str] = None) -> str:
    """Detects the current local IPv4 subnet (e.g. 192.168.1.0/24)."""
    try:
        if not interface:
            gateways = netifaces.gateways()
            default_gw = gateways.get('default', {}).get(netifaces.AF_INET)
            if not default_gw:
                return "127.0.0.1/32"
            interface = default_gw[1]
        
        addr = netifaces.ifaddresses(interface).get(netifaces.AF_INET)
        if not addr:
            return "127.0.0.1/32"
            
        ip = addr[0]['addr']
        mask = addr[0]['netmask']
        
        # Simple bitcount for mask
        cidr = sum(bin(int(x)).count('1') for x in mask.split('.'))
        
        # Calculate network address (IP AND MASK)
        ip_parts = [int(x) for x in ip.split('.')]
        mask_parts = [int(x) for x in mask.split('.')]
        net_parts = [str(ip_p & mask_p) for ip_p, mask_p in zip(ip_parts, mask_parts)]
        
        return f"{'.'.join(net_parts)}/{cidr}"
    except Exception:
        return "127.0.0.1/32"

def get_wifi_interface() -> str:
    """Identifies the default network interface name."""
    try:
        gateways = netifaces.gateways()
        return gateways['default'][netifaces.AF_INET][1]
    except Exception:
        return "eth0"

def get_default_gateway_ip() -> Optional[str]:
    """Returns the IP address of the default gateway (router)."""
    try:
        gateways = netifaces.gateways()
        return gateways['default'][netifaces.AF_INET][0]
    except Exception:
        return None

def sanitize_filename(name: str) -> str:
    """Sanitizes a string to be used as a filename."""
    if not name:
        return "unknown"
    # Extract basename to prevent path traversal
    base = os.path.basename(name)
    # Filter allowed characters and strip leading dots/spaces
    sanitized = "".join([c for c in base if c.isalnum() or c in (' ', '.', '_', '-')]).strip().replace(' ', '_')
    # Prevent hidden files if not intended or empty names
    sanitized = sanitized.lstrip('.')
    return sanitized if sanitized else "unknown"

def get_radar_data_dir() -> Path:
    """Returns the Radar data directory, creating it if necessary.
    Respects RADAR_DATA_DIR environment variable for cross-user persistence.
    """
    env_path = os.environ.get("RADAR_DATA_DIR")
    if env_path:
        path = Path(env_path)
    else:
        path = Path(os.path.expanduser("~/.radar/"))
    
    path.mkdir(parents=True, exist_ok=True)
    return path
