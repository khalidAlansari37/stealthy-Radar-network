from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field

class AppActivityRecord(BaseModel):
    id: Optional[int] = None
    timestamp: datetime = Field(default_factory=datetime.now)
    app_name: str
    window_title: str
    process_name: str
    process_pid: int
    is_idle: bool = False
    duration_seconds: int = 0

    @classmethod
    def from_row(cls, row: dict):
        return cls(**row)

class TerminalCommandRecord(BaseModel):
    id: Optional[int] = None
    timestamp: datetime = Field(default_factory=datetime.now)
    shell: str
    command: str
    working_dir: Optional[str] = None

    @classmethod
    def from_row(cls, row: dict):
        return cls(**row)

class NetworkDeviceRecord(BaseModel):
    id: Optional[int] = None
    mac_address: str
    ip_address: str
    device_name: Optional[str] = None
    device_type: str = "Unknown"
    manufacturer: Optional[str] = None
    confidence: int = 0
    first_seen: datetime = Field(default_factory=datetime.now)
    last_seen: datetime = Field(default_factory=datetime.now)
    mdns_hostname: Optional[str] = None
    mdns_services: Optional[str] = None
    ssdp_info: Optional[str] = None
    last_activity: Optional[str] = None
    traffic_summary: Optional[str] = None
    total_bytes: int = 0
    ttl: Optional[int] = None
    netbios_name: Optional[str] = None
    os_guess: Optional[str] = None        # Passive OS fingerprint (e.g. "Windows", "iOS")
    open_ports: Optional[str] = None      # JSON list of open ports from port scan

    @classmethod
    def from_row(cls, row: dict):
        return cls(**row)

class DeviceSessionRecord(BaseModel):
    id: Optional[int] = None
    mac_address: str
    session_start: datetime = Field(default_factory=datetime.now)
    session_end: Optional[datetime] = None
    traffic_level: str = "LIGHT"

    @classmethod
    def from_row(cls, row: dict):
        return cls(**row)

class SystemMetricRecord(BaseModel):
    id: Optional[int] = None
    timestamp: datetime = Field(default_factory=datetime.now)
    cpu_percent: float
    ram_percent: float
    disk_percent: float
    battery_percent: float
    battery_charging: bool
    net_bytes_sent: int
    net_bytes_recv: int
    wifi_ssid: Optional[str] = None
    wifi_signal_dbm: Optional[int] = None

    @classmethod
    def from_row(cls, row: dict):
        return cls(**row)

class ReportLogRecord(BaseModel):
    id: Optional[int] = None
    report_date: str  # YYYY-MM-DD
    generated_at: datetime = Field(default_factory=datetime.now)
    sent_at: Optional[datetime] = None
    status: str = "PENDING"
    retry_count: int = 0

    @classmethod
    def from_row(cls, row: dict):
        return cls(**row)
