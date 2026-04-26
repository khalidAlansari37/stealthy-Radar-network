import pytest
from datetime import datetime
from radar.database.models import (
    AppActivityRecord, TerminalCommandRecord, NetworkDeviceRecord,
    DeviceSessionRecord, SystemMetricRecord, ReportLogRecord
)

def test_app_activity_from_row():
    row = {
        "id": 1,
        "timestamp": datetime.now(),
        "app_name": "Chrome",
        "window_title": "Google Search",
        "process_name": "chrome",
        "process_pid": 1000,
        "is_idle": 0,
        "duration_seconds": 120
    }
    model = AppActivityRecord.from_row(row)
    assert model.app_name == "Chrome"
    assert model.is_idle is False
    assert model.duration_seconds == 120

def test_terminal_command_from_row():
    row = {
        "id": 5,
        "timestamp": datetime.now(),
        "shell": "bash",
        "command": "rm -rf /",
        "working_dir": "/root"
    }
    model = TerminalCommandRecord.from_row(row)
    assert model.command == "rm -rf /"
    assert model.shell == "bash"

def test_network_device_from_row():
    row = {
        "mac_address": "00:11:22:33:44:55",
        "ip_address": "192.168.1.10",
        "device_name": "My iPhone",
        "device_type": "iPhone",
        "confidence": 90,
        "first_seen": datetime.now(),
        "last_seen": datetime.now()
    }
    model = NetworkDeviceRecord.from_row(row)
    assert model.mac_address == "00:11:22:33:44:55"
    assert model.confidence == 90

def test_device_session_from_row():
    row = {
        "mac_address": "AA:BB:CC:DD:EE:FF",
        "session_start": datetime.now(),
        "session_end": None,
        "traffic_level": "HEAVY"
    }
    model = DeviceSessionRecord.from_row(row)
    assert model.mac_address == "AA:BB:CC:DD:EE:FF"
    assert model.traffic_level == "HEAVY"

def test_system_metric_from_row():
    row = {
        "timestamp": datetime.now(),
        "cpu_percent": 15.5,
        "ram_percent": 45.2,
        "disk_percent": 80.1,
        "battery_percent": 100.0,
        "battery_charging": 1,
        "net_bytes_sent": 500,
        "net_bytes_recv": 1200,
        "wifi_ssid": "Home-Network",
        "wifi_signal_dbm": -45
    }
    model = SystemMetricRecord.from_row(row)
    assert model.cpu_percent == 15.5
    assert model.battery_charging is True

def test_report_log_from_row():
    row = {
        "report_date": "2026-04-07",
        "generated_at": datetime.now(),
        "sent_at": None,
        "status": "SENT",
        "retry_count": 0
    }
    model = ReportLogRecord.from_row(row)
    assert model.report_date == "2026-04-07"
    assert model.status == "SENT"
