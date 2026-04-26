import pytest
import os
from pathlib import Path
from datetime import datetime
from radar.database.vault import Vault
from radar.database.models import AppActivityRecord, TerminalCommandRecord

@pytest.fixture
def vault(tmp_path, monkeypatch):
    """Fixture to provide a clean Vault pointing to a temporary DB."""
    db_file = tmp_path / ".radar" / "radar.db"
    db_file.parent.mkdir(parents=True, exist_ok=True)
    
    # Mock home directory to use tmp_path
    monkeypatch.setattr("os.path.expanduser", lambda x: str(tmp_path / x[2:]) if x.startswith("~/") else x)
    
    db_dir = tmp_path / ".radar"
    db_dir.mkdir(parents=True, exist_ok=True)
    db_file = db_dir / "radar.db"
    if db_file.exists():
        db_file.unlink()
    
    # Reset singleton for testing
    Vault._instance = None
    v = Vault()
    return v

def test_insert_and_get_app_activity(vault):
    record = AppActivityRecord(
        app_name="TestApp",
        window_title="TestTitle",
        process_name="test.exe",
        process_pid=1234,
        duration_seconds=60
    )
    vault.insert_app_activity(record)
    
    today = datetime.now().strftime("%Y-%m-%d")
    results = vault.get_app_activity(today)
    
    assert len(results) == 1
    assert results[0].app_name == "TestApp"
    assert results[0].duration_seconds == 60

def test_insert_and_get_terminal_commands(vault):
    record = TerminalCommandRecord(
        shell="zsh",
        command="ls -la",
        working_dir="/tmp"
    )
    vault.insert_terminal_command(record)
    
    today = datetime.now().strftime("%Y-%m-%d")
    results = vault.get_terminal_commands(today)
    
    assert len(results) == 1
    assert results[0].command == "ls -la"
    assert results[0].shell == "zsh"

def test_upsert_network_device(vault):
    from radar.database.models import NetworkDeviceRecord
    record = NetworkDeviceRecord(
        mac_address="DE:AD:BE:EF:00:11",
        ip_address="10.0.0.5",
        device_name="Old Name",
        confidence=50
    )
    vault.upsert_network_device(record)
    
    # Update with new name and higher confidence
    record.device_name = "New Name"
    record.confidence = 80
    vault.upsert_network_device(record)
    
    results = vault.get_network_devices()
    assert len(results) == 1
    assert results[0].mac_address == "DE:AD:BE:EF:00:11"
    assert results[0].device_name == "New Name"
    assert results[0].confidence == 80

def test_insert_system_metric(vault):
    from radar.database.models import SystemMetricRecord
    record = SystemMetricRecord(
        cpu_percent=10.0,
        ram_percent=20.0,
        disk_percent=30.0,
        battery_percent=40.0,
        battery_charging=False,
        net_bytes_sent=100,
        net_bytes_recv=200
    )
    vault.insert_system_metric(record)
    
    today = datetime.now().strftime("%Y-%m-%d")
    results = vault.get_system_metrics(today)
    assert len(results) == 1
    assert results[0].cpu_percent == 10.0

def test_report_log(vault):
    from radar.database.models import ReportLogRecord
    date_str = "2026-04-07"
    record = ReportLogRecord(
        report_date=date_str,
        status="SENT"
    )
    vault.insert_report_log(record)
    
    result = vault.get_report_log(date_str)
    assert result is not None
    assert result.report_date == date_str
    assert result.status == "SENT"
