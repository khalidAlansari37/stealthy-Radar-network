import pytest
import subprocess
from unittest.mock import MagicMock, patch
from datetime import datetime
from radar.monitors.idle_detector import IdleDetector
from radar.monitors.app_monitor import AppMonitor
from radar.monitors.system_monitor import SystemMonitor

@pytest.fixture
def mock_vault(mocker):
    return mocker.Mock()

@pytest.fixture
def idle_detector(mocker):
    detector = IdleDetector()
    mocker.patch.object(detector, 'get_idle_time_ms', return_value=1000)
    return detector

def test_idle_detector_is_idle(mocker):
    detector = IdleDetector()
    # Mock settings threshold to 5s (5000ms)
    mocker.patch("radar.config.settings.monitoring.idle_threshold", 5)
    detector.threshold_ms = 5000
    
    mocker.patch.object(detector, 'get_idle_time_ms', return_value=6000)
    assert detector.is_idle() is True
    
    mocker.patch.object(detector, 'get_idle_time_ms', return_value=1000)
    assert detector.is_idle() is False

def test_app_monitor_sample(mocker, mock_vault, idle_detector):
    monitor = AppMonitor(vault=mock_vault, idle_detector=idle_detector)
    
    # Mock xdotool calls
    mock_run = mocker.patch("subprocess.run")
    # First call for PID, second for Title
    mock_run.side_effect = [
        MagicMock(stdout="1234"),
        MagicMock(stdout="Test Window")
    ]
    
    # Mock psutil
    mock_ps = mocker.patch("psutil.Process")
    mock_ps.return_value.name.return_value = "test-app"
    
    record = monitor.sample()
    
    assert record is not None
    assert record.app_name == "test-app"
    assert record.window_title == "Test Window"
    assert record.process_pid == 1234
    assert mock_vault.insert_app_activity.called

def test_app_monitor_xdotool_fail(mocker, mock_vault, idle_detector):
    monitor = AppMonitor(vault=mock_vault, idle_detector=idle_detector)
    # Simulate xdotool missing or failing
    mocker.patch("subprocess.run", side_effect=FileNotFoundError)
    
    pid, title = monitor._get_active_window_info()
    assert pid is None
    assert title == "System / Locked"

def test_app_monitor_psutil_denied(mocker, mock_vault, idle_detector):
    import psutil
    monitor = AppMonitor(vault=mock_vault, idle_detector=idle_detector)
    mocker.patch("subprocess.run", side_effect=[
        MagicMock(stdout="1234"),
        MagicMock(stdout="Test Window")
    ])
    # Simulate psutil access denied
    mock_ps = mocker.patch("psutil.Process")
    mock_ps.return_value.name.side_effect = psutil.AccessDenied(pid=1234)
    
    record = monitor.sample()
    assert record.app_name == "Unknown"

def test_idle_detector_xprintidle_fail(mocker):
    detector = IdleDetector()
    mocker.patch("subprocess.run", side_effect=FileNotFoundError)
    assert detector.get_idle_time_ms() == 0
    assert detector.is_idle() is False
    
    # Test ValueError (malformed output)
    mocker.patch("subprocess.run", return_value=MagicMock(stdout="abc"))
    assert detector.get_idle_time_ms() == 0
    
    # Test Timeout
    mocker.patch("subprocess.run", side_effect=subprocess.TimeoutExpired(["xprintidle"], 1))
    assert detector.get_idle_time_ms() == 0

def test_idle_detector_zero_threshold(mocker):
    detector = IdleDetector()
    mocker.patch("radar.config.settings.monitoring.idle_threshold", 0)
    detector.threshold_ms = 0
    assert detector.is_idle() is False

def test_system_monitor_nmcli_fail(mocker, mock_vault):
    monitor = SystemMonitor(vault=mock_vault)
    mocker.patch("subprocess.run", side_effect=subprocess.CalledProcessError(1, "nmcli"))
    
    ssid, signal = monitor._get_wifi_details()
    assert ssid is None
    assert signal is None
    
    # Test malformed output
    mock_run = mocker.patch("subprocess.run")
    mock_run.return_value.stdout = "yes:SSID:invalid\n"
    ssid, signal = monitor._get_wifi_details()
    assert signal is None

def test_system_monitor_no_battery(mocker, mock_vault):
    monitor = SystemMonitor(vault=mock_vault)
    mocker.patch("psutil.sensors_battery", return_value=None)
    mocker.patch("psutil.cpu_percent", return_value=5.0)
    mocker.patch("psutil.virtual_memory", return_value=MagicMock(percent=50.0))
    mocker.patch("psutil.disk_usage", return_value=MagicMock(percent=50.0))
    mocker.patch("psutil.net_io_counters", return_value=MagicMock(bytes_sent=0, bytes_recv=0))
    
    record = monitor.snapshot()
    assert record.battery_percent == 100.0
    assert record.battery_charging is True

def test_system_monitor_snapshot(mocker, mock_vault):
    monitor = SystemMonitor(vault=mock_vault)
    
    # Mock psutil metrics
    mocker.patch("psutil.cpu_percent", return_value=10.5)
    mocker.patch("psutil.virtual_memory", return_value=MagicMock(percent=45.0))
    mocker.patch("psutil.disk_usage", return_value=MagicMock(percent=60.0))
    mocker.patch("psutil.sensors_battery", return_value=MagicMock(percent=85.0, power_plugged=True))
    mocker.patch("psutil.net_io_counters", return_value=MagicMock(bytes_sent=1000, bytes_recv=2000))
    
    # Mock nmcli WiFi details
    mock_run = mocker.patch("subprocess.run")
    mock_run.return_value.stdout = "yes:MyWiFi:90\n"
    
    record = monitor.snapshot()
    
    assert record is not None
    assert record.cpu_percent == 10.5
    assert record.wifi_ssid == "MyWiFi"
    assert record.wifi_signal_dbm == -55 # (90/2) - 100
    assert mock_vault.insert_system_metric.called

def test_app_monitor_insert_fail(mocker, mock_vault, idle_detector):
    monitor = AppMonitor(vault=mock_vault, idle_detector=idle_detector)
    mocker.patch.object(monitor, '_get_active_window_info', return_value=(1, "Title"))
    mock_vault.insert_app_activity.side_effect = Exception("DB Fail")
    
    record = monitor.sample()
    # It returns None when it fails to insert
    assert record is None

def test_system_monitor_insert_fail(mocker, mock_vault):
    monitor = SystemMonitor(vault=mock_vault)
    mocker.patch("psutil.cpu_percent", return_value=5.0)
    mocker.patch("psutil.virtual_memory", return_value=MagicMock(percent=50.0))
    mocker.patch("psutil.disk_usage", return_value=MagicMock(percent=50.0))
    mocker.patch("psutil.net_io_counters", return_value=MagicMock(bytes_sent=0, bytes_recv=0))
    mocker.patch.object(monitor, '_get_wifi_details', return_value=(None, None))
    mock_vault.insert_system_metric.side_effect = Exception("DB Fail")
    
    record = monitor.snapshot()
    assert record is None
