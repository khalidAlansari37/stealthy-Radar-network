import pytest
import os
import socket
from unittest.mock import MagicMock, patch
from radar.fingerprint.scanner import ArpScanner
from radar.fingerprint.profiler import DeviceProfiler
from radar.fingerprint.exporter import DeviceExporter
from radar.database.models import NetworkDeviceRecord

@pytest.fixture
def mock_vault(mocker):
    return mocker.Mock()

@pytest.fixture
def mock_interface(mocker):
    mocker.patch("radar.fingerprint.scanner.get_wifi_interface", return_value="wlan0")
    mocker.patch("radar.fingerprint.scanner.get_local_subnet", return_value="192.168.1.0/24")

def test_arp_scanner_scan(mocker, mock_vault, mock_interface):
    scanner = ArpScanner(vault=mock_vault)
    
    # Mock Scapy srp (Send/Receive Packets)
    # ans = [(send_packet, receive_packet), ...]
    mock_receive = MagicMock()
    mock_receive.psrc = "192.168.1.50"
    mock_receive.hwsrc = "00:11:22:33:44:55"
    
    mocker.patch("radar.fingerprint.scanner.srp", return_value=([(None, mock_receive)], []))
    
    results = scanner.scan()
    
    assert len(results) == 1
    assert results[0].ip_address == "192.168.1.50"
    assert results[0].mac_address == "00:11:22:33:44:55"
    assert mock_vault.upsert_network_device.called

def test_arp_scanner_no_subnet(mocker, mock_vault):
    mocker.patch("radar.fingerprint.scanner.get_wifi_interface", return_value="lo")
    mocker.patch("radar.fingerprint.scanner.get_local_subnet", return_value=None)
    scanner = ArpScanner(vault=mock_vault)
    assert scanner.scan() == []

def test_arp_scanner_permission_error(mocker, mock_vault, mock_interface):
    scanner = ArpScanner(vault=mock_vault)
    mocker.patch("radar.fingerprint.scanner.srp", side_effect=PermissionError)
    assert scanner.scan() == []

def test_arp_scanner_exception(mocker, mock_vault, mock_interface):
    scanner = ArpScanner(vault=mock_vault)
    mocker.patch("radar.fingerprint.scanner.srp", side_effect=Exception("Error"))
    assert scanner.scan() == []

def test_arp_scanner_upsert_fail(mocker, mock_vault, mock_interface):
    scanner = ArpScanner(vault=mock_vault)
    mock_receive = MagicMock()
    mock_receive.psrc = "1.1.1.1"
    mock_receive.hwsrc = "AA:BB"
    mocker.patch("radar.fingerprint.scanner.srp", return_value=([(None, mock_receive)], []))
    mock_vault.upsert_network_device.side_effect = Exception("DB Fail")
    results = scanner.scan()
    assert len(results) == 0

def test_device_profiler_apple(mocker, mock_vault):
    profiler = DeviceProfiler(vault=mock_vault)
    record = NetworkDeviceRecord(
        mac_address="00:03:93:11:22:33", # Apple OUI
        ip_address="192.168.1.5",
        device_name="Unknown"
    )
    
    # Mock DNS lookup
    mocker.patch("socket.gethostbyaddr", return_value=("Ahmed-iPhone.local", [], []))
    
    profiled = profiler.profile_device(record)
    
    assert "Apple" in profiled.device_name
    assert "Ahmed-iPhone" in profiled.device_name
    assert profiled.device_type == "Mobile"
    assert profiled.confidence == 80

def test_device_profiler_apple_mac(mocker, mock_vault):
    profiler = DeviceProfiler(vault=mock_vault)
    record = NetworkDeviceRecord(
        mac_address="00:03:93:11:22:33", 
        ip_address="192.168.1.5",
        device_name="Unknown"
    )
    mocker.patch("socket.gethostbyaddr", return_value=("MyMac.local", [], []))
    profiled = profiler.profile_device(record)
    assert profiled.device_type == "Apple Device"

def test_device_profiler_unknown(mocker, mock_vault):
    profiler = DeviceProfiler(vault=mock_vault)
    record = NetworkDeviceRecord(
        mac_address="FF:FF:FF:11:22:33", 
        ip_address="192.168.1.5",
        device_name="Unknown"
    )
    
    # Mock DNS failure
    mocker.patch("socket.gethostbyaddr", side_effect=socket.herror)
    
    profiled = profiler.profile_device(record)
    assert "Unknown Manufacturer" in profiled.device_name
    assert profiled.device_type == "Computer"
    assert profiled.confidence == 60

def test_device_profiler_tv(mocker, mock_vault):
    profiler = DeviceProfiler(vault=mock_vault)
    record = NetworkDeviceRecord(
        mac_address="00:11:22:33:44:55",
        ip_address="192.168.1.5",
        device_name="Unknown"
    )
    mocker.patch("socket.gethostbyaddr", return_value=("SmartTV-Bedroom", [], []))
    profiled = profiler.profile_device(record)
    assert profiled.device_type == "Smart TV"

def test_device_profiler_upsert_fail(mocker, mock_vault):
    profiler = DeviceProfiler(vault=mock_vault)
    record = NetworkDeviceRecord(mac_address="A:B", ip_address="1.1.1.1")
    mocker.patch("socket.gethostbyaddr", return_value=("pc", [], []))
    mock_vault.upsert_network_device.side_effect = Exception("DB Fail")
    # Should not crash
    profiler.profile_device(record)

def test_device_profiler_all(mocker, mock_vault):
    profiler = DeviceProfiler(vault=mock_vault)
    mock_vault.get_network_devices.return_value = [
        NetworkDeviceRecord(mac_address="1:1", ip_address="1.1.1.1")
    ]
    mocker.patch.object(profiler, 'profile_device')
    profiler.profile_all()
    assert profiler.profile_device.called

def test_device_exporter(mocker, mock_vault, tmp_path):
    exporter = DeviceExporter(vault=mock_vault)
    # Mock home directory to tmp_path
    exporter.device_dir = tmp_path / "devices"
    exporter.device_dir.mkdir()
    
    device = NetworkDeviceRecord(
        mac_address="AA:BB:CC:DD:EE:FF",
        ip_address="10.0.0.1",
        device_name="Test-Device (Mock)",
        device_type="Sensor"
    )
    
    exporter.export_device_profile(device)
    
    # Check if file exists
    files = list(exporter.device_dir.glob("*.txt"))
    assert len(files) == 1
    content = files[0].read_text()
    assert "AA:BB:CC:DD:EE:FF" in content
    assert "Test-Device" in content

def test_device_exporter_write_fail(mocker, mock_vault, tmp_path):
    exporter = DeviceExporter(vault=mock_vault)
    exporter.device_dir = tmp_path / "fail"
    # Don't create dir, will cause error in open()
    device = NetworkDeviceRecord(mac_address="A", device_name="B", ip_address="1.1.1.1")
    # Should not crash
    exporter.export_device_profile(device)

def test_device_exporter_all(mocker, mock_vault, tmp_path):
    exporter = DeviceExporter(vault=mock_vault)
    exporter.device_dir = tmp_path / "all"
    exporter.device_dir.mkdir()
    mock_vault.get_network_devices.return_value = [
        NetworkDeviceRecord(mac_address="1", device_name="D1", ip_address="1.1.1.1"),
        NetworkDeviceRecord(mac_address="2", device_name="D2", ip_address="2.2.2.2")
    ]
    exporter.export_all()
    assert len(list(exporter.device_dir.glob("*.txt"))) == 2
