import pytest
import socket
from unittest.mock import MagicMock, patch
from radar.fingerprint.passive import PassiveSentinel

@pytest.fixture
def mock_vault(mocker):
    return mocker.Mock()

def test_passive_sentinel_init(mock_vault):
    ps = PassiveSentinel(vault=mock_vault)
    assert ps.vault == mock_vault
    assert ps.running is False

def test_update_device_info(mock_vault):
    ps = PassiveSentinel(vault=mock_vault)
    ps._update_device_info("1.2.3.4", mdns_hostname="my-laptop")
    
    info = ps.get_info("1.2.3.4")
    assert info['mdns_hostname'] == "my-laptop"
    
    ps._update_device_info("1.2.3.4", ssdp_info="SmartTV")
    info = ps.get_info("1.2.3.4")
    assert info['ssdp_info'] == "SmartTV"
    assert info['mdns_hostname'] == "my-laptop"

@patch("socket.socket")
def test_listen_mdns_loop(mock_sock_cls, mocker, mock_vault):
    mock_sock = mock_sock_cls.return_value
    # First recv returns data, second fails with timeout to stop loop
    mock_sock.recvfrom.side_effect = [(b"my-device.local", ("1.1.1.1", 5353)), socket.timeout]
    
    ps = PassiveSentinel(vault=mock_vault)
    ps.running = True
    
    # We call it directly instead of thread for testing simplicity
    ps._listen_mdns()
    
    info = ps.get_info("1.1.1.1")
    assert info['mdns_hostname'] == "my-device"

@patch("socket.socket")
def test_listen_ssdp_loop(mock_sock_cls, mocker, mock_vault):
    mock_sock = mock_sock_cls.return_value
    ssdp_data = b"HTTP/1.1 200 OK\r\nSERVER: Linux/2.6 UPnP/1.0 Samsung TV\r\n\r\n"
    mock_sock.recvfrom.side_effect = [(ssdp_data, ("1.1.1.2", 1900)), socket.timeout]
    
    ps = PassiveSentinel(vault=mock_vault)
    ps.running = True
    
    ps._listen_ssdp()
    
    info = ps.get_info("1.1.1.2")
    assert "Samsung TV" in info['ssdp_info']
