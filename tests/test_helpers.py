import pytest
from radar.utils.helpers import format_duration, sanitize_filename

def test_format_duration():
    assert format_duration(60) == "1m"
    assert format_duration(3600) == "1h 0m"
    assert format_duration(3660) == "1h 1m"
    assert format_duration(7200) == "2h 0m"

def test_sanitize_filename():
    assert sanitize_filename("iPhone 14 Pro") == "iPhone_14_Pro"
    assert sanitize_filename("../bad/path") == "path"
    assert sanitize_filename("") == "unknown"

def test_detect_os(mocker):
    import platform
    mocker.patch("platform.system", return_value="Linux")
    from radar.utils.helpers import detect_os
    assert detect_os() == "linux"
    
    mocker.patch("platform.system", return_value="Darwin")
    assert detect_os() == "macos"
    
    mocker.patch("platform.system", return_value="Windows")
    assert detect_os() == "windows"

def test_get_wifi_interface(mocker):
    import netifaces
    mocker.patch("netifaces.gateways", return_value={
        'default': {netifaces.AF_INET: ('192.168.1.1', 'wlan0')}
    })
    from radar.utils.helpers import get_wifi_interface
    assert get_wifi_interface() == "wlan0"

def test_get_local_subnet(mocker):
    import netifaces
    mocker.patch("netifaces.gateways", return_value={
        'default': {netifaces.AF_INET: ('192.168.1.1', 'wlan0')}
    })
    mocker.patch("netifaces.ifaddresses", return_value={
        netifaces.AF_INET: [{'addr': '192.168.1.10', 'netmask': '255.255.255.0'}]
    })
    from radar.utils.helpers import get_local_subnet
    assert get_local_subnet() == "192.168.1.0/24"
