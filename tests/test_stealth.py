import pytest
import os
import sys
import logging
from unittest.mock import MagicMock, patch
from radar.utils.stealth import obfuscate_process_name, set_low_priority, configure_stealth_logging

def test_obfuscate_process_name_linux(mocker):
    mocker.patch("sys.platform", "linux")
    mock_libc = mocker.patch("ctypes.CDLL")
    
    obfuscate_process_name()
    
    # libc.prctl(15, ...)
    assert mock_libc.return_value.prctl.called
    args = mock_libc.return_value.prctl.call_args[0]
    assert args[0] == 15

def test_obfuscate_process_name_non_linux(mocker):
    mocker.patch("sys.platform", "win32")
    mock_libc = mocker.patch("ctypes.CDLL")
    
    obfuscate_process_name()
    assert not mock_libc.called

def test_set_low_priority(mocker):
    mock_nice = mocker.patch("os.nice")
    set_low_priority()
    assert mock_nice.called
    mock_nice.assert_called_with(19)

def test_configure_stealth_logging(mocker, tmp_path):
    # Setup paths
    radar_dir = tmp_path / ".radar"
    radar_dir.mkdir()
    mocker.patch("radar.utils.helpers.get_radar_data_dir", return_value=radar_dir)
    mocker.patch("sys.stdout", MagicMock())
    mocker.patch("sys.stderr", MagicMock())
    
    # Run config
    configure_stealth_logging()
    
    # Check if log file handler added
    root_logger = logging.getLogger()
    handlers = [h for h in root_logger.handlers if isinstance(h, logging.FileHandler)]
    assert len(handlers) >= 1
    assert str(radar_dir / "radar.log") in handlers[0].baseFilename
