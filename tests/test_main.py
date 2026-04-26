import pytest
import signal
import threading
import time
from unittest.mock import MagicMock, patch
from radar.main import RadarDaemon

@pytest.fixture
def mock_daemon(mocker):
    # Mock all heavy dependencies
    mocker.patch("radar.main.Vault")
    mocker.patch("radar.main.AppMonitor")
    mocker.patch("radar.main.SystemMonitor")
    mocker.patch("radar.main.ArpScanner")
    mocker.patch("radar.main.ReportingEngine")
    mocker.patch("radar.main.PassiveSentinel")
    mocker.patch("radar.main.start_terminal_monitoring")
    mocker.patch("radar.main.configure_stealth_logging")
    mocker.patch("radar.main.obfuscate_process_name")
    mocker.patch("radar.main.set_low_priority")
    
    return RadarDaemon()

def test_daemon_initialization(mock_daemon):
    assert mock_daemon.vault is not None
    assert mock_daemon.app_monitor is not None
    assert mock_daemon.running is False

def test_daemon_start_stop(mock_daemon, mocker):
    mocker.patch("time.sleep", side_effect=[None, KeyboardInterrupt]) # Stop after 1 tick
    mocker.patch("threading.Thread")
    
    with patch("sys.exit") as mock_exit:
        mock_daemon.start()
        
    assert mock_daemon.running is False
    assert mock_daemon.terminal_observer.stop.called

def test_sleep_wake_detection(mock_daemon, mocker):
    mock_daemon._last_tick = 100
    mocker.patch("time.monotonic", return_value=300) # Gap of 200s
    
    with patch.object(mock_daemon.arp_scanner, "scan") as mock_scan:
        with patch("threading.Thread") as mock_thread:
            mock_daemon._check_sleep_wake()
            assert mock_thread.called # Should trigger immediate scan in thread
    
    assert mock_daemon._last_tick == 300

def test_scheduler_loop(mock_daemon, mocker):
    mock_daemon.running = True
    mock_schedule = mocker.patch("radar.main.schedule")
    # Make loop run once then stop
    mocker.patch("time.sleep", side_effect=[StopIteration])
    
    try:
        mock_daemon._scheduler_loop()
    except StopIteration:
        pass
    
    # Verify that the pulse method was scheduled
    mock_schedule.every().minute.do.assert_any_call(mock_daemon.reporting_engine.pulse)
    assert mock_schedule.run_pending.called

def test_signal_handling(mocker):
    mock_daemon = MagicMock()
    from radar.main import main
    
    mocker.patch("radar.main.RadarDaemon", return_value=mock_daemon)
    mocker.patch("signal.signal")
    
    # We can't easily test the actual signal firing in pytest without side effects, 
    # but we can verify the handler assignment.
    main()
    assert signal.signal.call_count == 2
