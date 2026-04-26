import pytest
import os
from pathlib import Path
from unittest.mock import MagicMock, patch
from radar.monitors.terminal_monitor import TerminalMonitor

@pytest.fixture
def mock_vault(mocker):
    return mocker.Mock()

@pytest.fixture
def monitor(mock_vault, tmp_path, monkeypatch):
    # Mock home directory to tmp_path
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
    
    # Create fake history files
    bash_hist = tmp_path / ".bash_history"
    bash_hist.write_text("ls -la\ncd /tmp\n", encoding="utf8")
    
    zsh_hist = tmp_path / ".zsh_history"
    zsh_hist.write_text(": 1712512345:0;echo hello\n", encoding="utf8")
    
    return TerminalMonitor(vault=mock_vault)

def test_discover_history_files(monitor, tmp_path):
    paths = monitor._discover_history_files()
    assert any(".bash_history" in str(p) for p in paths)
    assert any(".zsh_history" in str(p) for p in paths)

def test_read_new_lines(monitor, tmp_path):
    bash_hist = str(tmp_path / ".bash_history")
    
    # Set offset to current size
    monitor.offsets[bash_hist] = os.path.getsize(bash_hist)
    
    # Append new line
    with open(bash_hist, "a") as f:
        f.write("grep root /etc/passwd\n")
        
    lines = monitor._read_new_lines(bash_hist)
    assert len(lines) == 1
    assert lines[0] == "grep root /etc/passwd"

def test_parse_zsh_line(monitor):
    # Standard format
    assert monitor._parse_zsh_line(": 1712512345:0;ls -la") == "ls -la"
    # Fallback for unexpected format
    assert monitor._parse_zsh_line("regular command") == "regular command"

def test_redaction(monitor, mock_vault, tmp_path):
    bash_hist = str(tmp_path / ".bash_history")
    monitor.offsets[bash_hist] = 0 # Read from start
    
    # Write a sensitive line
    with open(bash_hist, "w") as f:
        f.write("mysql -psecret_password -u root\n")
        
    monitor.process_file_change(bash_hist)
    
    # Check what was inserted in the vault
    assert mock_vault.insert_terminal_command.called
    record = mock_vault.insert_terminal_command.call_args[0][0]
    assert record.command == "[REDACTED]"

def test_process_file_change_bash(monitor, mock_vault, tmp_path):
    bash_hist = str(tmp_path / ".bash_history")
    monitor.offsets[bash_hist] = 0 # Read from start
    
    monitor.process_file_change(bash_hist)
    
    # Should have 2 calls for 'ls -la' and 'cd /tmp'
    assert mock_vault.insert_terminal_command.call_count == 2
    record = mock_vault.insert_terminal_command.call_args_list[0][0][0]
    assert record.shell == "bash"
    assert record.command == "ls -la"

def test_file_rotation(monitor, tmp_path):
    bash_hist = str(tmp_path / ".bash_history")
    monitor.offsets[bash_hist] = 100
    
    # Shrink file (rotation)
    with open(bash_hist, "w") as f:
        f.write("new content\n")
        
    lines = monitor._read_new_lines(bash_hist)
    assert lines == []
    assert monitor.offsets[bash_hist] == len("new content\n")

def test_fish_parsing(monitor, mock_vault, tmp_path):
    fish_hist = str(tmp_path / ".local/share/fish/fish_history")
    os.makedirs(os.path.dirname(fish_hist), exist_ok=True)
    with open(fish_hist, "w") as f:
        f.write("- cmd: echo fish\n  when: 1712512345\n")
    
    monitor.offsets[fish_hist] = 0
    monitor.process_file_change(fish_hist)
    
    assert mock_vault.insert_terminal_command.called
    # In my simple implementation, it treats each line independently
    # We just want to see that it processed 'cmd: echo fish'
    calls = mock_vault.insert_terminal_command.call_args_list
    commands = [c[0][0].command for c in calls]
    assert any("echo fish" in cmd for cmd in commands)

def test_watchdog_handler(monitor, mocker):
    from radar.monitors.terminal_monitor import HistoryEventHandler
    handler = HistoryEventHandler(monitor)
    mock_event = mocker.Mock()
    mock_event.is_directory = False
    mock_event.src_path = "/tmp/.bash_history"
    
    mocker.patch.object(monitor, 'process_file_change')
    handler.on_modified(mock_event)
    
    monitor.process_file_change.assert_called_with("/tmp/.bash_history")

def test_no_history_files(mocker, mock_vault, tmp_path, monkeypatch):
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path / "empty")
    # No files created
    monitor = TerminalMonitor(vault=mock_vault)
    assert monitor._discover_history_files() == []

def test_read_new_lines_exception(monitor, tmp_path, mocker):
    bash_hist = str(tmp_path / ".bash_history")
    mocker.patch("builtins.open", side_effect=IOError("Read error"))
    lines = monitor._read_new_lines(bash_hist)
    assert lines == []

def test_insert_command_exception(monitor, mock_vault, tmp_path):
    bash_hist = str(tmp_path / ".bash_history")
    monitor.offsets[bash_hist] = 0
    mock_vault.insert_terminal_command.side_effect = Exception("DB error")
    
    # This should log an error but not crash
    monitor.process_file_change(bash_hist)
    assert mock_vault.insert_terminal_command.called

def test_start_terminal_monitoring(mocker, mock_vault, tmp_path, monkeypatch):
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
    # Create a history file
    bash_hist = tmp_path / ".bash_history"
    bash_hist.write_text("ls\n", encoding="utf8")
    
    mock_observer = mocker.patch("radar.monitors.terminal_monitor.Observer")
    from radar.monitors.terminal_monitor import start_terminal_monitoring
    
    obs = start_terminal_monitoring(vault=mock_vault)
    assert mock_observer.called
    assert obs == mock_observer.return_value
