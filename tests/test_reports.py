import pytest
import os
import smtplib
from datetime import datetime
from unittest.mock import MagicMock, patch
from radar.reports.aggregator import DataAggregator
from radar.reports.generator import PdfReportGenerator
from radar.reports.mailer import ReportMailer
from radar.reports.engine import ReportingEngine
from radar.database.models import AppActivityRecord, NetworkDeviceRecord, TerminalCommandRecord, SystemMetricRecord

@pytest.fixture
def mock_vault(mocker):
    return mocker.Mock()

@pytest.fixture
def summary_data():
    return {
        "date": "2026-04-07",
        "apps": {
            "total_seconds": 630, 
            "top_10": [{"name": "Chrome", "minutes": 10.5}],
            "hourly_usage": [0]*24
        },
        "terminal": {
            "total_count": 5, 
            "top_commands": [{"command": "ls", "count": 3}],
            "recent": ["ls -la", "ps aux"]
        },
        "network": {
            "new_count": 1, 
            "active_count": 5, 
            "inventory": [
                {"name": "Ahmed-iPhone", "type": "Mobile", "ip": "1.1.1.1", "mac": "1", "manufacturer": "Apple"}
            ]
        },
        "system": {
            "avg_cpu": 15.2, 
            "avg_ram": 45.0,
            "trends": [{"hour": h, "cpu": 10, "ram": 40, "battery": 90} for h in range(24)]
        }
    }

def test_aggregator_logic(mocker, mock_vault):
    aggregator = DataAggregator(vault=mock_vault)
    
    # Mock vault returns
    now = datetime.now()
    mock_vault.get_app_activity.return_value = [
        AppActivityRecord(
            app_name="Chrome", 
            duration_seconds=600, 
            timestamp=now,
            window_title="Google",
            process_name="chrome",
            process_pid=1234
        )
    ]
    mock_vault.get_terminal_commands.return_value = [
        TerminalCommandRecord(
            command="ls", 
            shell="bash", 
            timestamp=now,
            working_dir="/home"
        )
    ]
    mock_vault.get_network_devices.return_value = [
        NetworkDeviceRecord(
            mac_address="1", 
            ip_address="1.1.1.1", 
            first_seen=now, 
            last_seen=now
        )
    ]
    mock_vault.get_system_metrics.return_value = [
        SystemMetricRecord(
            cpu_percent=10.0, 
            ram_percent=50.0, 
            disk_percent=20.0,
            battery_percent=100.0,
            battery_charging=True,
            net_bytes_sent=100,
            net_bytes_recv=200,
            timestamp=now
        )
    ]
    
    summary = aggregator.get_daily_summary(now.date().isoformat())
    
    assert summary["apps"]["total_seconds"] == 600
    assert summary["apps"]["top_10"][0]["name"] == "Chrome"
    assert summary["network"]["new_count"] == 1
    assert summary["system"]["avg_cpu"] == 10.0

def test_pdf_generator(summary_data, tmp_path):
    generator = PdfReportGenerator(summary_data)
    output_path = str(tmp_path / "report.pdf")
    
    path = generator.generate(output_path)
    assert os.path.exists(path)
    assert path == output_path

def test_mailer_disabled(mocker):
    mocker.patch("radar.config.settings.email.enabled", False)
    mailer = ReportMailer()
    assert mailer.send_report("dummy.pdf") is False

def test_mailer_send_success(mocker, tmp_path):
    mocker.patch("radar.config.settings.email.enabled", True)
    mocker.patch("radar.config.settings.email.sender", "sender@test.com")
    mocker.patch("radar.config.settings.email.recipient", "rcpt@test.com")
    
    mock_smtp = mocker.patch("smtplib.SMTP")
    
    # Create dummy pdf
    pdf_path = tmp_path / "test.pdf"
    pdf_path.write_bytes(b"dummy pdf content")
    
    mailer = ReportMailer()
    success = mailer.send_report(str(pdf_path))
    
    assert success is True
    assert mock_smtp.called

def test_reporting_engine_pulse(mocker, mock_vault, summary_data):
    engine = ReportingEngine(vault=mock_vault)
    
    # Mock should_report_now to True
    mocker.patch.object(engine, '_should_report_now', return_value=True)
    # Mock aggregate, generate, send
    mocker.patch.object(engine.aggregator, 'get_daily_summary', return_value=summary_data)
    mocker.patch("radar.reports.generator.PdfReportGenerator.generate", return_value="/tmp/test.pdf")
    mocker.patch.object(engine.mailer, 'send_report', return_value=True)
    
    # Mock _get_now to return the same date as summary_data
    mock_now = datetime.strptime(summary_data["date"], "%Y-%m-%d")
    mocker.patch.object(engine, '_get_now', return_value=mock_now)
    
    engine.pulse()
    
    assert mock_vault.insert_report_log.called
    assert engine.last_report_date == summary_data["date"]

def test_engine_should_report_now_logic(mocker, mock_vault):
    engine = ReportingEngine(vault=mock_vault)
    mocker.patch("radar.config.settings.general.report_time", "23:00")
    
    # 1. Already reported today
    engine.last_report_date = datetime.now().date().isoformat()
    mocker.patch.object(engine, "_get_now", return_value=datetime.now())
    assert engine._should_report_now() is False
    
    # 2. Not reported today, time matches
    engine.last_report_date = None
    mock_now = datetime.now().replace(hour=23, minute=0)
    mocker.patch.object(engine, "_get_now", return_value=mock_now)
    assert engine._should_report_now() is True
    
    # 3. Not reported today, time doesn't match
    mock_now = datetime.now().replace(hour=10, minute=0)
    mocker.patch.object(engine, "_get_now", return_value=mock_now)
    assert engine._should_report_now() is False
    
    # 4. Invalid time format
    mocker.patch("radar.config.settings.general.report_time", "invalid")
    assert engine._should_report_now() is False

def test_engine_pulse_full(mocker, mock_vault, summary_data):
    engine = ReportingEngine(vault=mock_vault)
    mocker.patch.object(engine, "_should_report_now", return_value=True)
    mocker.patch.object(engine, "generate_and_send", return_value="/tmp/test.pdf")
    
    engine.pulse()
    assert engine.generate_and_send.called

def test_engine_generate_and_send_fail(mocker, mock_vault):
    engine = ReportingEngine(vault=mock_vault)
    # Mock aggregator fail
    mocker.patch.object(engine.aggregator, "get_daily_summary", side_effect=Exception("Agg fail"))
    assert engine.generate_and_send() is None

def test_mailer_retry_logic(mocker, tmp_path):
    mocker.patch("radar.config.settings.email.enabled", True)
    mocker.patch("time.sleep") # Don't actually sleep
    
    # Mock SMTP to fail twice then succeed
    mock_smtp_inst = mocker.Mock()
    # first call fails, second fails, third succeeds
    mock_smtp_inst.send_message.side_effect = [smtplib.SMTPException("Fail 1"), smtplib.SMTPException("Fail 2"), None]
    
    mocker.patch("smtplib.SMTP", return_value=mocker.MagicMock(__enter__=mocker.Mock(return_value=mock_smtp_inst)))
    
    pdf_path = tmp_path / "test.pdf"
    pdf_path.write_bytes(b"pdf")
    
    mailer = ReportMailer()
    success = mailer.send_report(str(pdf_path))
    
    assert success is True
    assert mock_smtp_inst.send_message.call_count == 3

def test_engine_pending_recovery(mocker, mock_vault, summary_data, tmp_path):
    # Setup data dir and pending dir
    radar_dir = tmp_path / ".radar"
    pending_dir = radar_dir / "pending_reports"
    pending_dir.mkdir(parents=True)
    mocker.patch("radar.reports.engine.get_radar_data_dir", return_value=radar_dir)
    
    engine = ReportingEngine(vault=mock_vault)
    
    # 1. Test saving to pending on failure
    mocker.patch.object(engine.aggregator, "get_daily_summary", return_value=summary_data)
    mocker.patch.object(engine.mailer, "send_report", return_value=False)
    
    pdf_path = tmp_path / f"radar_intel_{summary_data['date']}.pdf"
    pdf_path.write_bytes(b"dummy pdf")
    mocker.patch("radar.reports.generator.PdfReportGenerator.generate", return_value=str(pdf_path))
    
    engine.generate_and_send(summary_data["date"])
    
    expected_pending = pending_dir / pdf_path.name
    assert expected_pending.exists()
    assert mock_vault.insert_report_log.called
    
    # 2. Test recovery (resending pending)
    mocker.patch.object(engine.mailer, "send_report", return_value=True)
    engine.process_pending_reports()
    
    assert not expected_pending.exists()
