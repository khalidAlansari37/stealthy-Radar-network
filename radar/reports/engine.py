import time
import logging
import shutil
from datetime import datetime
from typing import Optional
from pathlib import Path
from radar.config import settings
from radar.database.vault import Vault
from radar.database.models import ReportLogRecord
from radar.reports.aggregator import DataAggregator
from radar.reports.generator import PdfReportGenerator
from radar.reports.mailer import ReportMailer
from radar.utils.helpers import get_radar_data_dir

logger = logging.getLogger(__name__)

class ReportingEngine:
    """The central engine that schedules and runs intelligence reports."""
    
    def __init__(self, vault: Vault = None):
        self.vault = vault or Vault()
        self.aggregator = DataAggregator(self.vault)
        self.mailer = ReportMailer()
        self.last_report_date = None
        self.pending_dir = get_radar_data_dir() / "pending_reports"
        self.pending_dir.mkdir(parents=True, exist_ok=True)

    def _get_now(self) -> datetime:
        """Helper to get current time (mockable for tests)."""
        return datetime.now()

    def _should_report_now(self) -> bool:
        """Checks if the current time matches the scheduled report time."""
        now = self._get_now()
        current_date = now.date().isoformat()
        
        # If we already reported today, stop
        if self.last_report_date == current_date:
            return False
            
        # Parse scheduled time
        try:
            sched_h, sched_m = map(int, settings.general.report_time.split(":"))
            if now.hour == sched_h and now.minute == sched_m:
                return True
        except Exception as e:
            logger.error(f"Invalid report_time format: {settings.general.report_time}: {e}")
            
        return False

    def generate_and_send(self, target_date: str = None) -> Optional[str]:
        """Manually triggers a report generation and delivery."""
        if not target_date:
            target_date = self._get_now().date().isoformat()
            
        logger.info(f"Triggering intelligence report pulse for {target_date}...")
        
        try:
            # 1. Aggregate
            summary = self.aggregator.get_daily_summary(target_date)
            
            # 2. Generate PDF
            generator = PdfReportGenerator(summary)
            pdf_path = generator.generate()
            
            # 3. Deliver (if enabled)
            success = self.mailer.send_report(pdf_path, target_date)
            
            # 4. Handle failure (save for later)
            if not success:
                pending_path = self.pending_dir / Path(pdf_path).name
                logger.warning(f"Report delivery failed. Moving to pending: {pending_path}")
                shutil.move(pdf_path, pending_path)
            
            # 5. Log status to vault
            log_record = ReportLogRecord(
                report_date=target_date,
                status="sent" if success else "pending"
            )
            self.vault.insert_report_log(log_record)
            
            self.last_report_date = target_date
            return pdf_path
            
        except Exception as e:
            logger.error(f"Intelligence pulse failed: {e}")
            return None

    def process_pending_reports(self):
        """Attempts to resend all reports in the pending directory."""
        pending_files = list(self.pending_dir.glob("*.pdf"))
        if not pending_files:
            return

        logger.info(f"Checking for pending reports ({len(pending_files)} found)...")
        for pdf_path in pending_files:
            # Extract date from filename: radar_intel_YYYY-MM-DD.pdf
            try:
                target_date = pdf_path.stem.replace("radar_intel_", "")
                if self.mailer.send_report(str(pdf_path), target_date):
                    logger.info(f"Successfully resent pending report: {pdf_path.name}")
                    pdf_path.unlink()  # Delete file after success
                    
                    # Update vault log if possible (simplified for now)
                    self.vault.insert_report_log(ReportLogRecord(
                        report_date=target_date, status="sent"
                    ))
            except Exception as e:
                logger.error(f"Failed to resend pending report {pdf_path.name}: {e}")

    def pulse(self):
        """Standard pulse check for the main background loop."""
        # Check for pending first
        self.process_pending_reports()
        
        # Schedule check
        if self._should_report_now():
            self.generate_and_send()

if __name__ == "__main__":
    # Test a manual run
    engine = ReportingEngine()
    print("Manually generating today's report...")
    path = engine.generate_and_send()
    if path:
        print(f"Report finalized.")
