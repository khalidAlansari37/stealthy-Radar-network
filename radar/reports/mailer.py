import smtplib
import logging
import os
import time
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email import encoders
from radar.config import settings

logger = logging.getLogger(__name__)

class ReportMailer:
    """Delivers Radar intelligence reports via SMTP email."""
    
    def __init__(self):
        self.config = settings.email

    def send_report(self, pdf_path: str, target_date: str = None) -> bool:
        """Sends the specified PDF report as an email attachment with retries."""
        if not self.config.enabled:
            logger.warning("Email delivery is disabled in config.")
            return False
            
        if not target_date:
            target_date = os.path.basename(pdf_path).replace("radar_intel_", "").replace(".pdf", "")

        attempts = 5
        backoff = 30  # Start with 30s
        
        for attempt in range(1, attempts + 1):
            try:
                logger.info(f"Email attempt {attempt}/{attempts} for {target_date}...")
                
                # Create message
                msg = MIMEMultipart()
                msg['From'] = self.config.sender
                msg['To'] = self.config.recipient
                msg['Subject'] = f"RADAR: Intelligence Summary - {target_date}"
                
                body = f"Attached is the RADAR daily intelligence summary for {target_date}.\n\nStay secure."
                msg.attach(MIMEText(body, 'plain'))
                
                # Attach PDF
                with open(pdf_path, "rb") as f:
                    part = MIMEBase('application', 'octet-stream')
                    part.set_payload(f.read())
                    encoders.encode_base64(part)
                    part.add_header(
                        'Content-Disposition',
                        f"attachment; filename={os.path.basename(pdf_path)}"
                    )
                    msg.attach(part)
                
                # Connect and send
                with smtplib.SMTP(self.config.smtp_server, self.config.smtp_port) as server:
                    if self.config.use_tls:
                        server.starttls()
                    
                    if self.config.gmail_app_password:
                        server.login(self.config.sender, self.config.gmail_app_password)
                    
                    server.send_message(msg)
                    
                logger.info("Email report sent successfully.")
                return True
                
            except Exception as e:
                logger.error(f"Attempt {attempt} failed: {e}")
                if attempt < attempts:
                    logger.info(f"Retrying in {backoff} seconds...")
                    time.sleep(backoff)
                    backoff *= 2  # Exponential backoff
                else:
                    logger.error("Final email attempt failed.")
        
        return False

if __name__ == "__main__":
    # Test mailer (will likely fail without credentials)
    mailer = ReportMailer()
    # mailer.send_report("test.pdf")
    print("Mailer initialized. Update config.yaml with real credentials to test.")
