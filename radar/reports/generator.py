import logging
import io
import matplotlib.pyplot as plt
from fpdf import FPDF
from datetime import datetime
from pathlib import Path
from typing import Dict, Any
from fpdf.enums import XPos, YPos
from radar.utils.helpers import get_radar_data_dir

logger = logging.getLogger(__name__)

class RadarReportPDF(FPDF):
    """Custom FPDF class for the Radar report layout."""
    
    def header(self):
        # Header banner
        self.set_fill_color(0, 51, 102)  # Dark Blue
        self.rect(0, 0, 210, 40, "F")
        
        self.set_font("helvetica", "B", 24)
        self.set_text_color(255, 255, 255)
        self.set_xy(10, 10)
        self.cell(0, 15, "RADAR INTELLIGENCE", align="L")
        
        self.set_font("helvetica", "", 12)
        self.set_xy(10, 25)
        self.cell(0, 10, "Daily Surveillance Summary & Behavioral Analysis", align="L")
        
        self.set_font("helvetica", "B", 14)
        self.set_xy(150, 15)
        # In actual use, this will be set by the generator
        # self.cell(50, 10, self.report_date, align="R")
        self.ln(30)

    def footer(self):
        self.set_y(-15)
        self.set_font("helvetica", "I", 8)
        self.set_text_color(150, 150, 150)
        self.cell(0, 10, f"Confidential System Report | Internal Use Only | Page {self.page_no()}", align="C")

class PdfReportGenerator:
    """Generates a professional dashboard PDF report using FPDF and Matplotlib."""
    
    def __init__(self, summary: Dict[str, Any]):
        self.summary = summary
        self.pdf = RadarReportPDF()
        self.primary_color = (0, 51, 102)
        self.secondary_color = (0, 128, 255)
        self.text_color = (50, 50, 50)

    def _create_app_pie_chart(self) -> io.BytesIO:
        """Generates a pie chart of app usage."""
        top_apps = self.summary['apps']['top_10'][:5]
        if not top_apps:
            return None
            
        labels = [a['name'] for a in top_apps]
        sizes = [a['minutes'] for a in top_apps]
        
        plt.figure(figsize=(5, 4))
        colors = plt.cm.Blues(range(100, 255, 30))
        plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140, colors=colors, textprops={'fontsize': 10})
        plt.axis('equal')
        plt.title("Application Usage Distribution", fontsize=12, fontweight='bold')
        
        buf = io.BytesIO()
        plt.savefig(buf, format='png', bbox_inches='tight', dpi=150)
        plt.close()
        buf.seek(0)
        return buf

    def _create_system_trend_chart(self) -> io.BytesIO:
        """Generates a line chart for CPU and RAM trends."""
        trends = self.summary['system']['trends']
        hours = [t['hour'] for t in trends]
        cpu = [t['cpu'] for t in trends]
        ram = [t['ram'] for t in trends]
        
        plt.figure(figsize=(8, 4))
        plt.plot(hours, cpu, label='CPU Usage %', color='#FF4444', linewidth=2, marker='o', markersize=4)
        plt.plot(hours, ram, label='RAM Usage %', color='#0080FF', linewidth=2, marker='o', markersize=4)
        
        plt.title("24-Hour System Performance Profile", fontsize=12, fontweight='bold')
        plt.xlabel("Hour of Day", fontsize=10)
        plt.ylabel("Usage %", fontsize=10)
        plt.xticks(range(0, 24, 2))
        plt.ylim(0, 100)
        plt.grid(True, linestyle='--', alpha=0.6)
        plt.legend()
        
        buf = io.BytesIO()
        plt.savefig(buf, format='png', bbox_inches='tight', dpi=150)
        plt.close()
        buf.seek(0)
        return buf

    def generate(self, output_path: str = None) -> str:
        """Orchestrates the PDF creation."""
        if not output_path:
            reports_dir = get_radar_data_dir() / "reports"
            reports_dir.mkdir(parents=True, exist_ok=True)
            output_path = str(reports_dir / f"radar_intel_{self.summary['date']}.pdf")

        logger.info(f"Generating premium intelligence report: {output_path}")
        
        self.pdf.add_page()
        self.pdf.set_text_color(*self.text_color)
        
        # --- SECTION: STATUS CARDS ---
        self.pdf.set_font("helvetica", "B", 11)
        self.pdf.set_xy(10, 45)
        
        # Total Activity
        total_mins = round(self.summary['apps']['total_seconds'] / 60, 1)
        self.pdf.set_fill_color(240, 245, 250)
        self.pdf.rect(10, 45, 60, 20, "F")
        self.pdf.set_xy(15, 48)
        self.pdf.cell(50, 5, "TOTAL ACTIVITY", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.pdf.set_font("helvetica", "B", 16)
        self.pdf.set_x(15)
        self.pdf.cell(50, 10, f"{total_mins} mins")
        
        # New Devices
        self.pdf.set_font("helvetica", "B", 11)
        self.pdf.rect(75, 45, 60, 20, "F")
        self.pdf.set_xy(80, 48)
        self.pdf.cell(50, 5, "NEW HARDWARE", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.pdf.set_font("helvetica", "B", 16)
        self.pdf.set_x(80)
        self.pdf.cell(50, 10, str(self.summary['network']['new_count']))
        
        # Avg Load
        self.pdf.set_font("helvetica", "B", 11)
        self.pdf.rect(140, 45, 60, 20, "F")
        self.pdf.set_xy(145, 48)
        self.pdf.cell(50, 5, "AVG CPU LOAD", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.pdf.set_font("helvetica", "B", 16)
        self.pdf.set_x(145)
        self.pdf.cell(50, 10, f"{self.summary['system']['avg_cpu']}%")

        # --- SECTION: HOST INTELLIGENCE (Left: Pie, Right: Table) ---
        self.pdf.ln(25)
        self.pdf.set_font("helvetica", "B", 14)
        self.pdf.set_text_color(*self.primary_color)
        self.pdf.cell(0, 10, "HOST BEHAVIORAL ANALYSIS", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.pdf.set_draw_color(*self.primary_color)
        self.pdf.line(10, self.pdf.get_y(), 200, self.pdf.get_y())
        self.pdf.ln(5)
        
        start_y = self.pdf.get_y()
        pie_buf = self._create_app_pie_chart()
        if pie_buf:
            self.pdf.image(pie_buf, x=10, y=start_y, w=90)
            
        # Top Windows Table on the right (more descriptive than process name)
        self.pdf.set_xy(110, start_y + 5)
        self.pdf.set_font("helvetica", "B", 10)
        self.pdf.set_text_color(100, 100, 100)
        self.pdf.cell(70, 7, "TOP WORKFLOW ACTIVITY", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.pdf.set_font("helvetica", "", 8)
        self.pdf.set_text_color(*self.text_color)
        
        # Display top_windows for better context
        for app in self.summary['apps'].get('top_windows', [])[:10]:
            self.pdf.set_x(110)
            title = app['title'][:40] + ("..." if len(app['title']) > 40 else "")
            self.pdf.cell(75, 5, f"- {title}")
            self.pdf.cell(15, 5, f"{app['minutes']}m", align="R", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        # --- SECTION: SYSTEM DYNAMICS ---
        self.pdf.set_xy(10, start_y + 75)
        self.pdf.set_font("helvetica", "B", 14)
        self.pdf.set_text_color(*self.primary_color)
        self.pdf.cell(0, 10, "SYSTEM PERFORMANCE TRENDS", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.pdf.line(10, self.pdf.get_y(), 200, self.pdf.get_y())
        self.pdf.ln(5)
        
        trend_buf = self._create_system_trend_chart()
        if trend_buf:
            self.pdf.image(trend_buf, x=15, w=180)

        # --- SECTION: NETWORK INVENTORY (New Page) ---
        self.pdf.add_page()
        self.pdf.set_font("helvetica", "B", 14)
        self.pdf.set_text_color(*self.primary_color)
        self.pdf.cell(0, 10, "NETWORK RECONNAISSANCE INVENTORY", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.pdf.line(10, self.pdf.get_y(), 200, self.pdf.get_y())
        self.pdf.ln(5)
        
        # Inventory Table
        self.pdf.set_font("helvetica", "B", 9)
        self.pdf.set_fill_color(220, 230, 240)
        self.pdf.cell(50, 8, "Device Identifier", border=1, fill=True)
        self.pdf.cell(25, 8, "Type", border=1, fill=True)
        self.pdf.cell(30, 8, "IP Address", border=1, fill=True)
        self.pdf.cell(65, 8, "Vendor / Hardware", border=1, fill=True)
        self.pdf.cell(20, 8, "Conf %", border=1, fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        
        self.pdf.set_font("helvetica", "", 8)
        for d in self.summary['network']['inventory'][:25]:
            conf = d.get('confidence', 0)
            # Color row based on confidence
            if conf >= 80:
                self.pdf.set_fill_color(240, 255, 240) # Greenish
            elif conf >= 60:
                self.pdf.set_fill_color(255, 255, 240) # Yellowish
            else:
                self.pdf.set_fill_color(255, 240, 240) # Reddish
                
            self.pdf.cell(50, 7, d['name'][:30], border=1, fill=True)
            self.pdf.cell(25, 7, d['type'], border=1, fill=True)
            self.pdf.cell(30, 7, d['ip'], border=1, fill=True)
            self.pdf.cell(65, 7, d['manufacturer'][:40], border=1, fill=True)
            self.pdf.cell(20, 7, f"{conf}%", border=1, fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        # --- SECTION: TERMINAL AUDIT ---
        self.pdf.ln(10)
        self.pdf.set_font("helvetica", "B", 14)
        self.pdf.set_text_color(*self.primary_color)
        self.pdf.cell(0, 10, "TERMINAL COMMAND LOG (PASSIVE AUDIT)", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.pdf.line(10, self.pdf.get_y(), 200, self.pdf.get_y())
        self.pdf.ln(5)
        
        self.pdf.set_font("courier", "", 8)
        self.pdf.set_text_color(50, 70, 50)
        for cmd in self.summary['terminal']['recent']:
            clean_cmd = cmd.strip()[:100] + ("..." if len(cmd) > 100 else "")
            self.pdf.cell(0, 5, f"[AUDIT] {clean_cmd}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        self.pdf.output(output_path)
        logger.info(f"Report finalized at {output_path}")
        return output_path

if __name__ == "__main__":
    from radar.reports.aggregator import DataAggregator
    # Mock some data for stand-alone testing
    summary = {
        "date": datetime.now().strftime("%Y-%m-%d"),
        "apps": {
            "total_seconds": 36000,
            "top_10": [{"name": "Code", "minutes": 120}, {"name": "Chrome", "minutes": 80}, {"name": "Slack", "minutes": 45}],
            "hourly_usage": [10, 5, 20, 40, 10, 5, 2, 0, 0, 10, 20, 30, 40, 50, 60, 40, 30, 20, 10, 5, 5, 10, 20, 10]
        },
        "terminal": {
            "recent": ["ls -la", "git status", "make build", "python main.py"]
        },
        "network": {
            "new_count": 2,
            "inventory": [
                {"name": "Ahmed-MBP", "type": "Laptop", "ip": "192.168.1.5", "manufacturer": "Apple Inc."},
                {"name": "Home-Gateway", "type": "Router", "ip": "192.168.1.1", "manufacturer": "Cisco"}
            ]
        },
        "system": {
            "avg_cpu": 12.5,
            "avg_ram": 44.2,
            "trends": [{"hour": h, "cpu": 10 + (h%5)*5, "ram": 40 + (h%3)*2} for h in range(24)]
        }
    }
    generator = PdfReportGenerator(summary)
    generator.generate("test_modern_report.pdf")
