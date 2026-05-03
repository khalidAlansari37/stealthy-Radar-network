import os
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from radar.database.vault import Vault

class IntelligenceBrief:
    def __init__(self):
        self.vault = Vault()
        self.styles = getSampleStyleSheet()

    def generate(self, output_path=None):
        if not output_path:
            date_str = datetime.now().strftime("%Y-%m-%d")
            output_path = f"Radar_Intel_Brief_{date_str}.pdf"

        doc = SimpleDocTemplate(output_path, pagesize=letter)
        elements = []

        # 1. Header
        elements.append(Paragraph("RADAR INTELLIGENCE BRIEFING", self.styles['Title']))
        elements.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", self.styles['Normal']))
        elements.append(Spacer(1, 20))

        # 2. Network Overview
        elements.append(Paragraph("Section 1: Network Overview", self.styles['Heading2']))
        devices = self.vault.get_network_devices()
        
        device_data = [["MAC Address", "IP Address", "Device Name", "OS Guess"]]
        for d in devices[:15]:  # Limit to top 15 for report space
            device_data.append([
                d.mac_address,
                d.ip_address or "N/A",
                d.device_name or "Unknown",
                d.os_guess or "Unknown"
            ])
        
        t = Table(device_data, colWidths=[120, 100, 150, 100])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
        ]))
        elements.append(t)
        elements.append(Spacer(1, 20))

        # 3. Captured Intelligence (Credentials)
        elements.append(Paragraph("Section 2: Captured Credentials & Sessions", self.styles['Heading2']))
        creds = self.vault.get_credentials(limit=10)
        
        if creds:
            cred_data = [["Source IP", "Target Host", "Type", "Value (Partial)"]]
            for c in creds:
                cred_data.append([
                    c['src_ip'],
                    c['target_host'],
                    c['cred_type'],
                    (c['cred_value'][:30] + "...") if len(c['cred_value']) > 30 else c['cred_value']
                ])
            
            ct = Table(cred_data, colWidths=[100, 150, 80, 150])
            ct.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.darkred),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
            ]))
            elements.append(ct)
        else:
            elements.append(Paragraph("No credentials captured in this period.", self.styles['Italic']))

        elements.append(Spacer(1, 20))

        # 4. Traffic Intelligence
        elements.append(Paragraph("Section 3: Top Traffic Flows (Geo-Intelligence)", self.styles['Heading2']))
        # Fetching recent flows with Geo labels
        all_flows = self.vault.conn.execute("SELECT * FROM network_flows WHERE service_label LIKE 'Geo:%' ORDER BY timestamp DESC LIMIT 20").fetchall()
        
        if all_flows:
            flow_data = [["Timestamp", "Source", "Destination", "Location"]]
            for f in all_flows:
                flow_data.append([
                    f['timestamp'][11:19],
                    f['src_ip'],
                    f['dst_ip'],
                    f['service_label'].replace("Geo: ", "")
                ])
            
            ft = Table(flow_data, colWidths=[80, 100, 100, 180])
            ft.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
            ]))
            elements.append(ft)
        else:
            elements.append(Paragraph("No geo-intelligence data available yet.", self.styles['Italic']))

        doc.build(elements)
        return output_path

if __name__ == "__main__":
    brief = IntelligenceBrief()
    path = brief.generate()
    print(f"✅ Intelligence Briefing generated: {path}")
