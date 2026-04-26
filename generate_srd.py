import os
from fpdf import FPDF

class PDF(FPDF):
    def header(self):
        # Adding a bit of top margin and distinct title
        self.set_font("helvetica", "B", 18)
        self.set_text_color(30, 60, 90)
        self.cell(0, 12, "Software Requirements Document (SRD)", new_x="LMARGIN", new_y="NEXT", align="C")
        self.set_font("helvetica", "I", 12)
        self.set_text_color(100, 100, 100)
        self.cell(0, 8, "Project: Radar - Stealth Activity & Network Intelligence", new_x="LMARGIN", new_y="NEXT", align="C")
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font("helvetica", "I", 9)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f"Page {self.page_no()}", new_x="LMARGIN", new_y="NEXT", align="C")

    def chapter_title(self, title):
        self.set_font("helvetica", "B", 14)
        self.set_text_color(0, 0, 0)
        self.set_fill_color(230, 240, 250)
        # Adds padding and background color for the chapter title
        self.cell(0, 10, f"  {title}", new_x="LMARGIN", new_y="NEXT", fill=True, align="L")
        self.ln(4)

    def chapter_body(self, text):
        self.set_font("helvetica", "", 11)
        self.set_text_color(0, 0, 0)
        # multi_cell handles line breaks correctly
        self.multi_cell(0, 6, text)
        self.ln(6)

def generate_srd():
    pdf = PDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    
    # 1. Product Overview
    pdf.chapter_title("1. Product Overview")
    pdf.chapter_body(
        "Radar is an advanced, ultra-stealth background service designed to run 24/7 on a host laptop. "
        "Its primary objective is the seamless, undetectable monitoring of both the host's daily activities "
        "(foreground applications, terminal commands) and the external network environment.\n\n"
        "Crucially, Radar acts as a passive network sentinel. It not only tracks the host machine but extends its "
        "surveillance to all other devices connected to the same WiFi network, performing reconnaissance without "
        "triggering security alerts. At the end of each day, Radar processes this intelligence into a comprehensive, "
        "discreet daily report and emails it directly to the user's Gmail."
    )

    # 2. Functional Requirements
    pdf.chapter_title("2. Functional Requirements")
    pdf.chapter_body(
        "2.1 Ultra-Stealth & Performance (Zero-Footprint)\n"
        " - The system must operate completely invisibly (no tray icons, no visible processes).\n"
        " - It must maintain an ultra-low performance footprint (< 2% CPU usage, minimal RAM) to remain undetected.\n\n"
        "2.2 Host Activity Monitoring\n"
        " - Track open applications, window focus sequence, and exact time spent.\n"
        " - Silently record shell and terminal histories along with timestamps.\n\n"
        "2.3 Advanced Network Surveillance (Other Devices)\n"
        " - Passively monitor the local WiFi network.\n"
        " - Identify and track every other device connected to the network via MAC mapping and OS fingerprinting.\n"
        " - Monitor broader network performance and intercept broadcast/multicast telemetry to map device activity.\n\n"
        "2.4 Automated Intelligence Reporting\n"
        " - Nightly aggregation of all intelligence into an HTML/Text email payload.\n"
        " - Automatically attach a separate text log capturing raw network dumps and tracking data of other devices."
    )

    # 3. System Architecture & Flow
    pdf.chapter_title("3. System Architecture & Flow")
    pdf.chapter_body(
        "Phase 1: Ghost Initialization\n"
        "The system registers via hidden system hooks (e.g., systemd/launchd with obfuscated daemon names). It establishes "
        "a localized, encrypted SQLite database for resilient data buffering.\n\n"
        "Phase 2: Silent Polling & Sniffing\n"
        "The host application monitor runs at low-priority intervals to avoid CPU spikes. Concurrently, the network module "
        "periodically drops into promiscuous-like states or uses silent ARP requests to seamlessly inventory network peers.\n\n"
        "Phase 3: Exfiltration Payload\n"
        "At a randomized or scheduled time during the night, the payload builder formats the daily intelligence report and "
        "securely tunnels it via SMTP (TLS) to the destination Gmail address."
    )

    # 4. Deliverables
    pdf.chapter_title("4. Payload Deliverables")
    pdf.chapter_body(
        "Daily Intelligence Email Content:\n"
        " - Host Analytics Table: Top applications used with duration, and complete explicit terminal command history.\n"
        " - Network Intelligence Summary: Snapshot of the local WiFi ecosystem and status of peer devices.\n"
        " - Attached Log (network_intel_YYYYMMDD.txt): Detailed raw records outlining network status and peer device telemetry throughout the day."
    )

    pdf.add_page()
    
    # 5. Implementation Stack & Files
    pdf.chapter_title("5. Implementation Strategy & Libraries")
    pdf.chapter_body(
        "The project will be engineered in Python 3.11+ using the following structure:\n\n"
        "Core Libraries:\n"
        " - 'psutil': Absolute low-impact process and active-window monitoring.\n"
        " - 'scapy': Advanced packet crafting and network reconnaissance (ARP/DNS tracking).\n"
        " - 'schedule': Highly reliable scheduling for report triggers.\n"
        " - 'smtplib' & 'email': Built-in tools for securely compiling and dispatching payloads via Gmail SMTP.\n"
        " - 'sqlite3': Built-in database module operating in WAL mode to avoid write-locks and ensure data integrity.\n\n"
        "File Structure:\n"
        " - core_daemon.py: The obfuscated main loop.\n"
        " - monitors/host_tracker.py: Application and terminal history scraping.\n"
        " - monitors/net_sentinel.py: WiFi scanning and peer device MAC tracking.\n"
        " - reporting/payload_builder.py: Formats and prepares data for exfiltration.\n"
        " - database/vault.py: Interacts with the local SQLite data store safely."
    )
    
    # 6. Software Testing
    pdf.chapter_title("6. Software Testing Strategy")
    pdf.chapter_body(
        "Absolute reliability and stealth are non-negotiable. The testing regimen includes:\n\n"
        "1. Unit Testing ('pytest'):\n"
        "Modules like the host_tracker and payload_builder will be tested in complete isolation using 'pytest-mock'."
        "This simulates system APIs without actually triggering or disrupting the host OS during CI/CD checks.\n\n"
        "2. Performance & Stealth Profiling:\n"
        "The daemon will be stress-tested using performance profilers to mathematically guarantee it never spans above "
        "2% CPU utilization or 50MB of RAM. Persistent memory leak checks will be enforced over 72-hour sustained runs.\n\n"
        "3. E2E (End-to-End) Exfiltration Tests:\n"
        "Sandboxed environments will validate the full lifecycle - from data injection into the SQLite vault, to the "
        "successful receipt of the HTML/Text payload in a sandbox Gmail inbox without triggering spam filters.\n\n"
        "4. Signature & Obfuscation Audits:\n"
        "Continuous monitoring against standard task managers to verify process name obfuscation is successful and "
        "execution remains entirely invisible to a standard user."
    )

    output_path = "/home/qafilah_genomics/Desktop/Radar/SRD_Radar.pdf"
    pdf.output(output_path)
    print(f"SRD successfully generated at: {output_path}")

if __name__ == "__main__":
    generate_srd()
