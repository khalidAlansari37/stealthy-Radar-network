# Radar

### Stealth Activity Monitoring & Network Intelligence System

> A silent, 24/7 background daemon that monitors host laptop activity, discovers and profiles every device on the local WiFi network, and delivers automated daily intelligence reports via Gmail.

---

## Table of Contents

1. [Product Overview](#1-product-overview)
2. [Goals & Objectives](#2-goals--objectives)
3. [Functional Requirements](#3-functional-requirements)
4. [System Architecture & Data Flow](#4-system-architecture--data-flow)
5. [Core Modules (Deep Dive)](#5-core-modules-deep-dive)
6. [Device Fingerprinting Engine](#6-device-fingerprinting-engine)
7. [Per-Device Intelligence Files](#7-per-device-intelligence-files)
8. [Daily Report Specification](#8-daily-report-specification)
9. [Database Schema](#9-database-schema)
10. [Technology Stack & Libraries](#10-technology-stack--libraries)
11. [Project File Structure](#11-project-file-structure)
12. [Configuration Reference](#12-configuration-reference)
13. [Security & Privacy Considerations](#13-security--privacy-considerations)
14. [Software Testing Strategy](#14-software-testing-strategy)
15. [Deployment & Installation](#15-deployment--installation)
16. [Performance Benchmarks & Constraints](#16-performance-benchmarks--constraints)
17. [Future Enhancements & Roadmap](#17-future-enhancements--roadmap)
18. [Known Limitations](#18-known-limitations)
19. [Glossary](#19-glossary)

---

## 1. Product Overview

Radar is an advanced, ultra-stealth background service engineered to run 24/7 on a host laptop. It operates as an invisible daemon with two primary missions:

**Mission 1 - Host Surveillance:** Continuously and silently monitor the host machine's activity -- which applications are opened, how long they are used, every terminal command executed, browser usage patterns, system resource consumption, and idle/active periods throughout the day.

**Mission 2 - Network Intelligence:** Act as a passive network sentinel. Radar extends beyond the host machine to discover, fingerprint, and profile every single device connected to the same WiFi network. Whether it is an iPhone, an Android phone, a smart TV, a gaming console, an IoT thermostat, or another laptop -- Radar identifies it, classifies it, tracks when it joins and leaves the network, estimates its traffic usage, and compiles a dedicated intelligence file for each device.

At the end of each day (or at a user-configured time), Radar silently compiles all collected intelligence into a structured daily report with individualized per-device log files attached, and dispatches everything to the user's Gmail inbox via encrypted SMTP. The user wakes up to a complete picture of what happened on their machine and across their entire network -- without ever having to open a single dashboard.

**Key Differentiators:**
- Completely invisible to the host user and other network participants
- Cross-platform device detection (iOS, Android, macOS, Windows, Linux, IoT, Smart TVs, Consoles)
- Individual `.txt` intelligence files generated per detected device
- Zero-configuration after initial setup
- Survives reboots, sleep cycles, and network changes

---

## 2. Goals & Objectives

| Goal | Description | Success Metric |
|------|-------------|----------------|
| Invisible Operation | No visible GUI, tray icon, or detectable process name | Passes manual task manager audit |
| 24/7 Uptime | Survives reboots, sleep/wake, network drops | 99.9% uptime over 30 days |
| Host Tracking | Accurately log app usage with time-spent data | < 5 second granularity on app focus tracking |
| Network Discovery | Detect all WiFi-connected devices | 95%+ detection rate within 5 minutes of device joining |
| Device Classification | Correctly identify device type and OS | 90%+ accuracy using MAC OUI + TTL + mDNS fingerprinting |
| Daily Reporting | Deliver comprehensive email report on schedule | Email delivered within 5 minutes of scheduled time |
| Low Footprint | Minimal CPU and memory impact | < 2% CPU average, < 80MB RAM |
| Offline Resilience | Buffer data when network is unavailable | Zero data loss during 24-hour network outage |

---

## 3. Functional Requirements

### 3.1 Ultra-Stealth Operation (Zero-Footprint)

The system must be completely invisible to casual observation:

- **No GUI Elements**: No tray icons, no dock presence, no notification popups, no visible windows.
- **Process Obfuscation**: The daemon process name must blend with normal system processes (e.g., named as a generic system service rather than "radar" or "monitor").
- **Low Resource Signature**: CPU usage must stay below 2% on average, with burst spikes never exceeding 5%. Memory consumption must remain under 80MB. Disk I/O must be batched to avoid constant write patterns.
- **Network Stealth**: All network scanning must use passive techniques or low-volume active probes that do not trigger IDS/IPS systems or router alerts.
- **Boot Persistence**: The daemon must automatically start on system boot without requiring user interaction. It must silently recover from crashes via a watchdog mechanism.

### 3.2 Host Activity Monitoring

Detailed tracking of the user's daily laptop usage:

- **Active Application Tracking**: Record every application that gains window focus. Log the application name, window title (to identify specific documents/tabs), and exact timestamps of when focus was gained and lost.
- **Time-Spent Calculation**: Compute precise duration spent in each application per session and aggregate daily totals. Distinguish between active use (keyboard/mouse input) and passive display (app is focused but idle).
- **Terminal Command Logging**: Parse shell history files (`.bash_history`, `.zsh_history`, PowerShell `ConsoleHost_history.txt`) to capture every command executed. Where possible, extract timestamps. For shells that do not natively timestamp (like default bash), use file modification times and inotify-based watchers as fallback.
- **Idle Detection**: Track periods where no keyboard/mouse activity is detected. Separate "active work time" from "idle/away time" in reports.
- **Session Tracking**: Detect login/logout, lock/unlock screen events to understand the user's working hours.

### 3.3 Network Surveillance & Device Discovery

Deep intelligence gathering on all devices sharing the WiFi network:

- **ARP-Based Discovery**: Periodically send silent ARP requests across the local subnet to enumerate all active IP/MAC pairs. Frequency: every 2-5 minutes with jitter to avoid pattern detection.
- **mDNS/Bonjour Listening**: Passively listen for mDNS (multicast DNS) announcements. Apple devices (iPhones, iPads, MacBooks) constantly broadcast their names and services via Bonjour, making this the most reliable iOS detection method.
- **SSDP/UPnP Snooping**: Listen for SSDP `NOTIFY` and `M-SEARCH` messages. Smart TVs (Samsung, LG), gaming consoles (PlayStation, Xbox), and media streamers (Chromecast, Roku) all advertise via UPnP.
- **DHCP Fingerprinting**: If possible, observe DHCP request patterns. The DHCP option ordering (`parameter request list`) is highly device-specific and can distinguish between iOS versions, Android versions, and different operating systems.
- **NetBIOS Name Resolution**: On networks with Windows devices, listen for NetBIOS name broadcasts to identify Windows machine hostnames and workgroups.
- **OS Fingerprinting via TTL Analysis**: Analyze ICMP or TCP TTL values to determine OS families. Default TTL values are: Linux = 64, Windows = 128, macOS/iOS = 64, Android = 64, some IoT = 255. Combined with MAC OUI, this narrows identification significantly.
- **Traffic Volume Estimation**: By monitoring ARP activity frequency and optional lightweight packet counting per MAC address, estimate relative network usage per device (light/moderate/heavy classification).
- **Connection Timeline**: Track the exact time each device joins and departs the network (first ARP seen / last ARP seen without renewal) to build a connection timeline.

### 3.4 Multi-Platform Device Classification

Radar must classify discovered devices into one of the following categories:

| Category | Detection Method | Examples |
|----------|-----------------|----------|
| iPhone / iPad (iOS) | MAC OUI (Apple Inc.) + mDNS hostname pattern (`*iPhone*`, `*iPad*`) + Bonjour services (`_airplay._tcp`, `_airdrop._tcp`) | iPhone 14 Pro, iPad Air |
| Android Phone/Tablet | MAC OUI (Samsung, Xiaomi, Google, etc.) + mDNS pattern (`*android*`, `*Galaxy*`) + DHCP fingerprint | Galaxy S23, Pixel 8 |
| macOS Laptop/Desktop | MAC OUI (Apple) + mDNS hostname (`*MacBook*`, `*iMac*`) + Bonjour services (`_smb._tcp`, `_rfb._tcp`) | MacBook Pro, iMac |
| Windows PC | NetBIOS name broadcast + TTL=128 + SSDP device description | Dell XPS, Surface Pro |
| Linux Machine | TTL=64 + No mDNS Apple services + MAC OUI (varies) | Ubuntu Desktop, Raspberry Pi |
| Smart TV | SSDP/UPnP `deviceType:MediaRenderer` + MAC OUI (Samsung, LG, Sony) | Samsung Smart TV, LG webOS |
| Gaming Console | SSDP services + MAC OUI (Sony Interactive, Microsoft) + specific port patterns | PlayStation 5, Xbox Series X |
| IoT / Smart Home | MAC OUI (TP-Link, Tuya, Espressif) + minimal traffic pattern + TTL=255 | Smart plugs, cameras, bulbs |
| Network Equipment | MAC OUI (Cisco, Netgear, TP-Link) + acts as gateway or AP | Routers, access points, switches |
| Unknown | Unclassifiable -- MAC OUI not matched, no mDNS/SSDP response | Logged with raw data for manual review |

### 3.5 Automated Intelligence Reporting

- Nightly aggregation of all host and network intelligence.
- Construction of an HTML-formatted email body summarizing the day.
- Generation of individualized `.txt` device intelligence files.
- Secure dispatch via Gmail SMTP with TLS encryption.
- Retry logic: If email fails (network issue, Gmail rate limit), queue and retry with exponential backoff up to 5 attempts.

---

## 4. System Architecture & Data Flow

### High-Level Architecture

```
+---------------------------------------------+
|              HOST LAPTOP                     |
|                                              |
|  +--------+  +----------+  +-------------+  |
|  |  App   |  | Terminal  |  |   Network   |  |
|  |Monitor |  | Monitor   |  |  Sentinel   |  |
|  +---+----+  +-----+----+  +------+------+  |
|      |             |              |          |
|      +-------+-----+------+------+          |
|              |             |                 |
|        +-----v-----+ +----v------+          |
|        |  SQLite    | | Device    |          |
|        |  Vault     | | Profiles  |          |
|        +-----+------+ +----+-----+          |
|              |             |                 |
|        +-----v-------------v-----+           |
|        |   Report Builder        |           |
|        |   (HTML + .txt files)   |           |
|        +----------+--------------+           |
|                   |                          |
|        +----------v-----------+              |
|        |   Email Dispatcher   |              |
|        |   (Gmail SMTP/TLS)   |              |
|        +----------+-----------+              |
|                   |                          |
+---------------------------------------------+
                    |
                    v
           +-------+--------+
           |   Gmail Inbox   |
           |  (Daily Report) |
           +-----------------+
```

### Data Flow Sequence

```
1. BOOT: systemd/launchd starts the Radar daemon silently.
2. INIT: Daemon loads config, opens SQLite in WAL mode, starts scheduler.
3. POLL (every 30-60s):
   a. App Monitor samples the active foreground window -> writes to DB.
   b. Terminal Monitor checks for new history lines -> writes to DB.
   c. System Monitor captures CPU/RAM/battery snapshot -> writes to DB.
4. SCAN (every 2-5 min with jitter):
   a. Network Sentinel sends silent ARP sweep across subnet.
   b. Listens for mDNS, SSDP, NetBIOS responses.
   c. Fingerprints new devices (MAC OUI + TTL + service probes).
   d. Updates device registry in DB with join/leave timestamps.
5. REPORT (once daily at configured hour):
   a. Report Builder queries DB for last 24 hours of data.
   b. Generates host activity summary (apps, commands, timeline).
   c. For EACH discovered device, generates an individual .txt file
      with full device intelligence (see Section 7).
   d. Constructs HTML email body with summary tables.
   e. Attaches all device .txt files.
   f. Email Dispatcher authenticates with Gmail and sends.
   g. On success, marks data as reported. On failure, retries.
6. CLEANUP (weekly):
   a. Purge reported data older than configured retention (default: 30 days).
   b. Compact SQLite database (VACUUM).
```

---

## 5. Core Modules (Deep Dive)

### 5.1 App Monitor (`monitors/app_monitor.py`)

**Purpose:** Track which application the user is actively using at any given moment.

**How it works:**

On **Linux**, the module uses `xdotool` or reads from `/proc` combined with X11 window properties to determine the currently focused window. It extracts:
- The window title (e.g., "README.md - Visual Studio Code")
- The process name (e.g., "code")
- The process PID

On **macOS**, it uses `AppKit`'s `NSWorkspace` to query `activeApplication()`.

On **Windows**, it calls `win32gui.GetForegroundWindow()` and `win32process.GetWindowThreadProcessId()`.

**Data collected per sample:**

| Field | Example |
|-------|---------|
| `timestamp` | `2026-04-07 14:32:15` |
| `app_name` | `Visual Studio Code` |
| `window_title` | `README.md - Radar` |
| `process_name` | `code` |
| `process_pid` | `12847` |
| `is_idle` | `False` |

**Sampling rate:** Every 30 seconds (configurable). Low enough to be invisible, frequent enough to capture meaningful usage patterns.

### 5.2 Terminal Monitor (`monitors/terminal_monitor.py`)

**Purpose:** Capture every command the user runs in their terminal.

**How it works:**

The module watches shell history files using filesystem event watchers (`inotify` on Linux, `fsevents` on macOS, `ReadDirectoryChangesW` on Windows). When the history file is modified, the module reads the new lines appended since the last check.

**Supported shells:**
- **Bash**: Reads `~/.bash_history`. If `HISTTIMEFORMAT` is set, parses timestamps. Otherwise, uses file modification time as an approximation.
- **Zsh**: Reads `~/.zsh_history`. Zsh natively stores timestamps in the format `: <epoch>:0;<command>`, which the parser extracts directly.
- **Fish**: Reads `~/.local/share/fish/fish_history`. Fish uses a YAML-like format with `cmd:` and `when:` fields.
- **PowerShell (Windows)**: Reads `ConsoleHost_history.txt` from the PowerShell profile directory.

**Data collected per command:**

| Field | Example |
|-------|---------|
| `timestamp` | `2026-04-07 09:15:33` |
| `shell` | `zsh` |
| `command` | `git push origin main` |
| `working_directory` | `/home/user/projects/radar` (if recoverable) |

### 5.3 Network Sentinel (`monitors/net_sentinel.py`)

**Purpose:** Discover, fingerprint, and continuously track every device on the local WiFi network.

**Discovery techniques (layered approach):**

1. **ARP Sweep (Primary):** Uses `scapy` to send ARP requests (`who-has`) to every IP in the local subnet (e.g., `192.168.1.0/24`). Collects responding IP-MAC pairs. This is the most reliable method and works across all device types.

2. **mDNS Passive Listener:** Opens a UDP socket on port 5353 (multicast group `224.0.0.251`) and listens for mDNS announcements. Apple devices are particularly chatty on mDNS and broadcast their device names, model identifiers, and offered services (AirPlay, AirDrop, etc.).

3. **SSDP Passive Listener:** Listens on UDP port 1900 (multicast group `239.255.255.250`) for UPnP `NOTIFY` messages. Smart TVs, media players, and gaming consoles regularly announce themselves via SSDP.

4. **NetBIOS Listener:** Sends NetBIOS name queries (UDP port 137) and listens for responses from Windows devices.

5. **MAC OUI Database Lookup:** Every detected MAC address is looked up against the IEEE OUI (Organizationally Unique Identifier) database to determine the manufacturer (e.g., `Apple Inc.`, `Samsung Electronics`, `Sony Interactive Entertainment`).

6. **TTL-Based OS Fingerprinting:** Sends a single ICMP echo request (ping) to each discovered IP and analyzes the TTL of the response to classify the OS family.

**Scan scheduling:** ARP sweeps run every 3 minutes with a random jitter of +/- 60 seconds to avoid creating a predictable traffic pattern. mDNS and SSDP listeners run continuously as passive receivers.

### 5.4 System Monitor (`monitors/system_monitor.py`)

**Purpose:** Capture periodic system health snapshots.

**Metrics collected:**

| Metric | Source | Sampling Rate |
|--------|--------|---------------|
| CPU usage (%) | `psutil.cpu_percent()` | Every 60s |
| RAM usage (%) | `psutil.virtual_memory()` | Every 60s |
| Disk usage (%) | `psutil.disk_usage('/')` | Every 300s |
| Battery level & charging state | `psutil.sensors_battery()` | Every 300s |
| Network bytes sent/received | `psutil.net_io_counters()` | Every 60s |
| System uptime | `psutil.boot_time()` | Once at startup |
| Active user sessions | `psutil.users()` | Every 300s |
| WiFi SSID & signal strength | `nmcli` (Linux) / system APIs | Every 120s |

### 5.5 Data Vault (`database/vault.py`)

**Purpose:** Persistent local storage for all collected intelligence.

**Technology:** SQLite3 in WAL (Write-Ahead Logging) mode. WAL mode allows concurrent reads and writes without locking, which is critical since the monitoring threads write continuously while the report builder reads the full day's data at report time.

**Retention Policy:** Data is retained for 30 days by default (configurable). A weekly cleanup job runs `DELETE` followed by `VACUUM` to reclaim disk space.

**Estimated storage:** Approximately 5-15 MB per day depending on activity level and number of network devices.

### 5.6 Report Builder (`reporting/report_builder.py`)

**Purpose:** Synthesize raw data into human-readable reports.

**Outputs:**
1. An HTML-formatted email body with summary tables and charts
2. Individual `.txt` files per network device (see Section 7)
3. A host activity summary `.txt` file

**Template engine:** Jinja2 for HTML email rendering with inline CSS (email clients do not support external stylesheets).

### 5.7 Email Dispatcher (`reporting/email_dispatcher.py`)

**Purpose:** Securely deliver the daily report to the user's Gmail.

**Protocol:** SMTP over TLS (port 587) using Gmail App Passwords (not the main Gmail password). Credentials are stored in a local `.env` file with restricted file permissions (chmod 600).

**Retry logic:** If the SMTP connection fails, the dispatcher retries up to 5 times with exponential backoff (30s, 60s, 120s, 240s, 480s). If all retries fail, the report is saved locally in a `pending_reports/` directory and dispatched on the next successful connection.

---

## 6. Device Fingerprinting Engine

The fingerprinting engine is the intelligence core of Radar's network module. It combines multiple data points to build a confidence-weighted device profile.

### Fingerprint Data Sources

```
+-------------------+
|   ARP Response    |  --> MAC address, IP address
+-------------------+
         |
+-------------------+
|   MAC OUI Lookup  |  --> Manufacturer (Apple, Samsung, Sony, etc.)
+-------------------+
         |
+-------------------+
|   ICMP TTL        |  --> OS family (Linux/macOS=64, Windows=128)
+-------------------+
         |
+-------------------+
|   mDNS Records    |  --> Device name, model, services offered
+-------------------+
         |
+-------------------+
|   SSDP/UPnP Data  |  --> Device type, friendly name, model
+-------------------+
         |
+-------------------+
|   NetBIOS Name    |  --> Windows hostname, workgroup
+-------------------+
         |
+-------------------+
| DHCP Fingerprint  |  --> OS-specific option ordering
+-------------------+
         |
         v
+-------------------+
| CLASSIFICATION    |  --> "iPhone 14 Pro" / "Galaxy S23" / "LG Smart TV"
| ENGINE            |      with confidence score (0-100%)
+-------------------+
```

### Classification Confidence Scoring

Each data source contributes a weighted score to the final classification:

| Source | Weight | Example Contribution |
|--------|--------|---------------------|
| MAC OUI matches Apple | +30 | "Likely Apple device" |
| mDNS hostname contains "iPhone" | +40 | "Confirmed iPhone" |
| mDNS advertises `_airdrop._tcp` | +15 | "Supports AirDrop (iOS/macOS)" |
| TTL = 64 | +10 | "Linux/macOS/iOS family" |
| SSDP `deviceType` = MediaRenderer | +30 | "Smart TV or media player" |
| NetBIOS name exists | +25 | "Windows device confirmed" |

A device is classified when cumulative confidence exceeds 60%. Below that threshold, it is tagged as "Unknown" with all raw data preserved for manual review.

---

## 7. Per-Device Intelligence Files

For every device discovered on the network, Radar generates a dedicated text file. The filename follows this pattern:

```
<DeviceName>_<MACsuffix>_intel_<YYYYMMDD>.txt
```

**Example filenames:**
- `iPhone-Ahmed_A4B2_intel_20260407.txt`
- `Galaxy-S23_C7D9_intel_20260407.txt`
- `Samsung-SmartTV_E1F3_intel_20260407.txt`
- `Unknown-Device_8B2A_intel_20260407.txt`
- `MacBook-Pro_5C1E_intel_20260407.txt`

### Content of Each Device File

```
=====================================================
  RADAR DEVICE INTELLIGENCE REPORT
  Generated: 2026-04-07 23:00:05
=====================================================

DEVICE IDENTITY
  Name           : Ahmed's iPhone
  Type           : iPhone (iOS)
  Manufacturer   : Apple Inc.
  MAC Address    : AA:BB:CC:DD:A4:B2
  IP Address     : 192.168.1.42
  Confidence     : 95%

CLASSIFICATION EVIDENCE
  MAC OUI        : Apple, Inc. (Score: +30)
  mDNS Hostname  : Ahmeds-iPhone.local (Score: +40)
  mDNS Services  : _airdrop._tcp, _airplay._tcp (Score: +15)
  ICMP TTL       : 64 (Score: +10)

CONNECTION TIMELINE
  First Seen     : 07:14:22
  Last Seen      : 22:48:11
  Total Online   : 15h 33m
  Connection Map :
    07:14 -------- 09:02  [1h 48m]
    09:02 -------- 09:15  [OFFLINE - 13m]
    09:15 -------- 14:30  [5h 15m]
    14:30 -------- 15:45  [OFFLINE - 1h 15m]
    15:45 -------- 22:48  [7h 03m]

NETWORK ACTIVITY
  ARP Requests Observed   : 47
  mDNS Announcements      : 23
  Estimated Traffic Level  : MODERATE
  Services Advertised      : AirDrop, AirPlay, HomeKit

NOTES
  - Device was intermittently offline during midday (possibly user
    left WiFi range or switched to cellular data).
  - AirPlay service suggests user may have been streaming content.

=====================================================
  END OF REPORT
=====================================================
```

---

## 8. Daily Report Specification

### Email Subject Line
```
Radar Daily Intelligence Report - April 7, 2026
```

### Email Body (HTML Summary)

The email body contains the following sections:

**Section A: Host Activity Summary**
```
+-----------------------------------------------------+
|  YOUR LAPTOP ACTIVITY - April 7, 2026               |
+-----------------------------------------------------+
|  Total Active Time : 8h 42m                         |
|  Total Idle Time   : 2h 18m                         |
|  First Activity    : 08:15 AM                       |
|  Last Activity     : 11:42 PM                       |
+-----------------------------------------------------+

  TOP APPLICATIONS
  +---------------------+----------+----------+
  | Application         | Time     | Sessions |
  +---------------------+----------+----------+
  | VS Code             | 4h 23m   | 3        |
  | Google Chrome       | 2h 15m   | 12       |
  | Terminal (zsh)      | 1h 42m   | 8        |
  | Slack               | 0h 38m   | 5        |
  | Spotify             | 0h 22m   | 2        |
  +---------------------+----------+----------+

  TERMINAL COMMANDS EXECUTED (24 total)
  08:22  cd ~/projects/radar
  08:22  git status
  08:23  git pull origin main
  08:30  python3 -m pytest tests/
  09:15  docker compose up -d
  ...    (full list in attachment)
```

**Section B: Network Intelligence Summary**
```
+-----------------------------------------------------+
|  NETWORK INTELLIGENCE - April 7, 2026               |
+-----------------------------------------------------+
|  WiFi Network  : Home_5G                            |
|  Gateway       : 192.168.1.1 (TP-Link Router)      |
|  Subnet        : 192.168.1.0/24                     |
|  Your IP       : 192.168.1.105                      |
+-----------------------------------------------------+

  DEVICES DETECTED (7 devices)
  +--+---------------------+----------------+-----------+------------+
  |# | Device              | Type           | Online    | Traffic    |
  +--+---------------------+----------------+-----------+------------+
  |1 | Ahmed's iPhone      | iPhone (iOS)   | 15h 33m   | MODERATE   |
  |2 | Galaxy-S23          | Android        | 8h 12m    | HEAVY      |
  |3 | MacBook-Pro         | macOS          | 10h 45m   | HEAVY      |
  |4 | Samsung-TV          | Smart TV       | 3h 20m    | MODERATE   |
  |5 | PS5                 | Gaming Console | 2h 15m    | HEAVY      |
  |6 | ESP-SmartPlug       | IoT Device     | 24h 00m   | LIGHT      |
  |7 | Unknown-8B2A        | Unknown        | 0h 45m    | LIGHT      |
  +--+---------------------+----------------+-----------+------------+

  * Individual device reports attached as .txt files.
```

**Section C: System Health**
```
  SYSTEM HEALTH
  +--------------------+---------+
  | Metric             | Value   |
  +--------------------+---------+
  | Avg CPU Usage      | 18%     |
  | Avg RAM Usage      | 62%     |
  | Disk Used          | 234 GB  |
  | Battery (EOD)      | 78%     |
  | WiFi Signal        | -38 dBm |
  | System Uptime      | 14h 22m |
  +--------------------+---------+
```

### Email Attachments
- `host_activity_20260407.txt` -- Full terminal command log and detailed app timeline
- `iPhone-Ahmed_A4B2_intel_20260407.txt` -- iPhone device report
- `Galaxy-S23_C7D9_intel_20260407.txt` -- Android device report
- `MacBook-Pro_5C1E_intel_20260407.txt` -- macOS device report
- `Samsung-TV_E1F3_intel_20260407.txt` -- Smart TV device report
- `PS5_F2A1_intel_20260407.txt` -- Gaming console device report
- `ESP-SmartPlug_1B3C_intel_20260407.txt` -- IoT device report
- `Unknown-8B2A_intel_20260407.txt` -- Unclassified device report

---

## 9. Database Schema

### Table: `app_activity`
| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER PRIMARY KEY | Auto-increment ID |
| `timestamp` | DATETIME | When the sample was taken |
| `app_name` | TEXT | Application name |
| `window_title` | TEXT | Full window title |
| `process_name` | TEXT | Process binary name |
| `process_pid` | INTEGER | Process ID |
| `is_idle` | BOOLEAN | Whether user was idle |
| `duration_seconds` | INTEGER | Seconds focused (computed at next sample) |

### Table: `terminal_commands`
| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER PRIMARY KEY | Auto-increment ID |
| `timestamp` | DATETIME | When the command was executed |
| `shell` | TEXT | Shell type (bash, zsh, fish, powershell) |
| `command` | TEXT | Full command string |
| `working_dir` | TEXT | Working directory (if available) |

### Table: `network_devices`
| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER PRIMARY KEY | Auto-increment ID |
| `mac_address` | TEXT UNIQUE | Device MAC address |
| `ip_address` | TEXT | Last known IP address |
| `device_name` | TEXT | Resolved device name |
| `device_type` | TEXT | Classification (iPhone, Android, etc.) |
| `manufacturer` | TEXT | MAC OUI manufacturer |
| `confidence` | INTEGER | Classification confidence (0-100) |
| `first_seen` | DATETIME | First time device was detected |
| `last_seen` | DATETIME | Most recent detection |
| `mdns_hostname` | TEXT | mDNS hostname if available |
| `mdns_services` | TEXT | Comma-separated mDNS services |
| `ssdp_info` | TEXT | SSDP device description |
| `ttl` | INTEGER | ICMP TTL value |
| `netbios_name` | TEXT | NetBIOS name (Windows) |

### Table: `device_sessions`
| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER PRIMARY KEY | Auto-increment ID |
| `mac_address` | TEXT | Foreign key to network_devices |
| `session_start` | DATETIME | When device joined network |
| `session_end` | DATETIME | When device left network (NULL if still active) |
| `traffic_level` | TEXT | LIGHT / MODERATE / HEAVY |

### Table: `system_metrics`
| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER PRIMARY KEY | Auto-increment ID |
| `timestamp` | DATETIME | Sample time |
| `cpu_percent` | REAL | CPU usage percentage |
| `ram_percent` | REAL | RAM usage percentage |
| `disk_percent` | REAL | Disk usage percentage |
| `battery_percent` | REAL | Battery level |
| `battery_charging` | BOOLEAN | Is charger plugged in |
| `net_bytes_sent` | INTEGER | Cumulative bytes sent |
| `net_bytes_recv` | INTEGER | Cumulative bytes received |
| `wifi_ssid` | TEXT | Connected WiFi network name |
| `wifi_signal_dbm` | INTEGER | WiFi signal strength |

### Table: `report_log`
| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER PRIMARY KEY | Auto-increment ID |
| `report_date` | DATE | Date the report covers |
| `generated_at` | DATETIME | When report was built |
| `sent_at` | DATETIME | When email was sent (NULL if pending) |
| `status` | TEXT | SENT / PENDING / FAILED |
| `retry_count` | INTEGER | Number of send attempts |

---

## 10. Technology Stack & Libraries

### Core Language
- **Python 3.11+** with type hints throughout

### Dependencies

| Library | Version | Purpose | Required |
|---------|---------|---------|----------|
| `psutil` | 5.9+ | Process enumeration, CPU/RAM/battery, network I/O | Yes |
| `scapy` | 2.5+ | ARP scanning, packet crafting, ICMP probes, mDNS/SSDP listening | Yes |
| `schedule` | 1.2+ | Lightweight in-process job scheduling for report triggers | Yes |
| `jinja2` | 3.1+ | HTML email template rendering | Yes |
| `pyyaml` | 6.0+ | Configuration file parsing | Yes |
| `python-dotenv` | 1.0+ | Loading email credentials from `.env` file securely | Yes |
| `mac-vendor-lookup` | 0.1+ | MAC address to manufacturer name resolution (IEEE OUI database) | Yes |
| `netifaces` | 0.11+ | Enumerate network interfaces, get local IP/subnet | Yes |
| `pydantic` | 2.0+ | Data model validation and configuration schema enforcement | Yes |
| `watchdog` | 4.0+ | Filesystem event monitoring for history file changes | Yes |
| `python-xlib` | 0.33+ | Active window tracking on Linux (X11) | Linux only |
| `pywin32` | 306+ | Active window tracking and service registration on Windows | Windows only |
| `pytest` | 8.0+ | Unit and integration testing framework | Dev only |
| `pytest-mock` | 3.12+ | Mocking system calls in tests | Dev only |
| `pytest-cov` | 4.1+ | Code coverage reporting | Dev only |

### Built-in Standard Library Modules Used
- `sqlite3` -- Local database (WAL mode)
- `smtplib` -- SMTP email dispatch
- `email.mime` -- MIME message construction (HTML + attachments)
- `threading` -- Concurrent monitor execution
- `logging` -- Internal diagnostic logging (to file only, never stdout)
- `os`, `platform`, `subprocess` -- OS detection and system commands
- `json`, `datetime`, `pathlib` -- Data handling utilities

---

## 11. Project File Structure

```
Radar/
|
|-- radar/
|   |-- __init__.py
|   |-- main.py                     # Entry point: initializes daemon, starts all threads
|   |-- config.py                   # Pydantic settings model, loads config.yaml + .env
|   |
|   |-- monitors/
|   |   |-- __init__.py
|   |   |-- app_monitor.py          # Active window / application focus tracker
|   |   |-- terminal_monitor.py     # Shell history parser (bash/zsh/fish/powershell)
|   |   |-- net_sentinel.py         # ARP scanner, mDNS/SSDP listener, device fingerprinter
|   |   |-- system_monitor.py       # CPU, RAM, battery, disk, WiFi signal snapshots
|   |   |-- idle_detector.py        # Keyboard/mouse idle detection
|   |
|   |-- fingerprint/
|   |   |-- __init__.py
|   |   |-- classifier.py           # Device classification engine (confidence scoring)
|   |   |-- oui_lookup.py           # MAC vendor database wrapper
|   |   |-- mdns_parser.py          # mDNS announcement parser
|   |   |-- ssdp_parser.py          # SSDP/UPnP message parser
|   |   |-- ttl_analyzer.py         # TTL-based OS fingerprinting
|   |
|   |-- database/
|   |   |-- __init__.py
|   |   |-- vault.py                # SQLite connection manager (WAL mode)
|   |   |-- models.py               # Pydantic models for database records
|   |   |-- migrations.py           # Schema creation and migration logic
|   |   |-- cleanup.py              # Data retention enforcement and VACUUM
|   |
|   |-- reporting/
|   |   |-- __init__.py
|   |   |-- report_builder.py       # Aggregates data, builds HTML + device .txt files
|   |   |-- device_report.py        # Generates individual per-device .txt intel files
|   |   |-- email_dispatcher.py     # SMTP connector with retry and TLS
|   |   |-- templates/
|   |       |-- daily_report.html   # Jinja2 email template
|   |
|   |-- utils/
|       |-- __init__.py
|       |-- helpers.py              # Time formatting, OS detection, subnet calculation
|       |-- stealth.py              # Process name obfuscation, anti-detection utilities
|       |-- watchdog_handler.py     # Filesystem watcher for shell history files
|
|-- tests/
|   |-- __init__.py
|   |-- test_app_monitor.py
|   |-- test_terminal_monitor.py
|   |-- test_net_sentinel.py
|   |-- test_classifier.py
|   |-- test_report_builder.py
|   |-- test_device_report.py
|   |-- test_email_dispatcher.py
|   |-- test_vault.py
|   |-- conftest.py                 # Shared fixtures (mock DB, fake devices, etc.)
|
|-- config.yaml                     # User configuration file
|-- .env                            # Gmail credentials (APP PASSWORD, not main password)
|-- requirements.txt                # Production dependencies
|-- requirements-dev.txt            # Development/testing dependencies
|-- setup.py                        # Package installation script
|-- Makefile                        # Common commands (install, test, run, deploy)
|-- README.md                       # This document
|-- LICENSE
```

---

## 12. Configuration Reference

### `config.yaml`
```yaml
# Radar Configuration

general:
  report_time: "23:00"              # 24-hour format: when to send the daily report
  timezone: "Asia/Riyadh"           # Your local timezone
  data_retention_days: 30           # How many days to keep data before auto-purge
  log_level: "WARNING"              # Logging level (DEBUG/INFO/WARNING/ERROR)

monitoring:
  app_sample_interval: 30           # Seconds between app focus samples
  system_sample_interval: 60        # Seconds between CPU/RAM snapshots
  idle_threshold: 300               # Seconds of no input before marking as idle

network:
  scan_interval: 180                # Seconds between ARP sweeps (3 minutes)
  scan_jitter: 60                   # Random jitter added to scan interval (+/- seconds)
  subnet: "auto"                    # "auto" detects from interface, or specify "192.168.1.0/24"
  interface: "auto"                 # "auto" picks the default WiFi interface
  enable_mdns: true                 # Listen for mDNS/Bonjour announcements
  enable_ssdp: true                 # Listen for SSDP/UPnP announcements
  enable_netbios: true              # Send NetBIOS name queries

email:
  enabled: true
  recipient: "your.email@gmail.com"
  sender: "your.email@gmail.com"
  smtp_server: "smtp.gmail.com"
  smtp_port: 587
  use_tls: true
  # Credentials loaded from .env file (GMAIL_APP_PASSWORD)

stealth:
  process_name: "kworker/sys"       # Disguised process name
  hide_from_taskmanager: true       # Attempt to hide from casual task manager view
```

### `.env`
```env
GMAIL_APP_PASSWORD=xxxx-xxxx-xxxx-xxxx
```

---

## 13. Security & Privacy Considerations

### Credential Safety
- Gmail credentials are **never** stored in code or config.yaml. They are loaded exclusively from the `.env` file.
- The `.env` file must have restricted permissions (`chmod 600`) so only the owning user can read it.
- A Gmail **App Password** is used (not the main account password). This is a 16-character single-purpose token generated from Google Account settings.

### Data Encryption
- The SQLite database file should be stored in a user-accessible-only directory with `chmod 700` permissions.
- Email transmission uses TLS 1.2+ encryption (enforced by `smtplib.SMTP.starttls()`).
- Future enhancement: Optional SQLCipher integration for encrypted-at-rest database.

### Sensitive Data Filtering
- The terminal monitor should implement configurable regex filters to redact potentially sensitive commands (e.g., commands containing `password`, `token`, `secret`, `API_KEY`).
- Redacted commands are logged as `[REDACTED: sensitive content detected]` with the command type preserved.

### Network Scanning Ethics
- Radar performs read-only network reconnaissance. It does not attempt to exploit, intrude, or modify any discovered device.
- All scanning is confined to the local subnet. No external network probing is performed.
- ARP scanning is a standard network administration technique and does not penetrate device security boundaries.

---

## 14. Software Testing Strategy

### 14.1 Unit Tests (`pytest`)

Every module is tested in isolation with mocked system dependencies:

| Module | Mock Strategy | Key Test Cases |
|--------|---------------|----------------|
| `app_monitor` | Mock `xdotool` / `win32gui` responses | Correctly parses window title; handles no active window; handles special characters |
| `terminal_monitor` | Create temporary history files with known content | Parses zsh timestamps; handles empty history; detects new lines only |
| `net_sentinel` | Mock `scapy.arping()` with fabricated ARP responses | Discovers 3 fake devices; handles empty network; handles duplicate MACs |
| `classifier` | Inject known fingerprint data | iPhone classified with 95% confidence; unknown device handled gracefully |
| `report_builder` | Inject mock database records | HTML output contains expected tables; handles zero activity day; handles 50+ devices |
| `device_report` | Inject mock device profile | Output file matches expected format; filename sanitization works |
| `email_dispatcher` | Mock `smtplib.SMTP` | Verifies TLS is called; verifies attachments are added; retry logic works on failure |
| `vault` | Use in-memory SQLite (`':memory:'`) | CRUD operations work; WAL mode is enabled; cleanup deletes old records |

**Coverage target:** 85%+ line coverage.

### 14.2 Integration Tests

- **Monitor-to-Database Pipeline:** Start app_monitor and terminal_monitor with mock data sources, verify records appear in a temporary SQLite database.
- **Database-to-Report Pipeline:** Pre-populate a test database with 24 hours of fake data, trigger report_builder, verify HTML output and `.txt` file generation.
- **Full Email Pipeline:** Generate a report and send it to a test Gmail account (sandboxed), verify receipt and attachment integrity.

### 14.3 Performance & Stealth Profiling

- **CPU Benchmark:** Run the full daemon for 1 hour with `cProfile` attached. Verify average CPU < 2%.
- **Memory Benchmark:** Monitor RSS memory usage over a 72-hour sustained run. Verify no memory leaks (memory stays under 80MB).
- **Disk I/O Benchmark:** Monitor write operations per minute. Ensure batch writes, not continuous streaming.
- **Stealth Audit:** While daemon is running, open the system's task manager / Activity Monitor / `htop`. Verify the process does not stand out by name or resource usage.

### 14.4 Network Test Scenarios

| Scenario | Expected Behavior |
|----------|-------------------|
| Normal WiFi with 5 devices | All 5 detected and classified within 5 minutes |
| WiFi drops for 30 minutes | Data buffered locally, report sent when reconnected |
| No WiFi at all (offline day) | Host activity still tracked, network section shows "No connection" |
| Device joins then leaves WiFi | Join/leave times correctly logged in device report |
| 50+ devices on network (busy cafe) | All detected, reports generated without crash, email size manageable |

### 14.5 Edge Case Tests

- System clock change during monitoring
- Laptop goes to sleep and wakes up after 4 hours
- Shell history file is rotated or deleted
- SQLite database file reaches 500MB
- Gmail sends rate-limited (429 response)

---

## 15. Deployment & Installation

### Option A: systemd Service (Linux - Recommended)

```bash
# 1. Clone and install
git clone https://github.com/your-repo/radar.git
cd radar
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 2. Configure
cp config.example.yaml config.yaml
# Edit config.yaml with your preferences
echo "GMAIL_APP_PASSWORD=your-app-password-here" > .env
chmod 600 .env

# 3. Install as systemd service
sudo cp radar.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable radar
sudo systemctl start radar

# 4. Verify it is running
sudo systemctl status radar
```

### Option B: launchd Service (macOS)

```bash
cp com.system.radar.plist ~/Library/LaunchAgents/
launchctl load ~/Library/LaunchAgents/com.system.radar.plist
```

### Option C: Windows Service

```powershell
# Using NSSM (Non-Sucking Service Manager) to register as a Windows service
nssm install Radar "C:\Radar\.venv\Scripts\python.exe" "C:\Radar\radar\main.py"
nssm start Radar
```

---

## 16. Performance Benchmarks & Constraints

| Metric | Target | Rationale |
|--------|--------|-----------|
| CPU (average) | < 2% | Must be imperceptible in task manager |
| CPU (peak) | < 5% | Brief spikes during ARP scan or report generation |
| RAM (steady state) | < 80 MB | Below threshold that triggers user attention |
| Disk writes | < 500 KB/min | Batched writes to avoid SSD wear and I/O spikes |
| Database size (daily) | 5-15 MB | Varies by activity and device count |
| Database size (30 days) | 150-450 MB | Within acceptable range for local storage |
| ARP scan duration | < 3 seconds | Fast enough to not congest the network |
| Report generation time | < 30 seconds | Even with 50+ devices and full day of data |
| Email send time | < 10 seconds | Depends on attachment size and network speed |
| Boot-to-monitoring | < 5 seconds | Daemon must be collecting data within 5s of startup |

---

## 17. Future Enhancements & Roadmap

### Phase 2 Enhancements (Recommended)

| Enhancement | Description | Benefit |
|-------------|-------------|---------|
| **Web Dashboard** | Local Flask/FastAPI dashboard accessible at `localhost:8080` showing real-time activity and network map | Visual monitoring without waiting for the daily email |
| **Bluetooth Device Discovery** | Scan for nearby Bluetooth devices (phones, headphones, wearables) in addition to WiFi | Broader device awareness -- detect devices not on WiFi |
| **Browser History Integration** | Parse Chrome/Firefox/Safari history databases to report visited URLs and time spent per site | Deeper insight into browsing activity beyond just "Chrome was open" |
| **Screenshot Capture** | Take a screenshot every N minutes and attach a summary collage to the daily report | Visual proof of activity at specific times |
| **Weekly/Monthly Summary Reports** | Aggregate daily data into trend reports (most used apps this week, network device frequency) | Long-term pattern recognition and habit tracking |
| **Geolocation Awareness** | Use WiFi BSSID databases or IP geolocation to tag reports with physical location | Know which WiFi network and location the activity occurred at |
| **Telegram Bot Integration** | Real-time alerts to a Telegram bot when a new device joins the network or anomalous activity is detected | Instant notifications, not just daily reports |
| **Encrypted Database (SQLCipher)** | Encrypt the SQLite database at rest using SQLCipher | Prevents data exposure if laptop is lost or stolen |
| **USB Device Monitoring** | Log USB devices that are plugged in/removed (flash drives, external drives) | Detect unauthorized data transfer attempts |
| **Application Network Traffic** | Track which apps are making network connections and to what destinations | Identify apps phoning home or consuming excessive bandwidth |
| **Multi-Machine Support** | Deploy Radar on multiple machines, all reporting to a single central Gmail or dashboard | Monitor an entire household or office from one place |
| **Audio/Microphone Detection** | Detect when microphone or camera is being accessed by applications | Privacy awareness -- know if an app is listening or watching |

### Phase 3 (Advanced)

| Enhancement | Description |
|-------------|-------------|
| **Machine Learning Anomaly Detection** | Train a model on "normal" daily patterns and flag deviations (unusual app at unusual time, unknown device at 3 AM) |
| **Remote Configuration** | Send config updates to Radar via a special email with encrypted commands -- no SSH needed |
| **Packet Deep Inspection** | Analyze HTTP/DNS traffic from other devices to understand what websites/services they are using (requires promiscuous mode and elevated privileges) |
| **Mobile Companion App** | Android/iOS app that shows the latest Radar report and pushes real-time network alerts |

---

## 18. Known Limitations

| Limitation | Description | Mitigation |
|------------|-------------|------------|
| **Requires root/admin for ARP scanning** | Scapy ARP scanning typically needs elevated privileges | Run daemon with sudo or use capabilities (`cap_net_raw`) |
| **Some devices hide from ARP** | Some devices may have ARP caching or randomized MACs (iOS 14+ randomizes WiFi MAC by default) | Combine ARP with mDNS for Apple devices, which still broadcasts real hostname |
| **Cannot see traffic content** | Radar does not perform deep packet inspection by default | Traffic is estimated by volume, not content. DPI is a Phase 3 enhancement |
| **Shell history depends on config** | Bash without `HISTTIMEFORMAT` has no timestamps | Document the recommended shell config for the user to enable timestamps |
| **Email delivery is not instant** | Gmail may delay or rate-limit SMTP | Retry logic with exponential backoff handles transient failures |
| **WiFi-only discovery** | Ethernet-connected devices not on WiFi are on the same subnet and will be discovered, but wireless-specific metadata (SSID, signal) does not apply | Future enhancement for Ethernet/mixed network support |

---

## 19. Glossary

| Term | Definition |
|------|------------|
| **ARP** | Address Resolution Protocol -- maps IP addresses to MAC addresses on a local network |
| **MAC Address** | Media Access Control address -- unique hardware identifier for a network interface |
| **OUI** | Organizationally Unique Identifier -- the first 3 bytes of a MAC address, identifying the manufacturer |
| **mDNS** | Multicast DNS -- protocol used by devices (especially Apple) to advertise their names and services on a local network |
| **SSDP** | Simple Service Discovery Protocol -- used by UPnP devices (smart TVs, consoles) to announce their presence |
| **TTL** | Time To Live -- a value in IP packets that indirectly reveals the operating system of the sender |
| **WAL Mode** | Write-Ahead Logging -- SQLite journaling mode that allows concurrent reads and writes |
| **SMTP** | Simple Mail Transfer Protocol -- used to send emails |
| **TLS** | Transport Layer Security -- encryption protocol for network communication |
| **Daemon** | A background process that runs without user interaction |
| **Jitter** | Random time variation added to scheduled tasks to avoid pattern detection |
| **mTLS** | Mutual TLS -- both client and server authenticate each other (future enhancement) |
| **SQLCipher** | An extension to SQLite that provides 256-bit AES encryption of database files |
| **systemd** | Linux init system and service manager used to run background services |
| **launchd** | macOS daemon/service manager (equivalent of systemd) |
| **App Password** | A Google-generated 16-character password for third-party app access to Gmail via SMTP |

---

**Document Version:** 1.0
**Last Updated:** April 7, 2026
**Author:** Radar Development Team
**Status:** Draft - Ready for Implementation
