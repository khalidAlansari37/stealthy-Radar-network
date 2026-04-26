# Radar - Sprint Implementation Plan

> This document breaks the entire Radar project into **6 sprints** with a total estimated development time of **6 weeks** (one sprint per week). Each sprint is self-contained, testable, and builds on the previous one. No sprint ships dead code -- every sprint ends with something that runs and proves itself.

---

## Dependency Analysis

Before defining sprints, here is the dependency chain that dictates the build order:

```
                          config.py
                             |
                          vault.py (database)
                         /   |    \
                        /    |     \
            app_monitor  terminal_monitor  system_monitor
                        \    |     /
                         \   |    /
                     net_sentinel + fingerprint/
                             |
                     report_builder + device_report
                             |
                     email_dispatcher
                             |
                       main.py (daemon)
                             |
                   systemd / stealth layer
```

**Rule:** Nothing can write data without `vault.py`. Nothing can read config without `config.py`. Reports cannot exist without monitors feeding data. Email cannot fire without reports. The daemon cannot run without all pieces assembled. This chain dictates the sprint order.

---

## Sprint Overview

| Sprint | Name | Duration | Goal |
|--------|------|----------|------|
| 1 | Foundation & Data Layer | Week 1 | Project skeleton, config system, SQLite vault, schema, models |
| 2 | Host Monitors | Week 2 | App monitor, terminal monitor, system monitor, idle detector |
| 3 | Network Intelligence | Week 3 | ARP scanner, mDNS/SSDP listeners, fingerprint engine, device classification |
| 4 | Reporting & Email | Week 4 | Report builder, per-device .txt files, HTML template, email dispatcher |
| 5 | Daemon, Stealth & Integration | Week 5 | Main loop, threading, scheduler, systemd service, stealth utilities, full pipeline |
| 6 | Testing, Hardening & Deployment | Week 6 | Full test suite, performance profiling, edge cases, documentation, final deploy |

---

## Sprint 1: Foundation & Data Layer

**Duration:** Week 1 (Days 1-7)
**Goal:** Create the full project structure, configuration system, and database layer. By end of sprint, you can load config, create tables, insert/query rows, and run the cleanup job.

### Tasks

- [ ] **1.1 Project scaffold**
  - Create the entire directory tree as defined in README Section 11
  - Initialize `__init__.py` in every package
  - Create `requirements.txt` and `requirements-dev.txt`
  - Create the virtual environment and install all dependencies
  - Create `Makefile` with targets: `install`, `test`, `run`, `clean`

- [ ] **1.2 Configuration system (`radar/config.py`)**
  - Define Pydantic `Settings` model matching `config.yaml` schema from README Section 12
  - Sections: `GeneralConfig`, `MonitoringConfig`, `NetworkConfig`, `EmailConfig`, `StealthConfig`
  - Load and validate `config.yaml` using `pyyaml`
  - Load `.env` for `GMAIL_APP_PASSWORD` using `python-dotenv`
  - Provide sensible defaults for every field
  - Singleton pattern: one global `settings` object importable by all modules
  - Create `config.example.yaml` template

- [ ] **1.3 Data models (`radar/database/models.py`)**
  - Define Pydantic models for every database entity:
    - `AppActivityRecord`
    - `TerminalCommandRecord`
    - `NetworkDeviceRecord`
    - `DeviceSessionRecord`
    - `SystemMetricRecord`
    - `ReportLogRecord`
  - Each model has `to_dict()` for DB insertion and `from_row()` classmethod for DB reads

- [ ] **1.4 Database vault (`radar/database/vault.py`)**
  - Implement `Vault` class wrapping `sqlite3`
  - Enable WAL mode on connection: `PRAGMA journal_mode=WAL`
  - Thread-safe: use `check_same_thread=False` and a threading lock
  - Methods: `insert_app_activity()`, `insert_terminal_command()`, `insert_network_device()`, `upsert_network_device()`, `insert_device_session()`, `insert_system_metric()`, `insert_report_log()`
  - Query methods: `get_app_activity(date)`, `get_terminal_commands(date)`, `get_network_devices(date)`, `get_device_sessions(mac, date)`, `get_system_metrics(date)`, `get_report_status(date)`
  - Database file stored at `~/.radar/radar.db` (hidden directory)

- [ ] **1.5 Schema migrations (`radar/database/migrations.py`)**
  - Implement `create_tables()` with all 6 tables from README Section 9
  - Add proper indexes on timestamp columns and mac_address
  - Version tracking: store schema version in a `metadata` table
  - Idempotent: safe to call multiple times (`CREATE TABLE IF NOT EXISTS`)

- [ ] **1.6 Data cleanup (`radar/database/cleanup.py`)**
  - Implement `purge_old_data(retention_days)` deleting records older than threshold
  - Implement `vacuum_database()` to compact after purge
  - Read `data_retention_days` from config

- [ ] **1.7 Utility helpers (`radar/utils/helpers.py`)**
  - `detect_os()` -> returns `"linux"`, `"macos"`, or `"windows"`
  - `format_duration(seconds)` -> returns `"4h 23m"`
  - `get_local_subnet()` -> auto-detect subnet using `netifaces`
  - `get_wifi_interface()` -> auto-detect active WiFi interface
  - `sanitize_filename(name)` -> make device names safe for filenames
  - `get_radar_data_dir()` -> returns `~/.radar/` path, creates if missing

### Tests (Sprint 1)

| Test File | What It Validates |
|-----------|-------------------|
| `test_config.py` | Config loads from YAML; defaults work; .env password loads; invalid config raises error |
| `test_vault.py` | Tables created; CRUD for all 6 tables; WAL mode active; thread safety |
| `test_cleanup.py` | Old data purged correctly; retention boundary is precise; vacuum runs without error |
| `test_models.py` | Pydantic models validate; `to_dict()` and `from_row()` round-trip correctly |
| `test_helpers.py` | OS detection; duration formatting; filename sanitization |

### Definition of Done

```
$ make test
> All Sprint 1 tests pass
> Config loads from config.yaml
> Database creates all 6 tables
> Insert + query works for every table
> Cleanup removes old records
> Coverage > 90% for database/ and config.py
```

### Files Created

```
radar/__init__.py
radar/main.py              (placeholder)
radar/config.py
radar/monitors/__init__.py
radar/fingerprint/__init__.py
radar/database/__init__.py
radar/database/vault.py
radar/database/models.py
radar/database/migrations.py
radar/database/cleanup.py
radar/reporting/__init__.py
radar/utils/__init__.py
radar/utils/helpers.py
config.example.yaml
.env.example
requirements.txt
requirements-dev.txt
Makefile
tests/__init__.py
tests/conftest.py
tests/test_config.py
tests/test_vault.py
tests/test_cleanup.py
tests/test_models.py
tests/test_helpers.py
```

---

## Sprint 2: Host Monitors

**Duration:** Week 2 (Days 8-14)
**Goal:** Build the three host monitoring modules. By end of sprint, you can run each monitor independently and watch real data flow into the SQLite database.

### Tasks

- [ ] **2.1 App Monitor (`radar/monitors/app_monitor.py`)**
  - Implement `AppMonitor` class with `sample()` method
  - **Linux implementation:**
    - Use `subprocess` to call `xdotool getactivewindow getwindowname` for window title
    - Use `xdotool getactivewindow getwindowpid` for PID
    - Use `psutil.Process(pid).name()` to get the binary name
    - Fallback: parse `/proc/<pid>/comm` if xdotool is unavailable
  - Store each sample as an `AppActivityRecord` via `vault.insert_app_activity()`
  - Calculate `duration_seconds` by comparing current sample timestamp to previous
  - Handle edge cases: no active window (screen locked), permission denied, X11 not available

- [ ] **2.2 Terminal Monitor (`radar/monitors/terminal_monitor.py`)**
  - Implement `TerminalMonitor` class
  - On initialization, detect which shells are configured by checking for history files:
    - `~/.bash_history` (Bash)
    - `~/.zsh_history` (Zsh)
    - `~/.local/share/fish/fish_history` (Fish)
  - Track a `last_read_position` (byte offset) per file to only read new lines
  - **Zsh parser:** Parse `: <epoch>:0;<command>` format to extract timestamp + command
  - **Bash parser:** Read raw lines. If `HISTTIMEFORMAT` timestamps exist (lines starting with `#<epoch>`), parse them. Otherwise use file mtime.
  - **Fish parser:** Parse the YAML-like `cmd:` and `when:` blocks
  - Use `watchdog` library to watch history files for modifications instead of polling
  - Implement `radar/utils/watchdog_handler.py` with a custom `FileSystemEventHandler` that calls `TerminalMonitor.on_history_modified()`
  - Sensitive command filter: regex list from config, replace matched commands with `[REDACTED]`

- [ ] **2.3 System Monitor (`radar/monitors/system_monitor.py`)**
  - Implement `SystemMonitor` class with `snapshot()` method
  - Use `psutil` for all metrics:
    - `cpu_percent(interval=1)` -- note: first call always returns 0, needs warmup
    - `virtual_memory().percent`
    - `disk_usage('/').percent`
    - `sensors_battery()` -- handle `None` on desktops without battery
    - `net_io_counters()` -- bytes_sent, bytes_recv
    - `boot_time()` -- calculate uptime
    - `users()` -- active sessions
  - **WiFi SSID detection (Linux):** parse output of `nmcli -t -f active,ssid dev wifi` or read `/proc/net/wireless`
  - **WiFi signal strength:** parse from `iwconfig` or `nmcli -f SIGNAL`
  - Store each snapshot as `SystemMetricRecord` via vault

- [ ] **2.4 Idle Detector (`radar/monitors/idle_detector.py`)**
  - Implement `IdleDetector` class
  - **Linux:** Use `xprintidle` command (returns milliseconds since last input) or read from `/sys/` kernel interfaces
  - Compare idle time against `config.monitoring.idle_threshold`
  - Expose `is_idle() -> bool` method consumed by AppMonitor
  - If idle, AppMonitor marks the sample with `is_idle=True`

### Tests (Sprint 2)

| Test File | What It Validates |
|-----------|-------------------|
| `test_app_monitor.py` | Mocks `subprocess.run(xdotool)` with fake window data; verifies record inserted into DB; handles no-window case; handles special chars in title |
| `test_terminal_monitor.py` | Creates temp zsh_history with known timestamps; verifies parsing extracts correct command+time; verifies only new lines are read; verifies [REDACTED] for sensitive commands |
| `test_system_monitor.py` | Mocks `psutil` functions; verifies all metrics captured; handles no-battery gracefully; handles missing WiFi |
| `test_idle_detector.py` | Mocks `xprintidle`; verifies idle=True when over threshold; verifies idle=False when active |

### Definition of Done

```
$ python -m radar.monitors.app_monitor      # Samples once, prints result
$ python -m radar.monitors.terminal_monitor  # Reads history, prints commands
$ python -m radar.monitors.system_monitor    # Prints CPU/RAM/battery snapshot
> All Sprint 2 tests pass
> Each monitor writes real data to ~/.radar/radar.db
> Data is queryable via vault.get_*() methods
```

### Files Created

```
radar/monitors/app_monitor.py
radar/monitors/terminal_monitor.py
radar/monitors/system_monitor.py
radar/monitors/idle_detector.py
radar/utils/watchdog_handler.py
tests/test_app_monitor.py
tests/test_terminal_monitor.py
tests/test_system_monitor.py
tests/test_idle_detector.py
```

---

## Sprint 3: Network Intelligence

**Duration:** Week 3 (Days 15-21)
**Goal:** Build the network scanning and device fingerprinting engine. By end of sprint, you can run a scan that discovers devices, classifies them (iPhone, Android, Smart TV, etc.), and stores full profiles in the database.

### Tasks

- [ ] **3.1 ARP Scanner (core of `radar/monitors/net_sentinel.py`)**
  - Implement `NetworkSentinel` class
  - `arp_sweep(subnet)` method using `scapy`:
    ```python
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=subnet), timeout=3, verbose=0)
    ```
  - Extract IP and MAC from each response
  - Auto-detect subnet from config or via `helpers.get_local_subnet()`
  - Add random jitter: `scan_interval +/- scan_jitter` seconds

- [ ] **3.2 MAC OUI Lookup (`radar/fingerprint/oui_lookup.py`)**
  - Wrap the `mac-vendor-lookup` library
  - Method: `lookup(mac_address) -> str` returning manufacturer name
  - Handle lookup failures gracefully -> return `"Unknown Manufacturer"`
  - Cache results in-memory (dict) to avoid redundant lookups for same MAC prefix

- [ ] **3.3 TTL Analyzer (`radar/fingerprint/ttl_analyzer.py`)**
  - Send a single ICMP echo (`scapy.IP(dst=ip)/ICMP()`) and capture the response TTL
  - Classification map:
    - TTL 64 -> Linux / macOS / iOS / Android
    - TTL 128 -> Windows
    - TTL 255 -> Network equipment / IoT
  - Method: `analyze(ip) -> dict` with `{"ttl": int, "os_family": str}`
  - Timeout handling: if no response in 2 seconds, return `{"ttl": None, "os_family": "Unknown"}`

- [ ] **3.4 mDNS Parser (`radar/fingerprint/mdns_parser.py`)**
  - Open UDP socket on port 5353, join multicast group `224.0.0.251`
  - Run as a background thread: continuously listen for mDNS announcements
  - Parse incoming packets to extract:
    - Hostname (e.g., `Ahmeds-iPhone.local`)
    - Service types (e.g., `_airplay._tcp`, `_airdrop._tcp`, `_smb._tcp`)
  - Store parsed data in a thread-safe dict keyed by IP address
  - Method: `get_mdns_info(ip) -> dict | None`

- [ ] **3.5 SSDP Parser (`radar/fingerprint/ssdp_parser.py`)**
  - Open UDP socket on port 1900, join multicast group `239.255.255.250`
  - Listen for `NOTIFY` and `M-SEARCH` response messages
  - Parse `SERVER`, `ST` (search target), `USN`, `LOCATION` headers
  - Method: `get_ssdp_info(ip) -> dict | None`
  - Useful for identifying Smart TVs (`MediaRenderer`), gaming consoles, Chromecasts

- [ ] **3.6 Device Classifier (`radar/fingerprint/classifier.py`)**
  - Implement the confidence-scoring engine from README Section 6
  - Input: `DeviceFingerprint` dataclass containing MAC, OUI vendor, TTL, mDNS data, SSDP data
  - Output: `DeviceClassification` with `device_type`, `device_name`, `confidence` (0-100)
  - Scoring rules (from README):
    - MAC OUI = Apple -> +30 points
    - mDNS hostname contains "iPhone" -> +40 points
    - mDNS services include `_airdrop._tcp` -> +15 points
    - TTL = 64 -> +10 points
    - SSDP deviceType = MediaRenderer -> +30 points
    - NetBIOS name exists -> +25 points
  - Threshold: confidence >= 60 -> classified, else -> "Unknown"
  - Classification categories: iPhone, iPad, Android, macOS, Windows, Linux, Smart TV, Gaming Console, IoT, Network Equipment, Unknown

- [ ] **3.7 Network Sentinel orchestration**
  - Wire everything together in `net_sentinel.py`:
    1. Run ARP sweep -> get list of (IP, MAC) pairs
    2. For each device: OUI lookup, TTL analysis, check mDNS cache, check SSDP cache
    3. Feed all fingerprint data to `classifier.classify()`
    4. Upsert device in `network_devices` table
    5. Create/update `device_sessions` records (track join/leave via first_seen/last_seen)
  - Session logic: if a device was seen last time but NOT in current scan, close its session (set `session_end`). If a device is newly seen, start a new session.

### Tests (Sprint 3)

| Test File | What It Validates |
|-----------|-------------------|
| `test_net_sentinel.py` | Mock `scapy.srp()` with 5 fake ARP responses; verify all 5 stored in DB; verify session creation; verify device upsert on re-scan |
| `test_classifier.py` | Feed Apple OUI + iPhone mDNS -> expect "iPhone" at 85%; Feed unknown MAC + no mDNS -> expect "Unknown"; Feed Samsung OUI + Android mDNS -> expect "Android" |
| `test_oui_lookup.py` | Known Apple MAC returns "Apple Inc."; unknown MAC returns "Unknown Manufacturer"; results are cached |
| `test_ttl_analyzer.py` | Mock ICMP response with TTL=128 -> "Windows"; TTL=64 -> "Linux/macOS"; No response -> "Unknown" |
| `test_mdns_parser.py` | Parse a crafted mDNS packet; extract hostname and services correctly |
| `test_ssdp_parser.py` | Parse a crafted SSDP NOTIFY; extract device type and friendly name |

### Definition of Done

```
$ sudo python -m radar.monitors.net_sentinel   # Runs one ARP sweep, prints discovered devices
> Devices appear in DB with classification (iPhone, Android, etc.)
> mDNS listener running in background thread
> SSDP listener running in background thread
> All Sprint 3 tests pass
> Classification accuracy visually verified on local network
```

### Files Created

```
radar/monitors/net_sentinel.py
radar/fingerprint/__init__.py
radar/fingerprint/classifier.py
radar/fingerprint/oui_lookup.py
radar/fingerprint/mdns_parser.py
radar/fingerprint/ssdp_parser.py
radar/fingerprint/ttl_analyzer.py
tests/test_net_sentinel.py
tests/test_classifier.py
tests/test_oui_lookup.py
tests/test_ttl_analyzer.py
tests/test_mdns_parser.py
tests/test_ssdp_parser.py
```

---

## Sprint 4: Reporting & Email

**Duration:** Week 4 (Days 22-28)
**Goal:** Build the report generation pipeline and email dispatch. By end of sprint, you can trigger a report manually and receive a complete daily intelligence email in your Gmail inbox with per-device .txt attachments.

### Tasks

- [ ] **4.1 Per-device report generator (`radar/reporting/device_report.py`)**
  - Implement `generate_device_report(device, sessions, date) -> str`
  - Produces the exact text format from README Section 7:
    - DEVICE IDENTITY block (name, type, manufacturer, MAC, IP, confidence)
    - CLASSIFICATION EVIDENCE block (OUI score, mDNS score, TTL score)
    - CONNECTION TIMELINE block (list of online/offline periods with durations)
    - NETWORK ACTIVITY block (ARP count, mDNS count, traffic level, services)
    - NOTES block (auto-generated observations based on connection patterns)
  - Implement `save_device_report(content, device_name, mac_suffix, date) -> filepath`
  - Filename format: `<DeviceName>_<MACsuffix>_intel_<YYYYMMDD>.txt`
  - Use `helpers.sanitize_filename()` for safe device names

- [ ] **4.2 Host activity report (`radar/reporting/report_builder.py` -- host section)**
  - Query `vault.get_app_activity(date)` and aggregate:
    - Total active time vs idle time
    - Per-app time spent (sorted descending)
    - Session count per app
    - First activity / last activity timestamps
  - Query `vault.get_terminal_commands(date)`:
    - Full chronological list of commands with timestamps
    - Total command count
  - Query `vault.get_system_metrics(date)` and compute:
    - Average CPU, RAM
    - Final battery level and charging status
    - WiFi SSID, average signal
    - System uptime
  - Generate `host_activity_YYYYMMDD.txt` file with full details

- [ ] **4.3 HTML email template (`radar/reporting/templates/daily_report.html`)**
  - Jinja2 template with inline CSS (email-client compatible)
  - Section A: Host Activity Summary (app table, command excerpt)
  - Section B: Network Intelligence Summary (device grid table)
  - Section C: System Health Summary (metrics table)
  - Clean monospace-friendly styling with a dark header banner
  - Responsive: readable on mobile Gmail app
  - Variables: `date`, `apps`, `commands`, `devices`, `metrics`, `wifi_info`

- [ ] **4.4 Report builder orchestration (`radar/reporting/report_builder.py` -- main)**
  - Implement `build_daily_report(date) -> ReportPackage`
  - `ReportPackage` contains:
    - `html_body: str` -- rendered Jinja2 HTML
    - `host_report_path: str` -- path to host_activity .txt
    - `device_report_paths: list[str]` -- paths to all device .txt files
    - `subject: str` -- email subject line
  - Orchestration flow:
    1. Query all data for the given date from vault
    2. Generate host activity .txt
    3. For each network device: generate individual .txt file
    4. Render HTML template with summary data
    5. Return the complete `ReportPackage`
  - Handle edge cases: zero apps (idle day), zero devices (offline), zero commands

- [ ] **4.5 Email dispatcher (`radar/reporting/email_dispatcher.py`)**
  - Implement `EmailDispatcher` class
  - `send_report(report_package: ReportPackage) -> bool`
  - Build `MIMEMultipart` message:
    - `MIMEText(html_body, "html")` as the email body
    - `MIMEBase` attachment for `host_activity_YYYYMMDD.txt`
    - `MIMEBase` attachment for each `device_intel_YYYYMMDD.txt`
  - SMTP connection:
    ```python
    with smtplib.SMTP(server, port) as smtp:
        smtp.starttls()
        smtp.login(sender, app_password)
        smtp.send_message(msg)
    ```
  - Retry logic: on failure, wait 30s, retry. Exponential backoff up to 5 attempts (30, 60, 120, 240, 480 seconds).
  - On final failure: save the `ReportPackage` to `~/.radar/pending_reports/` for later dispatch.
  - Log report status in `report_log` table via vault.

- [ ] **4.6 Pending report recovery**
  - On daemon startup, check `~/.radar/pending_reports/` for unsent reports
  - Attempt to send each pending report
  - Delete from pending directory on successful send

### Tests (Sprint 4)

| Test File | What It Validates |
|-----------|-------------------|
| `test_device_report.py` | Generate report for a mock iPhone device; verify all sections present; verify filename sanitization; verify connection timeline calculation |
| `test_report_builder.py` | Pre-populate DB with fake 24h data (10 apps, 30 commands, 5 devices); trigger build; verify HTML contains correct tables; verify 5 device .txt files + 1 host .txt generated |
| `test_email_dispatcher.py` | Mock `smtplib.SMTP`; verify `starttls()` called; verify all attachments added; verify retry on mock failure (3 attempts then success); verify pending save on total failure |
| `test_html_template.py` | Render template with known data; verify HTML is valid; verify edge cases (0 apps, 0 devices) |

### Definition of Done

```
$ python -c "from radar.reporting.report_builder import build_daily_report; build_daily_report('2026-04-07')"
> Generates HTML + all .txt files in ~/.radar/reports/
$ python -c "from radar.reporting.email_dispatcher import EmailDispatcher; EmailDispatcher().send_report(pkg)"
> Email received in Gmail with correct body and all attachments
> All Sprint 4 tests pass
```

### Files Created

```
radar/reporting/report_builder.py
radar/reporting/device_report.py
radar/reporting/email_dispatcher.py
radar/reporting/templates/daily_report.html
tests/test_device_report.py
tests/test_report_builder.py
tests/test_email_dispatcher.py
tests/test_html_template.py
```

---

## Sprint 5: Daemon, Stealth & Integration

**Duration:** Week 5 (Days 29-35)
**Goal:** Wire everything into a single invisible daemon that starts on boot, runs 24/7, orchestrates all monitors on threads, triggers nightly reports, and hides from casual detection.

### Tasks

- [ ] **5.1 Main daemon loop (`radar/main.py`)**
  - Entry point: `def main():`
  - Initialization sequence:
    1. Load config (`config.py`)
    2. Create data directory (`~/.radar/`)
    3. Initialize database (run migrations)
    4. Apply stealth (rename process, set nice priority)
    5. Start monitor threads
    6. Start network listener threads (mDNS, SSDP)
    7. Schedule daily report job
    8. Schedule weekly cleanup job
    9. Enter main loop (`while True: schedule.run_pending(); sleep(1)`)
  - Graceful shutdown: catch SIGTERM/SIGINT, stop threads, close DB

- [ ] **5.2 Thread orchestration**
  - Each monitor runs in its own daemon thread:
    - `app_monitor_thread`: loops every `app_sample_interval` seconds
    - `terminal_monitor_thread`: event-driven via `watchdog` (no polling)
    - `system_monitor_thread`: loops every `system_sample_interval` seconds
    - `net_sentinel_thread`: loops every `scan_interval +/- jitter` seconds
    - `mdns_listener_thread`: continuous passive listener
    - `ssdp_listener_thread`: continuous passive listener
  - All threads are set as daemon threads (`thread.daemon = True`) so they auto-terminate with the main process
  - Thread error handling: if a monitor thread crashes, log the error and restart it after 30 seconds (self-healing)

- [ ] **5.3 Scheduler integration**
  - Use `schedule` library:
    ```python
    schedule.every().day.at(config.general.report_time).do(trigger_daily_report)
    schedule.every().sunday.at("03:00").do(trigger_weekly_cleanup)
    ```
  - `trigger_daily_report()`: calls `report_builder.build_daily_report()` then `email_dispatcher.send_report()`
  - `trigger_weekly_cleanup()`: calls `cleanup.purge_old_data()` then `cleanup.vacuum_database()`

- [ ] **5.4 Stealth utilities (`radar/utils/stealth.py`)**
  - **Process name obfuscation (Linux):**
    ```python
    import ctypes
    libc = ctypes.CDLL("libc.so.6")
    libc.prctl(15, config.stealth.process_name.encode(), 0, 0, 0)
    ```
    This changes the process name visible in `ps`, `top`, `htop` to something like `kworker/sys`
  - **Nice priority:** Set process to lowest priority (`os.nice(19)`) so it never competes for CPU
  - **I/O priority (Linux):** Use `ionice` to set idle I/O scheduling class
  - **Logging suppression:** Configure Python `logging` to write to `~/.radar/radar.log` only (never stdout/stderr). Set level to WARNING by default.

- [ ] **5.5 Sleep/wake resilience**
  - Detect sleep/wake events:
    - **Linux:** monitor `systemd-logind` D-Bus signals (`PrepareForSleep`)
    - **Fallback:** compare timestamps -- if `time.time()` jumps by more than 2x the poll interval, a sleep/wake occurred
  - On wake: re-run ARP sweep immediately, resync terminal histories, log the gap as idle time

- [ ] **5.6 systemd service file**
  - Create `deploy/radar.service`:
    ```ini
    [Unit]
    Description=System Worker Thread
    After=network-online.target
    Wants=network-online.target

    [Service]
    Type=simple
    ExecStart=/path/to/.venv/bin/python -m radar.main
    Restart=always
    RestartSec=10
    Nice=19
    IOSchedulingClass=idle
    AmbientCapabilities=CAP_NET_RAW

    [Install]
    WantedBy=multi-user.target
    ```
  - The `Description` is intentionally vague for stealth
  - `CAP_NET_RAW` allows ARP scanning without full root
  - `Restart=always` ensures self-healing on crash

- [ ] **5.7 Full integration smoke test**
  - Run the full daemon for 10 minutes on the actual laptop
  - Verify: SQLite database is populated with real data (apps, commands, metrics, devices)
  - Manually trigger `trigger_daily_report()` and verify email arrives

### Tests (Sprint 5)

| Test File | What It Validates |
|-----------|-------------------|
| `test_main.py` | Mock all monitors; verify initialization sequence; verify scheduler configured; verify graceful shutdown on SIGTERM |
| `test_stealth.py` | Verify process name change (mock `ctypes`); verify nice priority set; verify log file created (not stdout) |
| `test_integration.py` | Start full daemon with mocked monitors for 60 seconds; verify DB has records from all 3 host monitors; trigger report; verify report files generated |

### Definition of Done

```
$ sudo python -m radar.main &
> Daemon starts silently, no output to terminal
> ps aux | grep kworker/sys   # Shows disguised process
> After 5 minutes: ~/.radar/radar.db has real data
> Manual report trigger: email arrives in Gmail
> All Sprint 5 tests pass
```

### Files Created

```
radar/main.py               (full implementation)
radar/utils/stealth.py
deploy/radar.service
tests/test_main.py
tests/test_stealth.py
tests/test_integration.py
```

---

## Sprint 6: Testing, Hardening & Deployment

**Duration:** Week 6 (Days 36-42)
**Goal:** Comprehensive test coverage, performance profiling, edge-case hardening, and production deployment. By end of sprint, Radar is installed as a system service running invisibly 24/7.

### Tasks

- [ ] **6.1 Full test suite execution**
  - Run all unit tests with coverage: `pytest --cov=radar --cov-report=html tests/`
  - Target: 85%+ line coverage across all modules
  - Fix any test gaps discovered

- [ ] **6.2 Performance profiling**
  - Run daemon for 1 hour with `cProfile`:
    ```bash
    python -m cProfile -o perf.prof -m radar.main
    ```
  - Analyze with `snakeviz perf.prof`
  - Verify:
    - Average CPU < 2%
    - Peak CPU < 5% (during ARP scan)
    - RSS memory < 80MB
    - No memory leaks (compare beginning vs end RSS)
  - If any metric is over target: optimize the offending module (likely net_sentinel or report_builder)

- [ ] **6.3 72-hour sustained run test**
  - Deploy and run for 3 full days
  - Monitor with a separate script that logs RSS memory every 5 minutes
  - Check:
    - No crashes
    - No memory growth trend
    - Database size is within expected range (15-45 MB for 3 days)
    - 3 daily reports sent successfully
    - Sleep/wake handled correctly
    - WiFi drop/reconnect handled correctly

- [ ] **6.4 Edge case hardening**
  - Test scenarios from README Section 14.5:
    - [ ] Shell history file deleted mid-run -> monitor recovers, re-detects file
    - [ ] No WiFi available -> host monitoring continues, network section empty
    - [ ] 50+ devices on network -> no crash, report generated within 30 seconds
    - [ ] System clock change -> timestamps remain consistent (use monotonic clock for intervals)
    - [ ] Sleep for 4 hours then wake -> gap detected, monitors resume
    - [ ] Gmail rate-limited -> retry logic works, pending report saved
    - [ ] Database at 500MB -> performance still acceptable, cleanup triggers

- [ ] **6.5 Security hardening**
  - [ ] Verify `.env` file has chmod 600
  - [ ] Verify `~/.radar/` directory has chmod 700
  - [ ] Verify no credentials appear in logs
  - [ ] Verify sensitive commands are redacted in terminal history
  - [ ] Verify TLS is enforced on SMTP connection (no plaintext fallback)

- [ ] **6.6 Production deployment**
  - Install on the actual laptop:
    ```bash
    sudo cp deploy/radar.service /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable radar
    sudo systemctl start radar
    ```
  - Verify start-on-boot: reboot the laptop and confirm daemon restarts
  - Verify stealth: open `htop`, confirm process blends in
  - Verify first real daily report arrives in Gmail on schedule

- [ ] **6.7 Documentation finalization**
  - Update README.md with any changes discovered during implementation
  - Write `INSTALL.md` with step-by-step setup instructions
  - Write `CHANGELOG.md` documenting v1.0
  - Ensure `config.example.yaml` matches actual config schema

### Tests (Sprint 6)

All tests from Sprints 1-5 plus:

| Test File | What It Validates |
|-----------|-------------------|
| `test_edge_cases.py` | History file deletion recovery; no-WiFi mode; 50+ device stress; clock change handling |
| `test_security.py` | No credentials in log output; .env permissions check; TLS enforcement check |
| `test_performance.py` | CPU benchmark under 2%; memory benchmark under 80MB; report generation under 30 seconds |

### Definition of Done (Project Complete)

```
$ sudo systemctl status radar
> Active: active (running)

$ ls ~/.radar/
> radar.db  radar.log  reports/  pending_reports/

$ # Wait for report_time
> Email received in Gmail with:
>   - HTML body: app usage table, terminal commands, network grid, system health
>   - Attachments: host_activity.txt + individual device .txt files

$ pytest --cov=radar tests/
> All tests pass
> Coverage: 85%+

$ htop
> Radar process is invisible (disguised name, <2% CPU, ~40MB RAM)
```

### Files Created

```
tests/test_edge_cases.py
tests/test_security.py
tests/test_performance.py
INSTALL.md
CHANGELOG.md
```

---

## Sprint Summary Timeline

```
Week 1 (Sprint 1)  : [====] Foundation & Data Layer
Week 2 (Sprint 2)  : [====] Host Monitors (App, Terminal, System)
Week 3 (Sprint 3)  : [====] Network Intelligence (ARP, Fingerprinting)
Week 4 (Sprint 4)  : [====] Reporting & Email Delivery
Week 5 (Sprint 5)  : [====] Daemon, Stealth & Full Integration
Week 6 (Sprint 6)  : [====] Testing, Hardening & Production Deploy
```

## Risk Register

| Risk | Impact | Mitigation |
|------|--------|------------|
| `xdotool` not installed on target system | App monitor fails silently | Fallback to `/proc` parsing; document as a prerequisite |
| Gmail blocks SMTP due to "suspicious activity" | Daily reports not delivered | Use App Password (not main password); whitelist in Google security settings |
| scapy ARP scan requires root | Network sentinel fails | Use `CAP_NET_RAW` Linux capability instead of full root; document in INSTALL.md |
| iOS MAC randomization hides real MAC | Same iPhone appears as multiple "new" devices | Correlate via mDNS hostname which remains consistent; deduplicate in classifier |
| Laptop is offline for extended periods | Reports backlog | Queue reports in pending_reports/; send all on reconnection |
| Performance exceeds 2% CPU target | Daemon becomes detectable | Profile and optimize; increase polling intervals; reduce ARP scan frequency |

---

**Document Version:** 1.0
**Created:** April 7, 2026
**Status:** Ready to Begin Sprint 1
