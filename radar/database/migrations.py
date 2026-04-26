import sqlite3

def create_tables(conn: sqlite3.Connection):
    cursor = conn.cursor()
    
    # 1. App Activity
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS app_activity (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME NOT NULL,
        app_name TEXT NOT NULL,
        window_title TEXT,
        process_name TEXT,
        process_pid INTEGER,
        is_idle BOOLEAN DEFAULT 0,
        duration_seconds INTEGER DEFAULT 0
    )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_app_timestamp ON app_activity(timestamp)")

    # 2. Terminal Commands
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS terminal_commands (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME NOT NULL,
        shell TEXT,
        command TEXT NOT NULL,
        working_dir TEXT
    )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_terminal_timestamp ON terminal_commands(timestamp)")

    # 3. Network Devices
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS network_devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        mac_address TEXT UNIQUE NOT NULL,
        ip_address TEXT,
        device_name TEXT,
        device_type TEXT DEFAULT 'Unknown',
        manufacturer TEXT,
        confidence INTEGER DEFAULT 0,
        first_seen DATETIME,
        last_seen DATETIME,
        mdns_hostname TEXT,
        mdns_services TEXT,
        ssdp_info TEXT,
        last_activity TEXT,
        ttl INTEGER,
        netbios_name TEXT
    )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_device_mac ON network_devices(mac_address)")

    # 4. Device Sessions
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS device_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        mac_address TEXT NOT NULL,
        session_start DATETIME NOT NULL,
        session_end DATETIME,
        traffic_level TEXT DEFAULT 'LIGHT',
        FOREIGN KEY (mac_address) REFERENCES network_devices(mac_address)
    )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_session_mac ON device_sessions(mac_address)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_session_start ON device_sessions(session_start)")

    # 5. System Metrics
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS system_metrics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME NOT NULL,
        cpu_percent REAL,
        ram_percent REAL,
        disk_percent REAL,
        battery_percent REAL,
        battery_charging BOOLEAN,
        net_bytes_sent INTEGER,
        net_bytes_recv INTEGER,
        wifi_ssid TEXT,
        wifi_signal_dbm INTEGER
    )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON system_metrics(timestamp)")

    # 6. Report Log
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS report_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        report_date TEXT NOT NULL,
        generated_at DATETIME NOT NULL,
        sent_at DATETIME,
        status TEXT DEFAULT 'PENDING',
        retry_count INTEGER DEFAULT 0
    )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_report_date ON report_log(report_date)")

    # 7. Network Flows (Granular DPI)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS network_flows (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME NOT NULL,
        src_ip TEXT NOT NULL,
        dst_ip TEXT NOT NULL,
        dst_port INTEGER,
        protocol TEXT,
        service_label TEXT,
        byte_count INTEGER DEFAULT 0
    )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_flow_src_ip ON network_flows(src_ip)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_flow_timestamp ON network_flows(timestamp)")

    # 8. Schema Evolution (Add missing columns to existing DBs)
    try:
        cursor.execute("ALTER TABLE network_devices ADD COLUMN last_activity TEXT")
    except sqlite3.OperationalError:
        pass # Already exists

    try:
        cursor.execute("ALTER TABLE network_devices ADD COLUMN traffic_summary TEXT")
    except sqlite3.OperationalError:
        pass # Already exists

    try:
        cursor.execute("ALTER TABLE network_flows ADD COLUMN byte_count INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass # Already exists

    try:
        cursor.execute("ALTER TABLE network_devices ADD COLUMN total_bytes INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass # Already exists

    conn.commit()

if __name__ == "__main__":
    import os
    from radar.utils.helpers import get_radar_data_dir
    data_dir = get_radar_data_dir()
    db_path = data_dir / "radar.db"
    print(f"📡 Migrating database at {db_path}...")
    conn = sqlite3.connect(str(db_path))
    create_tables(conn)
    conn.close()
    print("✅ Migration complete.")
