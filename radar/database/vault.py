import sqlite3
import threading
import os
from typing import List, Optional
from datetime import datetime
from pathlib import Path
from radar.config import settings
from radar.database.models import (
    AppActivityRecord, TerminalCommandRecord, NetworkDeviceRecord,
    DeviceSessionRecord, SystemMetricRecord, ReportLogRecord
)
from radar.database.migrations import create_tables
from radar.utils.helpers import get_radar_data_dir

class Vault:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(Vault, cls).__new__(cls)
                cls._instance._init_db()
            return cls._instance

    def _init_db(self):
        # Use centralized data directory (env var aware)
        data_dir = get_radar_data_dir()
        self.db_path = data_dir / "radar.db"
        
        self.conn = sqlite3.connect(
            str(self.db_path),
            check_same_thread=False,
            isolation_level=None  # Handle transactions manually or via PRAGMA
        )
        self.conn.row_factory = sqlite3.Row
        
        # Enable WAL mode for high-concurrency background performance
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        
        # Ensure schema is up to date
        create_tables(self.conn)

    def _execute(self, query: str, params: tuple = ()):
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(query, params)
            self.conn.commit()
            return cursor

    # --- App Activity ---
    def insert_app_activity(self, record: AppActivityRecord):
        query = """
        INSERT INTO app_activity (timestamp, app_name, window_title, process_name, process_pid, is_idle, duration_seconds)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """
        self._execute(query, (
            record.timestamp.isoformat(),
            record.app_name,
            record.window_title,
            record.process_name,
            record.process_pid,
            int(record.is_idle),
            record.duration_seconds
        ))

    def get_app_activity(self, date: str) -> List[AppActivityRecord]:
        query = "SELECT * FROM app_activity WHERE DATE(timestamp) = ?"
        cursor = self.conn.cursor()
        cursor.execute(query, (date,))
        return [AppActivityRecord.from_row(dict(row)) for row in cursor.fetchall()]

    # --- Terminal Commands ---
    def insert_terminal_command(self, record: TerminalCommandRecord):
        query = """
        INSERT INTO terminal_commands (timestamp, shell, command, working_dir)
        VALUES (?, ?, ?, ?)
        """
        self._execute(query, (
            record.timestamp.isoformat(),
            record.shell,
            record.command,
            record.working_dir
        ))

    def get_terminal_commands(self, date: str) -> List[TerminalCommandRecord]:
        query = "SELECT * FROM terminal_commands WHERE DATE(timestamp) = ?"
        cursor = self.conn.cursor()
        cursor.execute(query, (date,))
        return [TerminalCommandRecord.from_row(dict(row)) for row in cursor.fetchall()]

    # --- Network Devices ---
    def upsert_network_device(self, record: NetworkDeviceRecord):
        query = """
        INSERT INTO network_devices (
            mac_address, ip_address, device_name, device_type, manufacturer, confidence,
            first_seen, last_seen, mdns_hostname, mdns_services, ssdp_info, last_activity,
            traffic_summary, ttl, netbios_name
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(mac_address) DO UPDATE SET
            ip_address = excluded.ip_address,
            last_seen = excluded.last_seen,
            device_name = COALESCE(excluded.device_name, network_devices.device_name),
            device_type = COALESCE(excluded.device_type, network_devices.device_type),
            manufacturer = COALESCE(excluded.manufacturer, network_devices.manufacturer),
            confidence = MAX(network_devices.confidence, excluded.confidence),
            mdns_hostname = COALESCE(excluded.mdns_hostname, network_devices.mdns_hostname),
            mdns_services = COALESCE(excluded.mdns_services, network_devices.mdns_services),
            ssdp_info = COALESCE(excluded.ssdp_info, network_devices.ssdp_info),
            last_activity = COALESCE(excluded.last_activity, network_devices.last_activity),
            traffic_summary = COALESCE(excluded.traffic_summary, network_devices.traffic_summary),
            ttl = COALESCE(excluded.ttl, network_devices.ttl),
            netbios_name = COALESCE(excluded.netbios_name, network_devices.netbios_name)
        """
        self._execute(query, (
            record.mac_address,
            record.ip_address,
            record.device_name,
            record.device_type,
            record.manufacturer,
            record.confidence,
            record.first_seen.isoformat(),
            record.last_seen.isoformat(),
            record.mdns_hostname,
            record.mdns_services,
            record.ssdp_info,
            record.last_activity,
            record.traffic_summary,
            record.ttl,
            record.netbios_name
        ))

    def get_network_devices(self) -> List[NetworkDeviceRecord]:
        query = "SELECT * FROM network_devices"
        cursor = self.conn.cursor()
        cursor.execute(query)
        return [NetworkDeviceRecord.from_row(dict(row)) for row in cursor.fetchall()]

    # --- Device Sessions ---
    def insert_device_session(self, record: DeviceSessionRecord):
        query = """
        INSERT INTO device_sessions (mac_address, session_start, session_end, traffic_level)
        VALUES (?, ?, ?, ?)
        """
        self._execute(query, (
            record.mac_address,
            record.session_start.isoformat(),
            record.session_end.isoformat() if record.session_end else None,
            record.traffic_level
        ))

    def get_device_sessions(self, date: str) -> List[DeviceSessionRecord]:
        query = "SELECT * FROM device_sessions WHERE DATE(session_start) = ?"
        cursor = self.conn.cursor()
        cursor.execute(query, (date,))
        return [DeviceSessionRecord.from_row(dict(row)) for row in cursor.fetchall()]

    # --- System Metrics ---
    def insert_system_metric(self, record: SystemMetricRecord):
        query = """
        INSERT INTO system_metrics (
            timestamp, cpu_percent, ram_percent, disk_percent, battery_percent,
            battery_charging, net_bytes_sent, net_bytes_recv, wifi_ssid, wifi_signal_dbm
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        self._execute(query, (
            record.timestamp.isoformat(),
            record.cpu_percent,
            record.ram_percent,
            record.disk_percent,
            record.battery_percent,
            int(record.battery_charging),
            record.net_bytes_sent,
            record.net_bytes_recv,
            record.wifi_ssid,
            record.wifi_signal_dbm
        ))

    def get_system_metrics(self, date: str) -> List[SystemMetricRecord]:
        query = "SELECT * FROM system_metrics WHERE DATE(timestamp) = ?"
        cursor = self.conn.cursor()
        cursor.execute(query, (date,))
        return [SystemMetricRecord.from_row(dict(row)) for row in cursor.fetchall()]

    # --- Report Log ---
    def insert_report_log(self, record: ReportLogRecord):
        query = """
        INSERT INTO report_log (report_date, generated_at, sent_at, status, retry_count)
        VALUES (?, ?, ?, ?, ?)
        """
        self._execute(query, (
            record.report_date,
            record.generated_at.isoformat(),
            record.sent_at.isoformat() if record.sent_at else None,
            record.status,
            record.retry_count
        ))

    def get_report_log(self, date: str) -> Optional[ReportLogRecord]:
        query = "SELECT * FROM report_log WHERE report_date = ?"
        cursor = self.conn.cursor()
        cursor.execute(query, (date,))
        row = cursor.fetchone()
        return ReportLogRecord.from_row(dict(row)) if row else None
    # --- Network Flows ---
    def insert_network_flow(self, timestamp: datetime, src_ip: str, dst_ip: str, dst_port: int, protocol: str, service: str = None, bytes: int = 0):
        # Insert the flow record
        query_flow = """
        INSERT INTO network_flows (timestamp, src_ip, dst_ip, dst_port, protocol, service_label, byte_count)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """
        # Update the cumulative bandwidth tracker for the device
        query_bandwidth = """
        UPDATE network_devices 
        SET total_bytes = total_bytes + ? 
        WHERE ip_address = ?
        """
        
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(query_flow, (timestamp.isoformat(), src_ip, dst_ip, dst_port, protocol, service, bytes))
            cursor.execute(query_bandwidth, (bytes, src_ip))
            self.conn.commit()

    def get_device_flows(self, ip: str, limit: int = 50):
        query = "SELECT * FROM network_flows WHERE src_ip = ? ORDER BY timestamp DESC LIMIT ?"
        cursor = self.conn.cursor()
        cursor.execute(query, (ip, limit))
        return [dict(row) for row in cursor.fetchall()]

    def cleanup_old_flows(self, hours: int = 48):
        query = "DELETE FROM network_flows WHERE timestamp < datetime('now', ?)"
        self._execute(query, (f'-{hours} hours',))
