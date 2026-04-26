from datetime import datetime, timedelta
from radar.database.vault import Vault
from radar.config import settings

def purge_old_data(retention_days: int = None):
    """Deletes records older than the configured retention period."""
    if retention_days is None:
        retention_days = settings.general.data_retention_days
        
    cutoff_date = (datetime.now() - timedelta(days=retention_days)).isoformat()
    vault = Vault()
    
    # 1. App Activity
    vault._execute("DELETE FROM app_activity WHERE timestamp < ?", (cutoff_date,))
    
    # 2. Terminal Commands
    vault._execute("DELETE FROM terminal_commands WHERE timestamp < ?", (cutoff_date,))
    
    # 3. System Metrics
    vault._execute("DELETE FROM system_metrics WHERE timestamp < ?", (cutoff_date,))
    
    # 4. Device Sessions
    vault._execute("DELETE FROM device_sessions WHERE session_start < ?", (cutoff_date,))
    
    # 5. Report Log
    # We keep reports a bit longer or follow the same rule
    vault._execute("DELETE FROM report_log WHERE generated_at < ?", (cutoff_date,))

def vacuum_database():
    """Compacts the SQLite database file to reclaim space."""
    vault = Vault()
    vault._execute("VACUUM")
