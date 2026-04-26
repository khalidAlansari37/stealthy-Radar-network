import pytest
from datetime import datetime, timedelta
from radar.database.vault import Vault
from radar.database.models import AppActivityRecord
from radar.database.cleanup import purge_old_data, vacuum_database

@pytest.fixture
def vault(tmp_path, monkeypatch):
    """Fixture to provide a clean Vault pointing to a temporary DB."""
    monkeypatch.setattr("os.path.expanduser", lambda x: str(tmp_path / x[2:]) if x.startswith("~/") else x)
    Vault._instance = None
    return Vault()

def test_purge_old_data(vault):
    # Insert an old record (60 days ago)
    old_time = datetime.now() - timedelta(days=60)
    old_record = AppActivityRecord(
        timestamp=old_time,
        app_name="OldApp",
        window_title="OldWindow",
        process_name="old",
        process_pid=1
    )
    vault.insert_app_activity(old_record)
    
    # Insert a new record
    new_record = AppActivityRecord(
        app_name="NewApp",
        window_title="NewWindow",
        process_name="new",
        process_pid=2
    )
    vault.insert_app_activity(new_record)
    
    # Verify both exist
    cursor = vault.conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM app_activity")
    assert cursor.fetchone()[0] == 2
    
    # Purge data older than 30 days
    purge_old_data(retention_days=30)
    
    # Verify only new record remains
    cursor.execute("SELECT COUNT(*) FROM app_activity")
    assert cursor.fetchone()[0] == 1
    
    cursor.execute("SELECT app_name FROM app_activity")
    assert cursor.fetchone()[0] == "NewApp"

def test_vacuum_database(vault):
    # Just verify it doesn't crash
    vacuum_database()
