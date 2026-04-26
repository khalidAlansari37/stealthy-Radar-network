import pytest
import os
import yaml
from radar.config import Settings

def test_default_config():
    settings = Settings()
    assert settings.general.report_time == "23:00"
    assert settings.monitoring.app_sample_interval == 30
    assert settings.network.enable_mdns is True

def test_load_from_yaml(tmp_path):
    config_file = tmp_path / "config.yaml"
    config_data = {
        "general": {"report_time": "12:00", "data_retention_days": 60},
        "monitoring": {"app_sample_interval": 10}
    }
    with open(config_file, "w") as f:
        yaml.dump(config_data, f)
        
    settings = Settings.load(str(config_file))
    assert settings.general.report_time == "12:00"
    assert settings.general.data_retention_days == 60
    assert settings.monitoring.app_sample_interval == 10
    # Check default still exists for unmentioned
    assert settings.network.enable_mdns is True

def test_env_override(monkeypatch):
    monkeypatch.setenv("GENERAL__REPORT_TIME", "09:00")
    monkeypatch.setenv("EMAIL__GMAIL_APP_PASSWORD", "secret")
    
    settings = Settings()
    assert settings.general.report_time == "09:00"
    assert settings.email.gmail_app_password == "secret"
