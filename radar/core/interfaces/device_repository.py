from abc import ABC, abstractmethod
from typing import List, Optional
from radar.core.entities.device import Device

class DeviceRepository(ABC):
    @abstractmethod
    def get_all(self) -> List[Device]:
        pass

    @abstractmethod
    def get_by_mac(self, mac: str) -> Optional[Device]:
        pass

    @abstractmethod
    def upsert(self, device: Device):
        pass

    @abstractmethod
    def get_dns_history(self, ip: str, limit: int = 500) -> List[dict]:
        pass

    @abstractmethod
    def get_flows(self, ip: str, limit: int = 50) -> List[dict]:
        pass

    @abstractmethod
    def get_system_metrics(self, date_str: str) -> List[dict]:
        pass

    @abstractmethod
    def get_app_activity(self, date_str: str) -> List[dict]:
        pass
