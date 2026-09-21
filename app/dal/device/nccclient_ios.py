"""IOS NETCONF client implementation."""

from typing import Any, Dict

from app.dal.device.base_client import BaseNCCClient


class IOSNCCClient(BaseNCCClient):
    def __init__(self, host: str, router_info: Dict[str, Any]):
        super().__init__(host, router_info)
        self.port = self._safe_port(router_info.get("netconf_port"), 830)

    def get_show_interface_command(self, interface_name=None) -> str:
        return f"show interface {interface_name}" if interface_name else "show interfaces"
