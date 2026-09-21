"""Adva NETCONF client implementation."""

from typing import Any, Dict

from app.dal.device.base_client import BaseNCCClient


class AdvaFSP114ProNCCClient(BaseNCCClient):
    def __init__(self, host: str, router_info: Dict[str, Any]):
        super().__init__(host, router_info)
        self.port = self._safe_port(router_info.get("netconf_port"), 830)
