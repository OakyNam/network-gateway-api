"""Base client abstraction for NETCONF and SSH operations."""

from __future__ import annotations

from abc import ABC
from typing import Any, Dict, Optional

import paramiko
from decouple import config
from loguru import logger
from ncclient import manager

from app.dal.device.credentials import resolve_credentials
from app.common.errors import GatewayError
from app.bl.factories.proxy_factory import ProxyFactory

TRUTHY_VALUES = {"1", "true", "yes", "on"}
DEFAULT_BGP_NAMESPACE = "http://openconfig.net/yang/bgp"


class BaseNCCClient(ABC):
    def __init__(self, host: str, router_info: Dict[str, Any]) -> None:
        self.host = host
        self.router_info = router_info
        self.port = self._safe_port(router_info.get("netconf_port"), 830)
        self.ssh_port = self._safe_port(router_info.get("ssh_port"), 22)
        self.session = None
        self.ssh_client: Optional[paramiko.SSHClient] = None

    def _get_proxy(self):
        return ProxyFactory.get_proxy(self.router_info)

    def _credentials(self) -> Dict[str, str]:
        return resolve_credentials(self.router_info)

    @staticmethod
    def _safe_port(value: Any, default: int) -> int:
        try:
            return int(value) if value is not None else default
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _netconf_hostkey_verify() -> bool:
        return str(config("ROUTER_NETCONF_HOSTKEY_VERIFY", default="true")).lower() in TRUTHY_VALUES

    @staticmethod
    def _ssh_config_path() -> Optional[str]:
        """Optional OpenSSH-style config file (e.g. to point at a non-default
        UserKnownHostsFile). Does not change hostkey_verify behavior itself."""
        path = str(config("ROUTER_SSH_CONFIG_PATH", default="")).strip()
        return path or None

    @staticmethod
    def _connect_timeout() -> int:
        try:
            return int(config("ROUTER_CONNECT_TIMEOUT", default="10"))
        except (TypeError, ValueError):
            return 10

    def connect(self) -> None:
        if self.session is not None:
            return
        try:
            proxy = self._get_proxy()
            sock = proxy.get_channel(self.host, self.port) if proxy else None
            auth = self._credentials()
            self.session = manager.connect(
                host=self.host,
                port=self.port,
                hostkey_verify=self._netconf_hostkey_verify(),
                allow_agent=False,
                look_for_keys=False,
                sock=sock,
                ssh_config=self._ssh_config_path(),
                timeout=self._connect_timeout(),
                **auth,
            )
        except Exception as exc:
            logger.error(f"NETCONF connect failed for {self.host}: {exc}")
            raise GatewayError(f"NETCONF connect failed: {exc}")

    def close(self) -> None:
        if self.session:
            self.session.close_session()
            self.session = None

    def _connect_ssh(self) -> None:
        if self.ssh_client is not None:
            return
        try:
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.load_system_host_keys()
            known_hosts_path = str(config("ROUTER_KNOWN_HOSTS_PATH", default="")).strip()
            if known_hosts_path:
                self.ssh_client.load_host_keys(known_hosts_path)
            else:
                logger.warning(
                    "ROUTER_KNOWN_HOSTS_PATH is not set; only system known_hosts will be used"
                )
            self.ssh_client.set_missing_host_key_policy(paramiko.RejectPolicy())
            proxy = self._get_proxy()
            sock = proxy.get_channel(self.host, self.ssh_port) if proxy else None
            auth = self._credentials()
            self.ssh_client.connect(
                hostname=self.host,
                port=self.ssh_port,
                sock=sock,
                look_for_keys=False,
                allow_agent=False,
                timeout=self._connect_timeout(),
                auth_timeout=self._connect_timeout(),
                **auth,
            )
        except Exception as exc:
            logger.error(f"SSH connect failed for {self.host}: {exc}")
            raise GatewayError(f"SSH connect failed: {exc}")

    def close_ssh(self) -> None:
        if self.ssh_client:
            self.ssh_client.close()
            self.ssh_client = None

    def cleanup(self) -> None:
        self.close()
        self.close_ssh()

    def execute_ssh_command(self, command: str) -> str:
        self._connect_ssh()
        if self.ssh_client is None:
            raise GatewayError("SSH session is not available")
        transport = self.ssh_client.get_transport()
        if transport is None or not transport.is_active():
            raise GatewayError("SSH transport is not active")
        _, stdout, stderr = self.ssh_client.exec_command(command, timeout=self._connect_timeout())
        output = stdout.read().decode("utf-8", errors="ignore")
        err = stderr.read().decode("utf-8", errors="ignore")
        if err.strip():
            logger.warning(f"SSH stderr for {self.host}: {err.strip()}")
        return output

    def get_config(self) -> str:
        self.connect()
        if self.session is None:
            raise GatewayError("NETCONF session is not available")
        reply = self.session.get_config(source="running")
        return str(reply.xml)

    def set_config(self, config_data: str) -> Dict[str, str]:
        self.connect()
        if self.session is None:
            raise GatewayError("NETCONF session is not available")
        reply = self.session.edit_config(target="running", config=config_data)
        return {"status": "ok", "reply": str(reply.xml)}

    def get_operational_state(self) -> str:
        self.connect()
        if self.session is None:
            raise GatewayError("NETCONF session is not available")
        reply = self.session.get()
        return str(reply.xml)

    def get_show_interface_command(self, interface_name: Optional[str] = None) -> str:
        return f"show interface {interface_name}" if interface_name else "show interfaces"

    def show_interface(self, interface_name: Optional[str] = None) -> Dict[str, str]:
        command = self.get_show_interface_command(interface_name)
        output = self.execute_ssh_command(command)
        return {"command": command, "output": output}

    def configure_interface(self, interface_name: str, config_xml: str) -> Dict[str, str]:
        logger.info(f"Applying interface configuration for {interface_name} on {self.host}")
        return self.set_config(config_xml)

    def get_bgp(self) -> str:
        self.connect()
        if self.session is None:
            raise GatewayError("NETCONF session is not available")
        bgp_ns = str(self.router_info.get("bgp_namespace", DEFAULT_BGP_NAMESPACE))
        filter_xml = f"<bgp xmlns='{bgp_ns}'/>"
        reply = self.session.get(filter=("subtree", filter_xml))
        return str(reply.xml)

    def set_bgp(self, config_xml: str) -> Dict[str, str]:
        return self.set_config(config_xml)

    def configure_firewall(self, config_xml: str) -> Dict[str, str]:
        return self.set_config(config_xml)
