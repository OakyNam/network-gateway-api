"""
Proxy client using paramiko for SSH tunneling, with error handling and logging.
"""

import paramiko
from decouple import config
from typing import Optional
from loguru import logger
from app.common.errors import GatewayError

class ProxyClient:
    def __init__(self, proxy_host: str) -> None:
        """
        Initialize a ProxyClient for SSH tunneling.

        Args:
            proxy_host (str): The hostname or IP of the proxy server.
        """
        self.proxy_host: str = proxy_host
        self.proxy_port: int = 22
        self.ssh_client: Optional[paramiko.SSHClient] = None
        logger.info(f"ProxyClient initialized for host: {proxy_host}")

    def connect(self) -> None:
        """
        Establish an SSH connection to the proxy server using credentials from environment variables.
        """
        try:
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            logger.info(f"Connecting to proxy {self.proxy_host}:{self.proxy_port}")
            self.ssh_client.connect(
                hostname=self.proxy_host,
                port=self.proxy_port,
                username=str(config('PROXY_USERNAME')),
                password=str(config('PROXY_PASSWORD'))
            )
            logger.success(f"Connected to proxy {self.proxy_host}:{self.proxy_port}")
        except Exception as e:
            logger.error(f"Failed to connect to proxy {self.proxy_host}: {e}")
            raise GatewayError(f"Proxy connection failed: {e}")

    def get_channel(self, dest_host: str, dest_port: int) -> paramiko.Channel:
        """
        Open a direct-tcpip channel to the destination host/port through the proxy.

        Args:
            dest_host (str): The destination hostname or IP.
            dest_port (int): The destination port.

        Returns:
            paramiko.Channel: The SSH channel for the connection.
        """
        try:
            if self.ssh_client is None:
                self.connect()
            transport = self.ssh_client.get_transport()
            if transport is None:
                logger.error("SSH transport is not available after connection.")
                raise GatewayError("SSH transport is not available.")
            logger.info(f"Opening channel to {dest_host}:{dest_port} via proxy {self.proxy_host}")
            channel = transport.open_channel(
                'direct-tcpip',
                (dest_host, dest_port),
                (self.proxy_host, self.proxy_port)
            )
            logger.success(f"Channel opened to {dest_host}:{dest_port} via proxy {self.proxy_host}")
            return channel
        except Exception as e:
            logger.error(f"Failed to open channel to {dest_host}:{dest_port} via proxy {self.proxy_host}: {e}")
            raise GatewayError(f"Failed to open channel: {e}")

    def close(self) -> None:
        """
        Close the SSH connection to the proxy server.
        """
        if self.ssh_client:
            try:
                self.ssh_client.close()
                logger.info(f"Closed SSH connection to proxy {self.proxy_host}")
            except Exception as e:
                logger.warning(f"Error closing SSH connection to proxy {self.proxy_host}: {e}")
            finally:
                self.ssh_client = None
