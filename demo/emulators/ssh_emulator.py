"""Local loopback SSH emulator (plain `exec_command` transport).

Used to exercise `BaseNCCClient.execute_ssh_command` / `show_interface` end to
end via `app.dal.device.nccclient_ios.IOSNCCClient` without any real device.
Responses are canned, clearly-labeled simulated output, not real IOS behavior.
"""

from __future__ import annotations

import socket
import threading
from typing import Optional

import paramiko
from loguru import logger

CONNECT_ACCEPT_TIMEOUT = 5.0
CHANNEL_TIMEOUT = 5.0


class _SSHServerInterface(paramiko.ServerInterface):
    def __init__(self, username: str, password: str) -> None:
        super().__init__()
        self._username = username
        self._password = password
        self.exec_event = threading.Event()
        self.command: Optional[str] = None

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username: str, password: str) -> int:
        if username == self._username and password == self._password:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username: str) -> str:
        return "password"

    def check_channel_exec_request(self, channel: paramiko.Channel, command: bytes) -> bool:
        self.command = command.decode("utf-8", errors="ignore")
        self.exec_event.set()
        return True


def _fake_show_interface_output(command: str) -> str:
    return (
        "[SIMULATED - demo emulator, not a real device]\n"
        f"% ran: {command}\n"
        "GigabitEthernet0/0 is up, line protocol is up\n"
        "  Description: demo-loopback-interface\n"
        "  Internet address is 192.0.2.1/24\n"
        "  5 minute input rate 1000 bits/sec, 1 packets/sec\n"
        "  5 minute output rate 1000 bits/sec, 1 packets/sec\n"
    )


class SSHEmulator:
    """A minimal, real SSH server bound to 127.0.0.1 for demo purposes."""

    def __init__(self, host: str, port: int, host_key: paramiko.PKey, username: str, password: str) -> None:
        self.host = host
        self.port = port
        self.host_key = host_key
        self.username = username
        self.password = password
        self._listener: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    def start(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((self.host, self.port))
            listener.listen(5)
        except OSError:
            # Never leak a bound-but-unusable socket on a failed start
            # (e.g. the port is already occupied by something else).
            listener.close()
            raise
        listener.settimeout(0.5)
        self._listener = listener
        self.port = listener.getsockname()[1]
        self._thread = threading.Thread(target=self._serve_forever, daemon=True)
        self._thread.start()

    def _serve_forever(self) -> None:
        assert self._listener is not None
        while not self._stop.is_set():
            try:
                client_sock, _addr = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle_connection, args=(client_sock,), daemon=True).start()

    def _handle_connection(self, client_sock: socket.socket) -> None:
        transport = paramiko.Transport(client_sock)
        try:
            transport.add_server_key(self.host_key)
            server = _SSHServerInterface(self.username, self.password)
            transport.start_server(server=server)
            channel = transport.accept(CONNECT_ACCEPT_TIMEOUT)
            if channel is None:
                return
            if not server.exec_event.wait(CHANNEL_TIMEOUT):
                return
            output = _fake_show_interface_output(server.command or "")
            channel.send(output.encode("utf-8"))
            channel.send_exit_status(0)
        except (paramiko.SSHException, OSError, EOFError) as exc:
            # Expected outcomes for a demo server: failed auth/negotiation,
            # or the peer disconnecting mid-handshake/mid-transfer.
            logger.debug(f"Demo SSH emulator: expected disconnect/negotiation error: {exc}")
        except Exception:
            # Anything else is a real bug in the emulator - never swallow it
            # silently; log it visibly (without any credential values).
            logger.exception("Demo SSH emulator: unexpected error handling a connection")
        finally:
            try:
                transport.close()
            except Exception:
                pass
            try:
                client_sock.close()
            except Exception:
                pass

    def stop(self) -> None:
        self._stop.set()
        if self._listener is not None:
            try:
                self._listener.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=2)
