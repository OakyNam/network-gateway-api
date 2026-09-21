"""Local loopback generic Telnet emulator.

This is an explicitly **generic, simulated** Telnet login shell used only to
exercise `app.dal.device.telnet_client.GenericTelnetNCCClient` end to end. It is
not modeled on, and does not claim compatibility with, any specific vendor
device (a Lucent DDM2200 was mentioned during scoping, but no authentication
details or command syntax were supplied for it, so none are emulated here).
"""

from __future__ import annotations

import socket
import threading
from typing import Optional

ACCEPT_TIMEOUT = 5.0
SESSION_TIMEOUT = 5.0

BANNER = (
    b"Generic Simulated Telnet Login (demo emulator - not real device firmware)\r\n"
)
PROMPT = b"demo-router-telnet> "


class TelnetEmulator:
    """A minimal, real TCP/Telnet-style server bound to 127.0.0.1."""

    def __init__(self, host: str, port: int, username: str, password: str) -> None:
        self.host = host
        self.port = port
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

    def _recv_line(self, sock: socket.socket) -> bytes:
        buf = bytearray()
        while b"\n" not in bytes(buf):
            try:
                chunk = sock.recv(256)
            except socket.timeout:
                break
            if not chunk:
                break
            buf.extend(chunk)
        return bytes(buf).strip(b"\r\n")

    def _handle_connection(self, sock: socket.socket) -> None:
        sock.settimeout(SESSION_TIMEOUT)
        try:
            sock.sendall(BANNER)
            sock.sendall(b"Username: ")
            username = self._recv_line(sock)
            sock.sendall(b"Password: ")
            password = self._recv_line(sock)
            if username.decode("utf-8", "ignore") != self.username or password.decode(
                "utf-8", "ignore"
            ) != self.password:
                sock.sendall(b"Login incorrect\r\n")
                return
            sock.sendall(b"\r\n" + PROMPT)
            self._command_loop(sock)
        except (OSError, socket.timeout):
            pass
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def _command_loop(self, sock: socket.socket) -> None:
        while True:
            command = self._recv_line(sock)
            if not command:
                return
            text = command.decode("utf-8", "ignore").strip()
            if text in ("exit", "quit", "logout"):
                sock.sendall(b"bye\r\n")
                return
            if text.startswith("show interface"):
                sock.sendall(
                    b"[SIMULATED - generic demo emulator, not real device firmware]\r\n"
                    b"interface0: up, simulated counters ok\r\n" + PROMPT
                )
            else:
                sock.sendall(b"% Unknown command (simulated)\r\n" + PROMPT)

    def stop(self) -> None:
        self._stop.set()
        if self._listener is not None:
            try:
                self._listener.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=2)
