"""Local loopback NETCONF-over-SSH emulator.

Speaks the real NETCONF-over-SSH transport (SSH `netconf` subsystem, RFC 6242
end-of-message framing, and a real `<hello>`/`<rpc>`/`<rpc-reply>` exchange)
so `ncclient`'s `manager.connect(...)` and `app.dal.device.nccclient_juniper`
run against a genuine, if minimal, NETCONF server rather than a mocked
Python object. Only `base:1.0` framing/capabilities are advertised; RPC
payloads are canned, clearly-labeled simulated responses.
"""

from __future__ import annotations

import re
import socket
import threading
from typing import Optional

import paramiko
from loguru import logger

EOM = b"]]>]]>"
ACCEPT_TIMEOUT = 5.0
CHANNEL_TIMEOUT = 5.0

SERVER_HELLO = (
    '<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">'
    "<capabilities>"
    "<capability>urn:ietf:params:netconf:base:1.0</capability>"
    "</capabilities>"
    "<session-id>1</session-id>"
    "</hello>"
).encode("utf-8") + EOM

MESSAGE_ID_RE = re.compile(rb'message-id="([^"]*)"')


def _rpc_reply(message_id: str, body: str) -> bytes:
    return (
        f'<rpc-reply message-id="{message_id}" '
        'xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">'
        f"{body}"
        "</rpc-reply>"
    ).encode("utf-8") + EOM


class _NetconfServerInterface(paramiko.ServerInterface):
    def __init__(self, username: str, password: str) -> None:
        super().__init__()
        self._username = username
        self._password = password
        self.subsystem_event = threading.Event()

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

    def check_channel_subsystem_request(self, channel: paramiko.Channel, name: str) -> bool:
        if name != "netconf":
            return False
        self.subsystem_event.set()
        return True


def _read_framed_message(channel: paramiko.Channel, timeout: float) -> Optional[bytes]:
    channel.settimeout(timeout)
    buf = bytearray()
    while EOM not in bytes(buf):
        try:
            chunk = channel.recv(4096)
        except socket.timeout:
            return None
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf).split(EOM, 1)[0]


def _handle_rpc(raw: bytes) -> Optional[bytes]:
    match = MESSAGE_ID_RE.search(raw)
    message_id = match.group(1).decode("utf-8") if match else "0"
    # ncclient emits namespace-prefixed elements (e.g. <nc:get-config>), so we
    # match on the local element name rather than requiring an exact prefix.
    if b"close-session" in raw:
        return _rpc_reply(message_id, "<ok/>")
    if b"get-config" in raw:
        body = (
            "<data><interfaces><interface>"
            "<name>demo0</name><simulated>true</simulated>"
            "</interface></interfaces></data>"
        )
        return _rpc_reply(message_id, body)
    if b"edit-config" in raw:
        return _rpc_reply(message_id, "<ok/>")
    if re.search(rb"[:<]get[ />]", raw):
        body = "<data><simulated-operational-state>demo</simulated-operational-state></data>"
        return _rpc_reply(message_id, body)
    return _rpc_reply(
        message_id,
        '<rpc-error><error-type>application</error-type>'
        '<error-severity>error</error-severity>'
        '<error-message>Unsupported operation in demo NETCONF emulator</error-message>'
        '</rpc-error>',
    )


class NetconfEmulator:
    """A minimal, real NETCONF-over-SSH server bound to 127.0.0.1."""

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
            server = _NetconfServerInterface(self.username, self.password)
            transport.start_server(server=server)
            channel = transport.accept(ACCEPT_TIMEOUT)
            if channel is None:
                return
            if not server.subsystem_event.wait(CHANNEL_TIMEOUT):
                return
            self._netconf_loop(channel)
        except (paramiko.SSHException, OSError, EOFError) as exc:
            logger.debug(f"Demo NETCONF emulator: expected disconnect/negotiation error: {exc}")
        except Exception:
            logger.exception("Demo NETCONF emulator: unexpected error handling a connection")
        finally:
            try:
                transport.close()
            except Exception:
                pass
            try:
                client_sock.close()
            except Exception:
                pass

    def _netconf_loop(self, channel: paramiko.Channel) -> None:
        # Client sends its <hello> first (ncclient behavior); we reply with ours.
        client_hello = _read_framed_message(channel, CHANNEL_TIMEOUT)
        if client_hello is None:
            return
        channel.send(SERVER_HELLO)
        while True:
            raw = _read_framed_message(channel, CHANNEL_TIMEOUT)
            if raw is None:
                return
            reply = _handle_rpc(raw)
            if reply is not None:
                channel.send(reply)
            if b"close-session" in raw:
                return

    def stop(self) -> None:
        self._stop.set()
        if self._listener is not None:
            try:
                self._listener.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=2)
