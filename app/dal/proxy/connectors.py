"""Bounded, explicit socket strategies for read-only connection checks.

SSH trust is never learned automatically. Device and bastion identities are
verified independently, against their own trust stores. No strategy falls back
to a direct connection. Demo traffic is pinned to literal loopback addresses.
"""

from __future__ import annotations

import base64
import io
import ipaddress
import math
import os
import queue
import re
import shlex
import socket
import threading
import time
from pathlib import Path

import paramiko
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa


class ConnectorError(Exception):
    def __init__(self, stage: str, detail: str):
        super().__init__(detail)
        self.stage = stage
        self.detail = detail


class Deadline:
    """One deadline including negotiation, authentication and channel requests."""

    def __init__(self, seconds: float):
        self.end = time.monotonic() + seconds
        self.expired = threading.Event()
        self._lock = threading.Lock()
        self._resources = []
        self._closed = False
        self._timer = threading.Timer(seconds, self._expire)
        self._timer.daemon = True

    def __enter__(self):
        self._timer.start()
        return self

    def remaining(self) -> float:
        remaining = self.end - time.monotonic()
        if remaining <= 0 or self.expired.is_set():
            raise ConnectorError("timeout", "The overall connection-test deadline expired.")
        return remaining

    def own(self, resource):
        with self._lock:
            closed = self._closed
            if not closed:
                self._resources.append(resource)
        if closed:
            resource.close()
            raise ConnectorError("timeout", "The overall connection-test deadline expired.")
        return resource

    def _expire(self):
        self.expired.set()
        self.close()

    def close(self):
        with self._lock:
            self._closed = True
            resources, self._resources = self._resources, []
        # Abort outer transports before sockets/channels: Channel.close() can
        # otherwise wait for a peer's rekey while trying to send an SSH close.
        resources.sort(key=lambda resource: 0 if isinstance(resource, paramiko.SSHClient) else 1)
        for resource in resources:
            try:
                if isinstance(resource, socket.socket):
                    try:
                        resource.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                resource.close()
            except Exception:
                pass

    def __exit__(self, *_):
        self._timer.cancel()
        self.close()
        self._timer.join(timeout=0.25)


PROJECT_ROOT = Path(__file__).resolve().parents[3]
CONNECTOR_TYPES = {"direct", "ssh_tunnel", "ssh_shell", "socks5", "http_connect"}
PROTOCOL_PORTS = {"ssh": 22, "netconf": 830, "telnet": 23}
_DNS_SLOTS = threading.BoundedSemaphore(8)
_HOSTNAME = re.compile(r"(?=.{1,253}\Z)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\Z")
SHELL_PROMPT = re.compile(rb"(?:^|[\r\n])[A-Za-z0-9_@().:/~ -]{0,160}[#$>] ?$")


def _port(value) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ConnectorError("validation", "A TCP port must be an integer from 1 to 65535.")
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise ConnectorError("validation", "A TCP port must be an integer from 1 to 65535.") from None
    if not 1 <= port <= 65535:
        raise ConnectorError("validation", "A TCP port must be an integer from 1 to 65535.")
    return port


def _host(value) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or "%" in value:
        raise ConnectorError("validation", "A host must be an IP address or plain DNS hostname.")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        if not _HOSTNAME.fullmatch(value) or ".." in value:
            raise ConnectorError("validation", "A host must be an IP address or plain DNS hostname.") from None
    return value


def loopback_host(host: str) -> str:
    if host.lower() == "localhost":
        return "127.0.0.1"
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        raise ConnectorError("demo_policy", "Demo connections require literal loopback addresses or localhost.") from None
    if not address.is_loopback:
        raise ConnectorError("demo_policy", "Demo connections require literal loopback addresses or localhost.")
    return str(address)


def _demo_file_policy(auth: dict):
    if auth.get("private_key_path"):
        raise ConnectorError("demo_policy", "Demo mode accepts pasted SSH keys, not private-key file paths.")
    if auth.get("known_hosts_path"):
        try:
            path = Path(os.path.abspath(auth["known_hosts_path"]))
            allowed = [PROJECT_ROOT / "demo" / "data", PROJECT_ROOT / "test" / "fixtures"]
            # Only the trusted demo bootstrap sets this after rejecting inherited
            # configuration and validating its explicit --storage-dir argument.
            configured_root = os.environ.get("GATEWAY_DEMO_STORAGE_DIR")
            if configured_root:
                root = Path(configured_root)
                if not root.is_absolute() or str(root).startswith(("\\\\", "//")):
                    raise ValueError
                allowed.append(Path(os.path.abspath(root)))
            if not any(path.is_relative_to(root) for root in allowed):
                raise ValueError
            path = path.resolve()
            if not any(path.is_relative_to(root.resolve()) for root in allowed):
                raise ValueError
        except (OSError, TypeError, ValueError):
            raise ConnectorError(
                "demo_policy", "Demo trust files must be inside configured local demo storage or test/fixtures."
            ) from None


def _auth_fields(auth: dict, *, required: bool, ssh: bool):
    username = auth.get("username")
    if required and (not isinstance(username, str) or not username):
        raise ConnectorError("validation", "A username is required for this login.")
    for field in ("username", "password", "key_passphrase"):
        value = auth.get(field)
        if value is not None and (not isinstance(value, str) or len(value) > 4096 or
                                  any(ord(ch) < 32 or ord(ch) == 127 for ch in value)):
            raise ConnectorError("validation", "Login fields must be bounded text without control characters.")
    has_key = bool(auth.get("private_key") or auth.get("private_key_path"))
    method = auth.get("authentication_type", "ssh_key" if has_key else "password")
    if method not in {"password", "ssh_key"}:
        raise ConnectorError("unsupported", "The selected authentication method is unsupported.")
    if method == "ssh_key" or has_key:
        if not ssh:
            raise ConnectorError("unsupported", "This login supports passwords only; SSH keys are not applicable.")
        if not has_key or method != "ssh_key" or auth.get("password"):
            raise ConnectorError("validation", "Select exactly one password or SSH-key credential.")
        if auth.get("private_key") and auth.get("private_key_path"):
            raise ConnectorError("validation", "Select pasted key material or a key file, not both.")
    elif required and not auth.get("password"):
        raise ConnectorError("validation", "A password is required for this login.")
    elif not required and bool(username) != bool(auth.get("password")):
        raise ConnectorError("validation", "Proxy username and password must be supplied together.")


def validate_profile(profile: dict, demo_mode: bool) -> tuple[dict, dict, float]:
    if not isinstance(profile, dict):
        raise ConnectorError("validation", "A resolved connection profile is required.")
    device = dict(profile)
    protocol = device.get("protocol")
    if protocol not in PROTOCOL_PORTS:
        raise ConnectorError("unsupported", "The selected device protocol is unsupported.")
    if device.get("proxy_id") and "connector" not in device:
        raise ConnectorError("validation", "The saved proxy reference must be resolved before testing.")
    raw_connector = device.get("connector", {"type": "direct"})
    if not isinstance(raw_connector, dict):
        raise ConnectorError("validation", "A resolved connector object is required.")
    connector = dict(raw_connector)
    kind = connector.get("type")
    if kind not in CONNECTOR_TYPES:
        raise ConnectorError("unsupported", "The selected connector is unsupported.")
    if device.get("proxy_id") and kind == "direct":
        raise ConnectorError("validation", "A saved proxy reference cannot be tested as a direct connection.")
    if kind == "ssh_shell" and protocol != "telnet":
        raise ConnectorError("unsupported", "Interactive SSH shell supports generic Telnet only, not SSH or NETCONF.")
    device["host"] = _host(device.get("host"))
    device["port"] = _port(device.get("port", PROTOCOL_PORTS[protocol]))
    connector["type"] = kind
    if kind != "direct":
        connector["host"] = _host(connector.get("host"))
        connector["port"] = _port(connector.get("port"))
    if isinstance(device.get("timeout_seconds"), bool):
        raise ConnectorError("validation", "The overall timeout must be between 1 and 30 seconds.")
    try:
        seconds = float(device.get("timeout_seconds", 5))
    except (TypeError, ValueError):
        raise ConnectorError("validation", "The overall timeout must be between 1 and 30 seconds.") from None
    if not math.isfinite(seconds) or not 1 <= seconds <= 30:
        raise ConnectorError("validation", "The overall timeout must be between 1 and 30 seconds.")
    if demo_mode:
        device["network_host"] = loopback_host(device["host"])
        if kind != "direct":
            connector["network_host"] = loopback_host(connector["host"])
        _demo_file_policy(device)
        if kind != "direct":
            _demo_file_policy(connector)
    else:
        device["network_host"] = device["host"]
        connector["network_host"] = connector.get("host")
    _auth_fields(device, required=True, ssh=protocol != "telnet")
    if kind != "direct":
        _auth_fields(connector, required=kind.startswith("ssh_"), ssh=kind.startswith("ssh_"))
    if kind == "http_connect" and ":" in (connector.get("username") or ""):
        raise ConnectorError("validation", "HTTP Basic proxy usernames cannot contain a colon.")
    return device, connector, seconds


def _resolve(host: str, port: int, deadline: Deadline):
    try:
        address = ipaddress.ip_address(host)
        family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
        return [(family, socket.SOCK_STREAM, 0, "", (host, port))]
    except ValueError:
        pass
    # OS DNS calls are not cancellable. Bound callers and outstanding resolver
    # threads rather than let a slow system resolver defeat the test deadline.
    if not _DNS_SLOTS.acquire(timeout=deadline.remaining()):
        raise ConnectorError("timeout", "The overall connection-test deadline expired.")
    result = queue.Queue(maxsize=1)

    def lookup():
        try:
            result.put(socket.getaddrinfo(host, port, type=socket.SOCK_STREAM))
        except Exception:
            result.put(None)
        finally:
            _DNS_SLOTS.release()

    threading.Thread(target=lookup, daemon=True, name="gateway-dns").start()
    try:
        addresses = result.get(timeout=deadline.remaining())
    except queue.Empty:
        raise ConnectorError("timeout", "The overall connection-test deadline expired.") from None
    if not addresses:
        raise ConnectorError("connect", "The endpoint hostname could not be resolved.")
    return addresses


def connect_tcp(host: str, port: int, deadline: Deadline, stage: str):
    for family, kind, proto, _, address in _resolve(host, port, deadline):
        sock = deadline.own(socket.socket(family, kind, proto))
        sock.settimeout(deadline.remaining())
        try:
            sock.connect(address)
            return sock
        except (OSError, TimeoutError):
            sock.close()
            deadline.remaining()
    raise ConnectorError(stage, "The TCP endpoint refused or could not establish a connection.")


def send(stream, payload: bytes, deadline: Deadline):
    stream.settimeout(deadline.remaining())
    stream.sendall(payload)


def receive_exact(stream, size: int, deadline: Deadline) -> bytes:
    data = bytearray()
    while len(data) < size:
        stream.settimeout(deadline.remaining())
        chunk = stream.recv(size - len(data))
        if not chunk:
            raise ConnectorError("protocol", "The peer closed before completing the protocol handshake.")
        data.extend(chunk)
    return bytes(data)


def receive_until(stream, marker: bytes, deadline: Deadline, limit: int = 8192) -> bytes:
    data = bytearray()
    while not data.endswith(marker):
        if len(data) >= limit:
            raise ConnectorError("protocol", "The protocol handshake exceeded the allowed response size.")
        data.extend(receive_exact(stream, 1, deadline))
    return bytes(data)


def _private_key(auth: dict):
    text = auth.get("private_key")
    if text is None and auth.get("private_key_path"):
        try:
            with open(auth["private_key_path"], "r", encoding="utf-8") as file:
                text = file.read(65537)
        except (OSError, UnicodeError):
            raise ConnectorError("validation", "The configured SSH key file could not be read.") from None
    if not isinstance(text, str) or len(text) > 65536:
        raise ConnectorError("validation", "The SSH private key is missing or too large.")
    password = (auth.get("key_passphrase") or "").encode("utf-8") or None
    try:
        raw = text.encode("utf-8")
        loader = (serialization.load_ssh_private_key if b"BEGIN OPENSSH PRIVATE KEY" in raw
                  else serialization.load_pem_private_key)
        key = loader(raw, password=password)
        if isinstance(key, rsa.RSAPrivateKey):
            key_type = paramiko.RSAKey
        elif isinstance(key, ec.EllipticCurvePrivateKey) and isinstance(
                key.curve, (ec.SECP256R1, ec.SECP384R1, ec.SECP521R1)):
            key_type = paramiko.ECDSAKey
        elif isinstance(key, ed25519.Ed25519PrivateKey):
            key_type = paramiko.Ed25519Key
        else:
            raise ValueError
        # Normalize PKCS8, traditional PEM and OpenSSH entirely in memory.
        # Paramiko's text loaders alone do not accept every valid PEM format.
        normalized = key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
            serialization.NoEncryption(),
        ).decode("ascii")
        return key_type.from_private_key(io.StringIO(normalized))
    except (ValueError, TypeError, UnsupportedAlgorithm, paramiko.SSHException):
        raise ConnectorError("validation", "The SSH private key or key passphrase is invalid or unsupported.") from None


class _StrictHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    def missing_host_key(self, client, hostname, key):
        raise ConnectorError("host_key", "The SSH host key is not present in the selected trust store.")


class _SingleAuth:
    """Paramiko auth_strategy: exactly one method, never interactive fallback."""

    def __init__(self, auth):
        self.username = auth["username"]
        self.key = _private_key(auth) if auth.get("private_key") or auth.get("private_key_path") else None
        self.password = auth.get("password")

    def authenticate(self, transport):
        if self.key is not None:
            transport.auth_publickey(self.username, self.key)
        else:
            transport.auth_password(self.username, self.password, fallback=False)
        if not transport.is_authenticated():
            raise paramiko.AuthenticationException("Additional authentication methods are unsupported.")


def connect_ssh(auth: dict, stream, deadline: Deadline, demo_mode: bool, role: str):
    client = deadline.own(paramiko.SSHClient())
    try:
        if auth.get("known_hosts_path"):
            client.load_host_keys(auth["known_hosts_path"])
        elif demo_mode:
            raise ConnectorError(f"{role}_host_key", "Demo SSH logins require an explicit trusted known_hosts file.")
        else:
            client.load_system_host_keys()
        client.set_missing_host_key_policy(_StrictHostKeyPolicy())
        strategy = _SingleAuth(auth)
        remaining = deadline.remaining()
        client.connect(
            hostname=auth["host"], port=auth["port"], username=auth["username"],
            sock=stream, allow_agent=False, look_for_keys=False,
            timeout=remaining, banner_timeout=remaining, auth_timeout=remaining,
            channel_timeout=remaining, auth_strategy=strategy,
        )
        deadline.remaining()
        return client
    except ConnectorError as exc:
        if exc.stage == "host_key":
            raise ConnectorError(f"{role}_host_key", exc.detail) from None
        raise
    except paramiko.BadHostKeyException:
        raise ConnectorError(f"{role}_host_key", "The SSH host key does not match the selected trust store.") from None
    except paramiko.AuthenticationException:
        raise ConnectorError(f"{role}_auth", "SSH authentication was rejected.") from None
    except (OSError, UnicodeError):
        deadline.remaining()
        raise ConnectorError(f"{role}_connect", "The SSH connection or selected trust file could not be opened.") from None
    except (paramiko.SSHException, EOFError, ValueError):
        deadline.remaining()
        raise ConnectorError(f"{role}_connect", "The SSH handshake could not be completed.") from None


def _socks5(stream, connector, device, deadline):
    username = connector.get("username")
    method = 2 if username else 0
    send(stream, bytes([5, 1, method]), deadline)
    greeting = receive_exact(stream, 2, deadline)
    if greeting != bytes([5, method]):
        raise ConnectorError("proxy_auth", "The SOCKS5 proxy rejected the selected authentication method.")
    if username:
        user, password = username.encode("utf-8"), connector["password"].encode("utf-8")
        if len(user) > 255 or len(password) > 255:
            raise ConnectorError("validation", "SOCKS5 credentials cannot exceed 255 encoded bytes.")
        send(stream, bytes([1, len(user)]) + user + bytes([len(password)]) + password, deadline)
        if receive_exact(stream, 2, deadline) != b"\x01\x00":
            raise ConnectorError("proxy_auth", "SOCKS5 proxy authentication was rejected.")
    host = device["network_host"]
    try:
        address = ipaddress.ip_address(host)
        encoded = bytes([1 if address.version == 4 else 4]) + address.packed
    except ValueError:
        encoded_host = host.encode("ascii")
        encoded = bytes([3, len(encoded_host)]) + encoded_host
    send(stream, b"\x05\x01\x00" + encoded + device["port"].to_bytes(2, "big"), deadline)
    reply = receive_exact(stream, 4, deadline)
    if reply[0] != 5 or reply[2] != 0 or reply[3] not in (1, 3, 4):
        raise ConnectorError("protocol", "The SOCKS5 proxy returned an invalid response.")
    if reply[1] != 0:
        raise ConnectorError("proxy_connect", "The SOCKS5 proxy denied or could not reach the destination.")
    length = {1: 4, 4: 16}.get(reply[3])
    if length is None:
        length = receive_exact(stream, 1, deadline)[0]
        if not length:
            raise ConnectorError("protocol", "The SOCKS5 proxy returned an invalid bound address.")
    receive_exact(stream, length + 2, deadline)


def _http_connect(stream, connector, device, deadline):
    host = device["network_host"]
    authority = f"[{host}]:{device['port']}" if ":" in host else f"{host}:{device['port']}"
    request = f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n"
    if connector.get("username"):
        raw = f"{connector['username']}:{connector['password']}".encode("utf-8")
        request += "Proxy-Authorization: Basic " + base64.b64encode(raw).decode("ascii") + "\r\n"
    send(stream, (request + "\r\n").encode("ascii"), deadline)
    response = receive_until(stream, b"\r\n\r\n", deadline)
    lines = response[:-4].split(b"\r\n")
    status = re.fullmatch(rb"HTTP/1\.[01] ([0-9]{3})(?: [\x20-\x7e]*)?", lines[0])
    if not status or any(not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+: ?[\x20-\x7e\t]*", line)
                         for line in lines[1:]):
        raise ConnectorError("protocol", "The HTTP proxy returned an invalid CONNECT response.")
    code = int(status[1])
    if code == 407:
        raise ConnectorError("proxy_auth", "HTTP CONNECT proxy authentication was rejected.")
    if not 200 <= code < 300:
        raise ConnectorError("proxy_connect", "The HTTP CONNECT proxy denied or could not reach the destination.")


def read_prompt(stream, pattern, deadline: Deadline, *, negotiator=None) -> bytes:
    data = bytearray()
    wire_size = 0
    while True:
        stream.settimeout(deadline.remaining())
        chunk = stream.recv(1024)
        if not chunk:
            raise ConnectorError("protocol", "The peer closed before the expected login prompt.")
        wire_size += len(chunk)
        if wire_size > 16384:
            raise ConnectorError("protocol", "The login prompt exceeded the allowed response size.")
        data.extend(negotiator.feed(chunk) if negotiator else chunk)
        if re.search(rb"(?i)(login incorrect|authentication failed|access denied|connection refused|connection closed)", data):
            raise ConnectorError("device_auth", "The remote login was rejected or the remote connection closed.")
        if pattern.search(data):
            return bytes(data)


def open_stream(device: dict, connector: dict, deadline: Deadline, demo_mode: bool):
    kind = connector["type"]
    if kind == "direct":
        return connect_tcp(device["network_host"], device["port"], deadline, "device_connect")
    stream = connect_tcp(connector["network_host"], connector["port"], deadline, "proxy_connect")
    if kind == "socks5":
        _socks5(stream, connector, device, deadline)
    elif kind == "http_connect":
        _http_connect(stream, connector, device, deadline)
    else:
        client = connect_ssh(connector, stream, deadline, demo_mode, "proxy")
        transport = client.get_transport()
        try:
            if kind == "ssh_tunnel":
                stream = deadline.own(transport.open_channel(
                    "direct-tcpip", (device["network_host"], device["port"]),
                    ("127.0.0.1", 0), timeout=deadline.remaining(),
                ))
            else:
                stream = deadline.own(transport.open_session(timeout=deadline.remaining()))
                stream.settimeout(deadline.remaining())
                stream.get_pty(term="dumb", width=160, height=24)
                stream.invoke_shell()
                read_prompt(stream, SHELL_PROMPT, deadline)
                command = f"telnet {shlex.quote(device['network_host'])} {device['port']}\n"
                send(stream, command.encode("ascii"), deadline)
        except (paramiko.SSHException, EOFError, OSError):
            deadline.remaining()
            raise ConnectorError("proxy_connect", "The bastion denied or could not establish the requested channel.") from None
    deadline.remaining()
    return stream
