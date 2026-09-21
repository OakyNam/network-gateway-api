"""Real loopback-only protocol peers for connector acceptance tests.

These are deliberately small, generic simulators, not firmware emulators.
Every requested destination is checked before DNS/connect. They never execute
shell commands: the bastion interprets only a bounded `telnet HOST PORT` line.
All listeners, accepted streams and workers have explicit stop/close ownership.
"""

from __future__ import annotations

import base64
import ipaddress
import re
import select
import shlex
import socket
import threading
import time

import paramiko


def _loopback(host):
    if host.lower() == "localhost":
        return "127.0.0.1"
    address = ipaddress.ip_address(host)
    if not address.is_loopback:
        raise ValueError("Only loopback is allowed.")
    return str(address)


def _exact(stream, size):
    data = bytearray()
    while len(data) < size:
        chunk = stream.recv(size - len(data))
        if not chunk:
            raise EOFError
        data.extend(chunk)
    return bytes(data)


def _until(stream, marker, limit=8192):
    data = bytearray()
    while not data.endswith(marker):
        if len(data) >= limit:
            raise ValueError("Oversized emulator request.")
        data.extend(_exact(stream, 1))
    return bytes(data)


class LoopbackPeer:
    def __init__(self, *, port=0, stall=False):
        if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535:
            raise ValueError("The emulator port must be an integer from 0 to 65535.")
        self.host = "127.0.0.1"
        self.port = port
        self.stall = stall
        self.events = []
        self._stop = threading.Event()
        self._resources = set()
        self._workers = []
        self._lock = threading.Lock()
        self._listener = None
        self._thread = None

    def own(self, resource):
        with self._lock:
            if self._stop.is_set():
                resource.close()
                raise EOFError
            self._resources.add(resource)
        return resource

    def start(self):
        if self._listener is not None:
            raise RuntimeError("This emulator instance has already been started.")
        self._listener = self.own(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        try:
            self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._listener.bind((self.host, self.port))
            self.port = self._listener.getsockname()[1]
            self._listener.listen(16)
            self._listener.settimeout(0.1)
        except OSError:
            self._listener.close()
            with self._lock:
                self._resources.discard(self._listener)
            self._listener = None
            raise
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        return self

    def _serve(self):
        while not self._stop.is_set():
            try:
                stream, _ = self._listener.accept()
                self.own(stream)
                stream.settimeout(2)
                worker = threading.Thread(target=self._run, args=(stream,), daemon=True)
                self._workers.append(worker)
                worker.start()
            except socket.timeout:
                continue
            except (OSError, EOFError):
                break

    def _run(self, stream):
        self.events.append("accepted")
        try:
            if self.stall:
                self._stop.wait(5)
            else:
                self.handle(stream)
        except (OSError, EOFError, ValueError, paramiko.SSHException):
            pass
        finally:
            stream.close()
            with self._lock:
                self._resources.discard(stream)

    def destination(self, host, port):
        host = _loopback(host)
        if not 1 <= int(port) <= 65535:
            raise ValueError("Invalid port.")
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        stream = self.own(socket.socket(family, socket.SOCK_STREAM))
        stream.settimeout(1)
        stream.connect((host, int(port)))
        self.events.append("destination_connected")
        return stream

    def relay(self, left, right):
        try:
            while not self._stop.is_set():
                ready, _, _ = select.select([left, right], [], [], 0.1)
                for source in ready:
                    payload = source.recv(32768)
                    if not payload:
                        return
                    (right if source is left else left).sendall(payload)
        finally:
            right.close()
            with self._lock:
                self._resources.discard(right)

    def stop(self):
        self._stop.set()
        with self._lock:
            resources = tuple(self._resources)
        for resource in resources:
            try:
                resource.close()
            except (OSError, EOFError, paramiko.SSHException):
                pass
        end = time.monotonic() + 3
        for worker in [self._thread] + self._workers:
            if worker:
                worker.join(timeout=max(0, end - time.monotonic()))
        with self._lock:
            self._resources.clear()

    @property
    def workers_alive(self):
        return sum(worker.is_alive() for worker in self._workers)

    def __enter__(self):
        return self.start()

    def __exit__(self, *_):
        self.stop()


class Socks5Peer(LoopbackPeer):
    def __init__(self, *, username=None, password=None, deny=False, malformed=False, **kwargs):
        super().__init__(**kwargs)
        self.username, self.password = username, password
        self.deny, self.malformed = deny, malformed

    def handle(self, stream):
        version, count = _exact(stream, 2)
        methods = _exact(stream, count)
        method = 2 if self.username else 0
        if version != 5 or method not in methods:
            stream.sendall(b"\x05\xff")
            return
        stream.sendall(bytes([5, method]))
        if method == 2:
            version, size = _exact(stream, 2)
            username = _exact(stream, size).decode("utf-8")
            password = _exact(stream, _exact(stream, 1)[0]).decode("utf-8")
            if version != 1 or username != self.username or password != self.password:
                self.events.append("auth_rejected")
                stream.sendall(b"\x01\x01")
                return
            stream.sendall(b"\x01\x00")
        version, command, reserved, kind = _exact(stream, 4)
        if kind == 1:
            host = str(ipaddress.ip_address(_exact(stream, 4)))
        elif kind == 4:
            host = str(ipaddress.ip_address(_exact(stream, 16)))
        elif kind == 3:
            host = _exact(stream, _exact(stream, 1)[0]).decode("ascii")
        else:
            return
        port = int.from_bytes(_exact(stream, 2), "big")
        if self.malformed:
            stream.sendall(b"\x04\x00\x00\x01" + b"\x00" * 6)
            return
        if self.deny or (version, command, reserved) != (5, 1, 0):
            stream.sendall(b"\x05\x02\x00\x01" + b"\x00" * 6)
            return
        try:
            target = self.destination(host, port)
        except (ValueError, OSError):
            stream.sendall(b"\x05\x04\x00\x01" + b"\x00" * 6)
            return
        stream.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
        self.relay(stream, target)


class HttpConnectPeer(LoopbackPeer):
    def __init__(self, *, username=None, password=None, deny=False, malformed=False, **kwargs):
        super().__init__(**kwargs)
        self.username, self.password = username, password
        self.deny, self.malformed = deny, malformed

    def handle(self, stream):
        request = _until(stream, b"\r\n\r\n").decode("ascii")
        lines = request.split("\r\n")
        match = re.fullmatch(r"CONNECT (\[[0-9a-fA-F:]+\]|[A-Za-z0-9.-]+):([0-9]+) HTTP/1.1", lines[0])
        if not match:
            stream.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            return
        headers = dict(line.split(": ", 1) for line in lines[1:] if line)
        if self.username:
            expected = "Basic " + base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
            if headers.get("Proxy-Authorization") != expected:
                self.events.append("auth_rejected")
                stream.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                return
        if self.malformed:
            stream.sendall(b"HTTP/1.1 200junk\r\n\r\n")
            return
        if self.deny:
            stream.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            return
        try:
            target = self.destination(match[1].strip("[]"), int(match[2]))
        except (ValueError, OSError):
            stream.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            return
        stream.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        self.relay(stream, target)


class _SSHInterface(paramiko.ServerInterface):
    def __init__(self, peer):
        self.peer = peer
        self.destinations = {}
        self.request = threading.Event()
        self.mode = None

    def get_allowed_auths(self, username):
        if self.peer.interactive_only:
            return "keyboard-interactive"
        return "publickey,password"

    def check_auth_password(self, username, password):
        self.peer._stop.wait(self.peer.auth_delay)
        if self.peer.interactive_only:
            return paramiko.AUTH_FAILED
        if self.peer.password is not None and username == self.peer.username and password == self.peer.password:
            if self.peer.partial_auth:
                return paramiko.AUTH_PARTIALLY_SUCCESSFUL
            self.peer.events.append("password_authenticated")
            return paramiko.AUTH_SUCCESSFUL
        self.peer.events.append("auth_rejected")
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        if username == self.peer.username and self.peer.allowed_key is not None and key == self.peer.allowed_key:
            if self.peer.partial_auth:
                return paramiko.AUTH_PARTIALLY_SUCCESSFUL
            self.peer.events.append("key_authenticated")
            return paramiko.AUTH_SUCCESSFUL
        self.peer.events.append("auth_rejected")
        return paramiko.AUTH_FAILED

    def check_auth_interactive(self, username, submethods):
        self.peer.events.append("unexpected_interactive_auth")
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_direct_tcpip_request(self, chanid, origin, destination):
        if not self.peer.bastion or self.peer.deny:
            return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        try:
            _loopback(destination[0])
        except ValueError:
            return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        self.destinations[chanid] = destination
        return paramiko.OPEN_SUCCEEDED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return self.peer.bastion and not self.peer.deny

    def check_channel_shell_request(self, channel):
        if not self.peer.bastion or self.peer.deny:
            return False
        self.mode = "shell"
        self.request.set()
        return True

    def check_channel_subsystem_request(self, channel, name):
        if self.peer.bastion or name != "netconf" or self.peer.deny:
            return False
        self.mode = "netconf"
        self.request.set()
        return True

    def check_channel_exec_request(self, channel, command):
        self.peer.events.append("unexpected_exec")
        return False


class SSHPeer(LoopbackPeer):
    """Real SSH bastion or key/password-authenticated SSH/NETCONF device."""

    def __init__(self, host_key, *, username="device", password="device-password",
                 allowed_key=None, bastion=False, deny=False, bad_hello=False,
                 stall_prompt=False, stall_hello=False, hello=None,
                 auth_delay=0, partial_auth=False, interactive_only=False, **kwargs):
        super().__init__(**kwargs)
        self.host_key = host_key
        self.username, self.password = username, password
        self.allowed_key = allowed_key
        self.bastion, self.deny, self.bad_hello = bastion, deny, bad_hello
        self.stall_prompt, self.stall_hello = stall_prompt, stall_hello
        self.hello = hello
        self.auth_delay = auth_delay
        self.partial_auth = partial_auth
        self.interactive_only = interactive_only

    def handle(self, stream):
        transport = self.own(paramiko.Transport(stream))
        transport.banner_timeout = 1
        transport.handshake_timeout = 2
        server = _SSHInterface(self)
        try:
            transport.add_server_key(self.host_key)
            transport.start_server(server=server)
            while transport.is_active() and not self._stop.is_set():
                channel = transport.accept(0.1)
                if channel is None:
                    continue
                self.own(channel)
                channel.settimeout(2)
                if channel.get_id() in server.destinations:
                    target = self.destination(*server.destinations[channel.get_id()])
                    self.relay(channel, target)
                    return
                if not server.request.wait(2):
                    return
                if server.mode == "shell":
                    self._shell(channel)
                elif server.mode == "netconf":
                    self._netconf(channel)
                return
        finally:
            transport.close()
            with self._lock:
                self._resources.discard(transport)

    def _shell(self, channel):
        if self.stall_prompt:
            self._stop.wait(5)
            return
        channel.sendall(b"Generic simulated bastion\r\nbastion$ ")
        command = shlex.split(_until(channel, b"\n", 1024).decode("ascii").strip())
        if len(command) != 3 or command[0] != "telnet":
            self.events.append("unexpected_shell_command")
            return
        self.events.append("telnet_command")
        try:
            target = self.destination(command[1], int(command[2]))
        except (OSError, ValueError):
            channel.sendall(b"Connection refused\r\nbastion$ ")
            return
        self.relay(channel, target)

    def _netconf(self, channel):
        hello = _until(channel, b"]]>]]>", 65536)
        self.events.append("client_hello" if b"<hello" in hello else "unexpected_rpc")
        if self.stall_hello:
            self._stop.wait(5)
            return
        if self.hello is not None:
            channel.sendall(self.hello)
        elif self.bad_hello:
            channel.sendall(b"<not-hello/>]]>]]>")
        else:
            channel.sendall(
                b'<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">'
                b"<capabilities><capability>urn:ietf:params:netconf:base:1.0"
                b"</capability></capabilities><session-id>42</session-id></hello>]]>]]>"
            )
        while not self._stop.is_set():
            payload = channel.recv(1024)
            if not payload:
                return
            self.events.append("unexpected_rpc")


class TelnetPeer(LoopbackPeer):
    def __init__(self, *, username="device", password="device-password",
                 bad_prompt=False, fragmented_negotiation=False, **kwargs):
        super().__init__(**kwargs)
        self.username, self.password = username, password
        self.bad_prompt = bad_prompt
        self.fragmented_negotiation = fragmented_negotiation

    def handle(self, stream):
        if self.fragmented_negotiation:
            stream.sendall(b"\xff")
            time.sleep(0.02)
            stream.sendall(b"\xfb\x01")
            if _exact(stream, 3) != b"\xff\xfe\x01":
                return
            self.events.append("telnet_negotiated")
        stream.sendall(b"Generic simulated Telnet\r\nUsername: ")
        username = _until(stream, b"\n", 4096).strip(b"\r\n").decode("utf-8")
        stream.sendall(b"Password: ")
        password = _until(stream, b"\n", 4096).strip(b"\r\n").decode("utf-8")
        if username != self.username or password != self.password:
            self.events.append("auth_rejected")
            stream.sendall(b"Login incorrect\r\n")
            return
        self.events.append("password_authenticated")
        stream.sendall(b"\r\nnot a prompt\r\n" if self.bad_prompt else b"\r\ndevice> ")
        if self.bad_prompt:
            self._stop.wait(5)
        else:
            payload = stream.recv(1024)
            if payload:
                self.events.append("unexpected_command")
