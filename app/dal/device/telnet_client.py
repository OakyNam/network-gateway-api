"""Generic Telnet client adapter.

This is a real, reusable gateway adapter (not test-only scaffolding) that
speaks a minimal, generic Telnet login flow. It is intentionally **not**
modeled on any specific vendor firmware. In particular, a Lucent DDM2200
device was mentioned during scoping but no authentication details or command
syntax were supplied for it, so none are invented here or claimed to be
compatible with that hardware. Any device that speaks a plain-text
"Username:"/"Password:" Telnet login followed by a line-based command prompt
can be exercised through this adapter; the bundled demo emulator
(`demo/emulators/telnet_emulator.py`) is a generic simulated login shell used
to demonstrate this adapter end-to-end over localhost.

Telnet option negotiation (RFC 854/855): this client tracks negotiation
state across TCP reads (a WILL/DO request can arrive split across two
`recv()` calls) and explicitly answers every DO/WILL option request from the
peer with a refusal (WONT/DONT respectively) - it does not agree to any
Telnet option. IAC-escaped literal 0xFF bytes are unescaped; subnegotiation
(`IAC SB ... IAC SE`) payloads are discarded unread rather than interpreted,
since this client implements no subnegotiated options.

Every blocking read is bounded by both a wall-clock deadline and a maximum
buffer size; reaching either, or the peer closing the connection before the
expected prompt/marker appears, raises `GatewayError` rather than returning
truncated data as if it were a complete, successful response.

Telnet has no NETCONF equivalent, so structured operations (get/set config,
BGP, firewall) are not supported over this transport and fail explicitly
rather than returning fabricated success.
"""

from __future__ import annotations

import math
import socket
import time
from typing import Any, Dict, Optional

from decouple import config
from loguru import logger

from app.dal.device.credentials import resolve_credentials
from app.common.errors import GatewayError

# Telnet IAC negotiation bytes (RFC 854).
IAC = 0xFF
DONT = 0xFE
DO = 0xFD
WONT = 0xFC
WILL = 0xFB
SB = 0xFA
SE = 0xF0

DEFAULT_MAX_RESPONSE_BYTES = 8192


class _TelnetReadError(GatewayError):
    """Raised by `_recv_until` when the expected marker was not reached
    (EOF, overflow, or deadline) - carries whatever partial, already
    IAC-cleaned bytes were read, so callers can distinguish a real
    application-level signal (e.g. a "Login incorrect" line the peer sent
    right before closing) from a bare protocol/timeout failure, without ever
    treating partial data as a successful response."""

    def __init__(self, message: str, partial: bytes = b"") -> None:
        super().__init__(message)
        self.partial = partial


class _TelnetNegotiator:
    """Stateful RFC 854 IAC handler for a single Telnet connection.

    `feed()` may be called with arbitrarily-sized chunks, including ones
    that split an IAC sequence in half; state persists across calls so a
    negotiation request is never lost or misread as literal text. Every
    DO/WILL option request from the peer is answered immediately with an
    explicit WONT/DONT refusal, matching this client's "no options
    supported" behavior; DONT/WONT and subnegotiation are consumed and
    discarded without a reply.
    """

    _NORMAL, _GOT_IAC, _GOT_VERB, _GOT_SB, _GOT_SB_IAC = range(5)

    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock
        self._state = self._NORMAL
        self._pending_verb = 0

    def feed(self, data: bytes) -> bytes:
        out = bytearray()
        for byte in data:
            if self._state == self._NORMAL:
                if byte == IAC:
                    self._state = self._GOT_IAC
                else:
                    out.append(byte)
            elif self._state == self._GOT_IAC:
                if byte == IAC:
                    out.append(IAC)
                    self._state = self._NORMAL
                elif byte in (DO, DONT, WILL, WONT):
                    self._pending_verb = byte
                    self._state = self._GOT_VERB
                elif byte == SB:
                    self._state = self._GOT_SB
                else:
                    # Other IAC commands (NOP, AYT, DM, ...) carry no
                    # option byte and need no reply; just resume.
                    self._state = self._NORMAL
            elif self._state == self._GOT_VERB:
                self._reply(self._pending_verb, byte)
                self._state = self._NORMAL
            elif self._state == self._GOT_SB:
                if byte == IAC:
                    self._state = self._GOT_SB_IAC
                # else: subnegotiation payload byte - unsupported, discard.
            elif self._state == self._GOT_SB_IAC:
                if byte == SE:
                    self._state = self._NORMAL
                else:
                    self._state = self._GOT_SB
        return bytes(out)

    def _reply(self, verb: int, option: int) -> None:
        if verb == DO:
            refusal = WONT
        elif verb == WILL:
            refusal = DONT
        else:
            return  # DONT/WONT from the peer need no reply.
        try:
            self._sock.sendall(bytes([IAC, refusal, option]))
        except OSError:
            # A send failure here surfaces on the next real read/write;
            # nothing useful to do with it at negotiation time.
            pass


class GenericTelnetNCCClient:
    """Generic Telnet transport adapter for simple CLI-style devices."""

    def __init__(self, host: str, router_info: Dict[str, Any]) -> None:
        self.host = host
        self.router_info = router_info
        self.port = self._safe_port(router_info.get("telnet_port"), 23)
        self._sock: Optional[socket.socket] = None
        self._negotiator: Optional[_TelnetNegotiator] = None
        self._authenticated = False

    @staticmethod
    def _safe_port(value: Any, default: int) -> int:
        """Return a validated TCP port. A missing value (`None`) falls back
        to `default` (the device simply doesn't use this protocol); any
        *present* value must be a valid 1-65535 port, or this raises
        `GatewayError` rather than silently substituting the default."""
        if value is None:
            return default
        try:
            port = int(value)
        except (TypeError, ValueError):
            raise GatewayError(f"Invalid telnet_port value: {value!r}; expected an integer 1-65535")
        if not 1 <= port <= 65535:
            raise GatewayError(f"Invalid telnet_port value: {port}; must be between 1 and 65535")
        return port

    @staticmethod
    def _timeout() -> float:
        """Return the configured per-operation timeout in seconds. Must be a
        positive, finite number; an invalid configured value raises
        `GatewayError` instead of silently falling back to a default that
        could mask a misconfiguration."""
        raw = config("ROUTER_TELNET_TIMEOUT", default="5")
        try:
            value = float(raw)
        except (TypeError, ValueError):
            raise GatewayError(
                f"Invalid ROUTER_TELNET_TIMEOUT value: {raw!r}; expected a positive number of seconds"
            )
        if not math.isfinite(value) or value <= 0:
            raise GatewayError(
                f"Invalid ROUTER_TELNET_TIMEOUT value: {value}; must be a positive, finite number of seconds"
            )
        return value

    def _recv_until(
        self, marker: bytes, deadline: float, max_bytes: int = DEFAULT_MAX_RESPONSE_BYTES
    ) -> bytes:
        """Read until `marker` appears in the (IAC-cleaned) stream, a total
        wall-clock `deadline` (a `time.monotonic()` value) passes, or
        `max_bytes` is exceeded. Never returns a partial/truncated buffer as
        if it were a complete response: on EOF, overflow, or deadline
        expiry, raises `_TelnetReadError` carrying whatever partial bytes
        were read so far."""
        assert self._sock is not None
        assert self._negotiator is not None
        buf = bytearray()
        while marker not in bytes(buf):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _TelnetReadError(
                    f"Telnet read timed out waiting for {marker!r}", bytes(buf)
                )
            try:
                self._sock.settimeout(remaining)
                chunk = self._sock.recv(1024)
            except OSError as exc:
                raise _TelnetReadError(
                    f"Telnet read failed waiting for {marker!r}: {exc}", bytes(buf)
                )
            if not chunk:
                raise _TelnetReadError(
                    f"Telnet connection closed before receiving {marker!r} (EOF)", bytes(buf)
                )
            buf.extend(self._negotiator.feed(chunk))
            if len(buf) > max_bytes:
                raise _TelnetReadError(
                    f"Telnet response exceeded the {max_bytes}-byte limit while waiting "
                    f"for {marker!r}",
                    bytes(buf),
                )
        return bytes(buf)

    def connect(self) -> None:
        if self._sock is not None:
            return
        try:
            sock = socket.create_connection((self.host, self.port), timeout=self._timeout())
        except OSError as exc:
            logger.error(f"Telnet connect failed for {self.host}:{self.port}: {exc}")
            raise GatewayError(f"Telnet connect failed: {exc}")
        self._sock = sock
        self._negotiator = _TelnetNegotiator(sock)
        self._login()

    def _login(self) -> None:
        assert self._sock is not None
        auth = resolve_credentials(self.router_info)
        try:
            self._recv_until(b"Username:", time.monotonic() + self._timeout())
            self._sock.sendall(auth["username"].encode() + b"\r\n")

            self._recv_until(b"Password:", time.monotonic() + self._timeout())
            self._sock.sendall(auth["password"].encode() + b"\r\n")

            self._recv_until(b"> ", time.monotonic() + self._timeout())
        except _TelnetReadError as exc:
            self.close()
            if b"incorrect" in exc.partial.lower():
                raise GatewayError("Telnet authentication failed") from exc
            raise GatewayError(f"Telnet login failed: {exc}") from exc
        except OSError as exc:
            self.close()
            raise GatewayError(f"Telnet login failed: {exc}") from exc
        finally:
            # Never log credential values, only that a login attempt occurred.
            logger.info(f"Telnet login attempted for {self.host}:{self.port}")
        self._authenticated = True

    def _run_command(self, command: str) -> str:
        self.connect()
        if not self._authenticated or self._sock is None:
            raise GatewayError("Telnet session is not authenticated")
        try:
            self._sock.sendall(command.encode() + b"\r\n")
            raw = self._recv_until(b"> ", time.monotonic() + self._timeout())
        except _TelnetReadError as exc:
            self.close()
            raise GatewayError(f"Telnet command failed: {exc}") from exc
        except OSError as exc:
            self.close()
            raise GatewayError(f"Telnet command failed: {exc}") from exc
        return raw.decode("utf-8", errors="ignore")

    def get_show_interface_command(self, interface_name: Optional[str] = None) -> str:
        return f"show interface {interface_name}" if interface_name else "show interface"

    def show_interface(self, interface_name: Optional[str] = None) -> Dict[str, str]:
        command = self.get_show_interface_command(interface_name)
        output = self._run_command(command)
        return {"command": command, "output": output}

    def _unsupported(self, operation: str) -> None:
        raise GatewayError(
            f"{operation} is not supported over the generic Telnet transport in this demo; "
            "Telnet only exposes CLI-style show commands here."
        )

    def get_config(self) -> str:
        self._unsupported("get_config")

    def set_config(self, config_data: str) -> Dict[str, str]:
        self._unsupported("set_config")

    def get_operational_state(self) -> str:
        self._unsupported("get_operational_state")

    def configure_interface(self, interface_name: str, config_xml: str) -> Dict[str, str]:
        self._unsupported("configure_interface")

    def get_bgp(self) -> str:
        self._unsupported("get_bgp")

    def set_bgp(self, config_xml: str) -> Dict[str, str]:
        self._unsupported("set_bgp")

    def configure_firewall(self, config_xml: str) -> Dict[str, str]:
        self._unsupported("configure_firewall")

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None
                self._negotiator = None
                self._authenticated = False

    def cleanup(self) -> None:
        self.close()
