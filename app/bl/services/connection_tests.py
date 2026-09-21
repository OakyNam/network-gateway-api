"""Read-only authentication checks, never device commands or configuration RPCs.

SSH tests authenticate only. NETCONF additionally opens the subsystem and
exchanges validated base:1.0 hello messages. Generic Telnet requires a
Username:/Login:, Password:, then a simple line-ending >/#/$ prompt. It is
not DDM2200-certified. ssh_shell requires a POSIX-like shell with `telnet`.
"""

from __future__ import annotations

import re
import socket
import time
import xml.etree.ElementTree as ET

import paramiko

from app.dal.proxy.connectors import (
    ConnectorError, Deadline, SHELL_PROMPT, connect_ssh, open_stream,
    read_prompt, receive_until, send, validate_profile,
)


CAPABILITIES = {
    "protocols": ["ssh", "netconf", "telnet"],
    "connectors": [
        {"type": "direct", "label": "Direct TCP", "protocols": ["ssh", "netconf", "telnet"],
         "description": "Direct read-only authentication check; strict SSH host-key verification."},
        {"type": "ssh_tunnel", "label": "SSH TCP forwarding", "protocols": ["ssh", "netconf", "telnet"],
         "description": "SSH direct-tcpip forwarding with separate bastion and device credentials and trust."},
        {"type": "ssh_shell", "label": "Interactive SSH shell (generic Telnet)", "protocols": ["telnet"],
         "description": "POSIX-like bastion shell running telnet; generic prompts only, not DDM2200-certified."},
        {"type": "socks5", "label": "SOCKS5", "protocols": ["ssh", "netconf", "telnet"],
         "description": "SOCKS5 CONNECT with explicit no-auth or username/password authentication."},
        {"type": "http_connect", "label": "HTTP CONNECT", "protocols": ["ssh", "netconf", "telnet"],
         "description": "HTTP/1.x CONNECT with optional Basic proxy authentication; no TLS-to-proxy."},
    ],
}

_NAMESPACE = "urn:ietf:params:xml:ns:netconf:base:1.0"
_BASE = "urn:ietf:params:netconf:base:1.0"
_EOM = b"]]>]]>"
_HELLO = (
    f'<hello xmlns="{_NAMESPACE}"><capabilities>'
    f"<capability>{_BASE}</capability></capabilities></hello>"
).encode("ascii") + _EOM
_USERNAME = re.compile(rb"(?:^|[\r\n])(?:Username|username|Login|login):[ \t]*$")
_PASSWORD = re.compile(rb"(?:^|[\r\n])(?:Password|password):[ \t]*$")


def _telnet_login(stream, device, deadline):
    from app.dal.device.telnet_client import _TelnetNegotiator
    negotiator = _TelnetNegotiator(stream)
    read_prompt(stream, _USERNAME, deadline, negotiator=negotiator)
    send(stream, device["username"].encode("utf-8") + b"\r\n", deadline)
    read_prompt(stream, _PASSWORD, deadline, negotiator=negotiator)
    send(stream, device["password"].encode("utf-8") + b"\r\n", deadline)
    read_prompt(stream, SHELL_PROMPT, deadline, negotiator=negotiator)


def _netconf_hello(client, deadline):
    channel = deadline.own(client.get_transport().open_session(timeout=deadline.remaining()))
    channel.settimeout(deadline.remaining())
    channel.invoke_subsystem("netconf")
    send(channel, _HELLO, deadline)
    raw = receive_until(channel, _EOM, deadline, limit=65536)[:-len(_EOM)]
    if b"\x00" in raw or b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        raise ConnectorError("protocol", "NETCONF hello must not contain a DTD or entity declaration.")
    try:
        text = raw.decode("utf-8")
        declaration = re.match(r'\ufeff?<\?xml\s+[^?]*encoding=["\']([^"\']+)["\']', text)
        if declaration and declaration[1].lower() not in ("utf-8", "utf8"):
            raise ValueError
        root = ET.fromstring(text)
        caps = root.find(f"{{{_NAMESPACE}}}capabilities")
        session = root.find(f"{{{_NAMESPACE}}}session-id")
        if (root.tag != f"{{{_NAMESPACE}}}hello" or caps is None or session is None or
                len(root) != 2 or
                any(node.tag != f"{{{_NAMESPACE}}}capability" or len(node) for node in caps) or
                not session.text or not session.text.isascii() or not session.text.isdecimal() or
                len(session) != 0 or
                not 1 <= int(session.text) <= 4294967295 or
                _BASE not in {node.text for node in caps.findall(f"{{{_NAMESPACE}}}capability")}):
            raise ValueError
    except (ET.ParseError, UnicodeError, ValueError, OverflowError):
        raise ConnectorError("protocol", "The server did not provide a valid compatible NETCONF hello.") from None


def run_connection_test(profile: dict, demo_mode: bool = False) -> dict:
    started = time.monotonic()
    deadline = None
    try:
        device, connector, seconds = validate_profile(profile, demo_mode)
        with Deadline(seconds) as deadline:
            stream = open_stream(device, connector, deadline, demo_mode)
            if device["protocol"] == "telnet":
                _telnet_login(stream, device, deadline)
                detail = "Generic Telnet login and prompt verified; no device commands were executed."
            else:
                client = connect_ssh(device, stream, deadline, demo_mode, "device")
                if device["protocol"] == "netconf":
                    _netconf_hello(client, deadline)
                    detail = "SSH authentication and NETCONF hello verified; no RPCs were sent."
                else:
                    detail = "SSH authentication verified; no device commands were executed."
            deadline.remaining()
        result = {"success": True, "stage": "complete", "detail": detail}
    except Exception as exc:
        if deadline is not None and (deadline.expired.is_set() or time.monotonic() >= deadline.end):
            stage, detail = "timeout", "The overall connection-test deadline expired."
        elif isinstance(exc, ConnectorError):
            stage, detail = exc.stage, exc.detail
        elif isinstance(exc, (socket.timeout, TimeoutError)):
            stage, detail = "timeout", "The overall connection-test deadline expired."
        elif isinstance(exc, (paramiko.SSHException, OSError, EOFError)):
            stage, detail = "protocol", "The connection closed or failed during protocol negotiation."
        else:
            stage, detail = "internal", "The connection test could not be completed."
        result = {"success": False, "stage": stage, "detail": detail}
    result["duration_ms"] = round((time.monotonic() - started) * 1000, 2)
    return result
