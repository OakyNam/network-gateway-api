"""Isolated fake-peer regression tests for `GenericTelnetNCCClient`'s Telnet
protocol handling.

Unlike `test/integration_test/test_demo_emulators.py` (which exercises the bundled
`TelnetEmulator`'s fixed, canned behavior), these tests use a minimal,
fully test-controlled raw TCP peer so we can script byte-for-byte
adversarial/edge-case server behavior: truncated responses, IAC negotiation
requests split across TCP reads, a missing/incorrect login prompt, and a
peer that never responds at all (deadline exceeded). Each case asserts the
client fails loudly with `GatewayError` rather than ever returning a
truncated buffer as if it were a complete, successful response.
"""

import os
import socket
import threading
import time
import unittest
from unittest.mock import patch

from app.dal.device.telnet_client import DONT, IAC, WILL, GenericTelnetNCCClient
from app.common.errors import GatewayError

USERNAME = "u"
PASSWORD = "p"


class _FakePeer:
    """A bare TCP listener the test drives by hand as the "device" side of
    the Telnet conversation, independent of the demo's `TelnetEmulator`."""

    def __init__(self) -> None:
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(1)
        self.port = self._listener.getsockname()[1]
        self._conn = None
        self._accept_thread = threading.Thread(target=self._accept, daemon=True)
        self._accept_thread.start()

    def _accept(self) -> None:
        try:
            self._listener.settimeout(5)
            conn, _ = self._listener.accept()
            self._conn = conn
        except OSError:
            pass

    def wait_for_connection(self, timeout: float = 5) -> socket.socket:
        deadline = time.monotonic() + timeout
        while self._conn is None and time.monotonic() < deadline:
            time.sleep(0.01)
        assert self._conn is not None, "client never connected to the fake peer"
        return self._conn

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            except OSError:
                pass
        try:
            self._listener.close()
        except OSError:
            pass


def _read_until_crlf(conn: socket.socket, timeout: float = 5) -> bytes:
    """Read whatever the client just sent (it always terminates each line
    with \\r\\n), for scripting a request/response exchange step by step."""
    conn.settimeout(timeout)
    buf = bytearray()
    while b"\r\n" not in bytes(buf):
        chunk = conn.recv(256)
        if not chunk:
            break
        buf.extend(chunk)
    return bytes(buf).split(b"\r\n", 1)[0]


def _run_in_thread(func, result: dict) -> threading.Thread:
    def runner() -> None:
        try:
            result["value"] = func()
        except BaseException as exc:  # noqa: BLE001 - captured for assertions
            result["error"] = exc

    thread = threading.Thread(target=runner, daemon=True)
    thread.start()
    return thread


class TelnetProtocolFakePeerTests(unittest.TestCase):
    def setUp(self):
        self.peer = _FakePeer()
        self.addCleanup(self.peer.close)
        self.env_patch = patch.dict(os.environ, {"ROUTER_TELNET_TIMEOUT": "2"})
        self.env_patch.start()
        self.addCleanup(self.env_patch.stop)

    def _client(self) -> GenericTelnetNCCClient:
        return GenericTelnetNCCClient(
            "127.0.0.1",
            {"telnet_port": self.peer.port, "username": USERNAME, "password": PASSWORD},
        )

    def _login_and_get_conn(self, client: GenericTelnetNCCClient, result: dict) -> socket.socket:
        """Drive the fake peer through a normal login for `client` (run in a
        background thread via `result`'s runner), returning the accepted
        server-side socket positioned right after authentication."""
        conn = self.peer.wait_for_connection()
        conn.sendall(b"Username: ")
        self.assertEqual(_read_until_crlf(conn), USERNAME.encode())
        conn.sendall(b"Password: ")
        self.assertEqual(_read_until_crlf(conn), PASSWORD.encode())
        conn.sendall(b"\r\n> ")
        return conn

    def test_truncated_response_raises_gateway_error_not_partial_success(self):
        """A response that stops (peer closes) before the prompt appears
        must raise GatewayError, never be returned as a successful,
        silently-truncated result."""
        client = self._client()
        result: dict = {}
        thread = _run_in_thread(client.show_interface, result)

        conn = self._login_and_get_conn(client, result)
        _read_until_crlf(conn)  # the "show interface" command line
        conn.sendall(b"partial output, then the connection just drops")
        conn.close()

        thread.join(timeout=5)
        self.assertNotIn("value", result)
        self.assertIsInstance(result.get("error"), GatewayError)
        client.cleanup()

    def test_split_iac_negotiation_is_handled_across_reads_and_refused(self):
        """A WILL/DO negotiation request split across two separate TCP
        sends must not corrupt the surrounding plain-text prompt, and must
        be answered with an explicit refusal (DONT/WONT)."""
        client = self._client()
        result: dict = {}
        thread = _run_in_thread(client.show_interface, result)

        conn = self.peer.wait_for_connection()
        conn.sendall(b"User")
        conn.sendall(bytes([IAC, WILL]))  # first half of the IAC sequence
        time.sleep(0.05)
        conn.sendall(bytes([1]))  # ECHO option, arrives in a separate recv()
        conn.sendall(b"name: ")

        # The client must reply with an explicit refusal for the split
        # negotiation request before/while it keeps reading the prompt.
        refusal = conn.recv(3)
        self.assertEqual(refusal, bytes([IAC, DONT, 1]))

        self.assertEqual(_read_until_crlf(conn), USERNAME.encode())
        conn.sendall(b"Password: ")
        self.assertEqual(_read_until_crlf(conn), PASSWORD.encode())
        conn.sendall(b"\r\n> ")
        _read_until_crlf(conn)  # the "show interface" command line
        conn.sendall(b"SIMULATED\r\n> ")

        thread.join(timeout=5)
        self.assertIsNone(result.get("error"))
        self.assertIn("SIMULATED", result["value"]["output"])
        client.cleanup()

    def test_missing_login_prompt_raises_gateway_error(self):
        """A peer that never sends a recognizable 'Username:' prompt (e.g.
        an incompatible device or protocol mismatch) must fail explicitly
        instead of the client guessing or proceeding anyway."""
        client = self._client()
        result: dict = {}
        thread = _run_in_thread(client.show_interface, result)

        conn = self.peer.wait_for_connection()
        conn.sendall(b"Unexpected banner text, no login prompt here\r\n")
        conn.close()

        thread.join(timeout=5)
        self.assertIsInstance(result.get("error"), GatewayError)
        client.cleanup()

    def test_read_deadline_exceeded_raises_gateway_error(self):
        """A peer that accepts the connection but never sends anything must
        cause the client to fail after its bounded read deadline, not hang
        indefinitely or return an empty/partial success."""
        with patch.dict(os.environ, {"ROUTER_TELNET_TIMEOUT": "1"}):
            client = self._client()
            result: dict = {}
            thread = _run_in_thread(client.show_interface, result)

            conn = self.peer.wait_for_connection()
            thread.join(timeout=5)
            self.assertIsInstance(result.get("error"), GatewayError)
            client.cleanup()
            conn.close()

    def test_invalid_port_raises_gateway_error(self):
        with self.assertRaises(GatewayError):
            GenericTelnetNCCClient("127.0.0.1", {"telnet_port": 99999})
        with self.assertRaises(GatewayError):
            GenericTelnetNCCClient("127.0.0.1", {"telnet_port": "not-a-port"})

    def test_invalid_timeout_raises_gateway_error(self):
        client = self._client()
        with patch.dict(os.environ, {"ROUTER_TELNET_TIMEOUT": "-3"}):
            with self.assertRaises(GatewayError):
                client.show_interface()
        with patch.dict(os.environ, {"ROUTER_TELNET_TIMEOUT": "not-a-number"}):
            with self.assertRaises(GatewayError):
                client.show_interface()
        client.cleanup()


if __name__ == "__main__":
    unittest.main()
