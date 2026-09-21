"""Real local protocol matrix; no hardware, external service or device writes."""

import io
import logging
import socket
import threading
import time
import unittest
import uuid
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

import paramiko
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from app.bl.services.connection_tests import CAPABILITIES, run_connection_test
from app.bl.services.management import ManagementService
from app.dal.proxy.connectors import ConnectorError, Deadline, _resolve
from demo.emulators.proxy_protocols import HttpConnectPeer, SSHPeer, Socks5Peer, TelnetPeer


ROOT = Path(__file__).resolve().parents[2]


class ConnectorMatrixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.host_key = paramiko.ECDSAKey.generate()
        cls.bastion_key = paramiko.ECDSAKey.generate()
        cls.login_key = paramiko.RSAKey.generate(2048)
        cls.other_login_key = paramiko.ECDSAKey.generate()
        cls._logger = logging.getLogger("paramiko")
        cls._log_level = cls._logger.level
        cls._logger.setLevel(logging.CRITICAL)

    @classmethod
    def tearDownClass(cls):
        cls._logger.setLevel(cls._log_level)

    def setUp(self):
        self.stack = ExitStack()
        self.peers = []
        self.files = []

    def tearDown(self):
        self.stack.close()
        for peer in self.peers:
            self.assertEqual(peer.workers_alive, 0, "Emulator worker leaked after shutdown")
        for path in self.files:
            path.unlink(missing_ok=True)

    def start(self, peer):
        self.peers.append(peer)
        return self.stack.enter_context(peer)

    def trust(self, peer, key=None):
        directory = ROOT / "test" / "fixtures"
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"connector_known_hosts_{uuid.uuid4().hex}"
        key = key or peer.host_key
        path.write_text(f"[127.0.0.1]:{peer.port} {key.get_name()} {key.get_base64()}\n", encoding="utf-8")
        self.files.append(path)
        return str(path)

    @staticmethod
    def pasted(key, passphrase=None):
        text = io.StringIO()
        key.write_private_key(text, password=passphrase)
        return text.getvalue()

    def device(self, protocol, **kwargs):
        peer = self.start(TelnetPeer(**kwargs) if protocol == "telnet" else SSHPeer(self.host_key, **kwargs))
        profile = {
            "protocol": protocol, "host": peer.host, "port": peer.port,
            "username": "device", "password": "device-password",
            "timeout_seconds": 3, "connector": {"type": "direct"},
        }
        if protocol != "telnet":
            profile["known_hosts_path"] = self.trust(peer)
        return peer, profile

    def proxy(self, kind, **kwargs):
        if kind.startswith("ssh_"):
            peer = SSHPeer(self.bastion_key, bastion=True, username="bastion", password="bastion-password", **kwargs)
        elif kind == "socks5":
            peer = Socks5Peer(username="bastion", password="bastion-password", **kwargs)
        else:
            peer = HttpConnectPeer(username="bastion", password="bastion-password", **kwargs)
        self.start(peer)
        config = {"type": kind, "host": peer.host, "port": peer.port,
                  "username": "bastion", "password": "bastion-password"}
        if kind.startswith("ssh_"):
            config["known_hosts_path"] = self.trust(peer)
        return peer, config

    def check_result(self, profile, success=True, stage=None):
        service = ManagementService(None, demo_mode=True, device_data_provider="fake")
        result = service.test_profile(profile)
        self.assertEqual(set(result), {"success", "simulated", "stage", "detail", "duration_ms"})
        self.assertIs(result["simulated"], False)
        self.assertIs(result["success"], success, result)
        if stage:
            self.assertEqual(result["stage"], stage, result)
        for secret in ("device-password", "bastion-password", "sensitive-secret", "BEGIN RSA PRIVATE KEY"):
            self.assertNotIn(secret, str(result))
        self.assertGreaterEqual(result["duration_ms"], 0)
        return result

    def test_advertised_protocol_connector_matrix_real_handshakes(self):
        combinations = 0
        for capability in CAPABILITIES["connectors"]:
            for protocol in capability["protocols"]:
                kind = capability["type"]
                with self.subTest(protocol=protocol, connector=kind):
                    peer, profile = self.device(protocol)
                    if kind != "direct":
                        _, profile["connector"] = self.proxy(kind)
                    self.check_result(profile, stage="complete")
                    self.assertIn("password_authenticated", peer.events)
                    self.assertNotIn("unexpected_command", peer.events)
                    self.assertNotIn("unexpected_exec", peer.events)
                    self.assertNotIn("unexpected_rpc", peer.events)
                    if protocol == "netconf":
                        self.assertIn("client_hello", peer.events)
                    combinations += 1
        self.assertEqual(combinations, 13)

    def test_socks_and_http_explicit_no_auth(self):
        for kind, peer_type in (("socks5", Socks5Peer), ("http_connect", HttpConnectPeer)):
            with self.subTest(connector=kind):
                _, profile = self.device("telnet")
                peer = self.start(peer_type())
                profile["connector"] = {"type": kind, "host": peer.host, "port": peer.port}
                self.check_result(profile)

    def test_proxy_ports_can_be_fixed_and_reused_on_new_instances(self):
        for kind in ("socks5", "http_connect", "ssh_tunnel", "ssh_shell"):
            with self.subTest(connector=kind):
                first, _ = self.proxy(kind)
                port = first.port
                first.stop()
                replacement, connector = self.proxy(kind, port=port)
                self.assertEqual(replacement.port, port)
                _, profile = self.device("telnet")
                profile["connector"] = connector
                self.check_result(profile)

    def test_failed_emulator_bind_releases_listener_and_allows_safe_stop(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as occupied:
            if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                occupied.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            occupied.bind(("127.0.0.1", 0))
            occupied.listen(1)
            peer = Socks5Peer(port=occupied.getsockname()[1])
            try:
                with self.assertRaises(OSError):
                    peer.start()
                self.assertIsNone(peer._listener)
                self.assertEqual(len(peer._resources), 0)
                self.assertEqual(peer.workers_alive, 0)
            finally:
                peer.stop()
        for port in (-1, 65536, True, "1080"):
            with self.subTest(port=port), self.assertRaises(ValueError):
                Socks5Peer(port=port)

    def test_proxy_denials_do_not_bypass_proxy(self):
        for kind in ("socks5", "http_connect", "ssh_tunnel", "ssh_shell"):
            with self.subTest(connector=kind):
                device, profile = self.device("telnet")
                _, profile["connector"] = self.proxy(kind, deny=True)
                self.check_result(profile, False, "proxy_connect")
                self.assertNotIn("accepted", device.events)

    def test_proxy_authentication_is_separate_from_device_authentication(self):
        for kind in ("socks5", "http_connect", "ssh_tunnel", "ssh_shell"):
            with self.subTest(connector=kind):
                device, profile = self.device("telnet")
                _, profile["connector"] = self.proxy(kind)
                profile["connector"]["password"] = "sensitive-secret"
                self.check_result(profile, False, "proxy_auth")
                self.assertNotIn("accepted", device.events)

    def test_device_authentication_failure_through_proxies(self):
        for kind in ("direct", "socks5", "http_connect", "ssh_tunnel", "ssh_shell"):
            with self.subTest(connector=kind):
                _, profile = self.device("telnet")
                if kind != "direct":
                    _, profile["connector"] = self.proxy(kind)
                profile["password"] = "sensitive-secret"
                self.check_result(profile, False, "device_auth")

    def test_ssh_authentication_failure(self):
        for protocol in ("ssh", "netconf"):
            with self.subTest(protocol=protocol):
                _, profile = self.device(protocol)
                profile["password"] = "sensitive-secret"
                self.check_result(profile, False, "device_auth")

    def test_wrong_device_host_key_direct_and_tunnel(self):
        for kind in ("direct", "ssh_tunnel"):
            with self.subTest(connector=kind):
                device, profile = self.device("netconf")
                profile["known_hosts_path"] = self.trust(device, self.bastion_key)
                if kind != "direct":
                    _, profile["connector"] = self.proxy(kind)
                self.check_result(profile, False, "device_host_key")
                self.assertNotIn("password_authenticated", device.events)

    def test_wrong_bastion_key_does_not_contact_device(self):
        device, profile = self.device("ssh")
        proxy, profile["connector"] = self.proxy("ssh_tunnel")
        profile["connector"]["known_hosts_path"] = self.trust(proxy, self.host_key)
        self.check_result(profile, False, "proxy_host_key")
        self.assertNotIn("accepted", device.events)

    def test_missing_and_unknown_trust_rejected(self):
        device, profile = self.device("ssh")
        del profile["known_hosts_path"]
        self.check_result(profile, False, "device_host_key")
        path = Path(self.trust(device))
        path.write_text("", encoding="utf-8")
        profile["known_hosts_path"] = str(path)
        self.check_result(profile, False, "device_host_key")
        self.assertNotIn("password_authenticated", device.events)

    def test_pasted_encrypted_key_ssh_and_netconf_direct_and_tunnel(self):
        for protocol in ("ssh", "netconf"):
            for kind in ("direct", "ssh_tunnel"):
                with self.subTest(protocol=protocol, connector=kind):
                    device, profile = self.device(protocol, allowed_key=self.login_key)
                    profile.pop("password")
                    profile.update(authentication_type="ssh_key", private_key=self.pasted(self.login_key, "key-passphrase"),
                                   key_passphrase="key-passphrase")
                    if kind == "ssh_tunnel":
                        bastion, profile["connector"] = self.proxy(kind, allowed_key=self.other_login_key)
                        profile["connector"].pop("password")
                        profile["connector"].update(authentication_type="ssh_key",
                                                     private_key=self.pasted(self.other_login_key))
                    self.check_result(profile)
                    self.assertIn("key_authenticated", device.events)
                    self.assertNotIn("password_authenticated", device.events)
                    if kind == "ssh_tunnel":
                        self.assertIn("key_authenticated", bastion.events)
                        self.assertNotIn("password_authenticated", bastion.events)

    def test_pasted_key_interactive_bastion_password_device(self):
        _, profile = self.device("telnet")
        bastion, profile["connector"] = self.proxy("ssh_shell", allowed_key=self.other_login_key)
        profile["connector"].pop("password")
        profile["connector"].update(authentication_type="ssh_key", private_key=self.pasted(self.other_login_key))
        self.check_result(profile)
        self.assertIn("key_authenticated", bastion.events)
        self.assertIn("telnet_command", bastion.events)

    def test_pasted_pkcs8_rsa_ecdsa_ed25519_keys_with_and_without_passphrase(self):
        keys = (
            (rsa.generate_private_key(public_exponent=65537, key_size=2048), paramiko.RSAKey),
            (ec.generate_private_key(ec.SECP256R1()), paramiko.ECDSAKey),
            (ed25519.Ed25519PrivateKey.generate(), paramiko.Ed25519Key),
        )
        for key, paramiko_type in keys:
            authorized = paramiko_type.from_private_key(io.StringIO(key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                serialization.NoEncryption(),
            ).decode("ascii")))
            for encrypted in (False, True):
                with self.subTest(key=paramiko_type.__name__, encrypted=encrypted):
                    device, profile = self.device("netconf", allowed_key=authorized)
                    profile.pop("password")
                    encryption = (serialization.BestAvailableEncryption(b"key-passphrase") if encrypted
                                  else serialization.NoEncryption())
                    profile.update(
                        authentication_type="ssh_key",
                        private_key=key.private_bytes(
                            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption,
                        ).decode("ascii"),
                        key_passphrase="key-passphrase" if encrypted else None,
                    )
                    self.check_result(profile)
                    self.assertIn("key_authenticated", device.events)
                    self.assertIn("client_hello", device.events)

    def test_bad_key_passphrase_and_unauthorized_key_are_sanitized(self):
        _, profile = self.device("netconf", allowed_key=self.login_key)
        profile.pop("password")
        profile.update(authentication_type="ssh_key", private_key=self.pasted(self.login_key, "correct-passphrase"),
                       key_passphrase="sensitive-secret")
        self.check_result(profile, False, "validation")
        profile.update(private_key=self.pasted(self.other_login_key), key_passphrase=None)
        self.check_result(profile, False, "device_auth")

    def test_overall_timeout_for_all_proxy_protocols(self):
        for kind in ("socks5", "http_connect", "ssh_tunnel", "ssh_shell"):
            with self.subTest(connector=kind):
                device, profile = self.device("telnet")
                _, profile["connector"] = self.proxy(kind, stall=True)
                profile["timeout_seconds"] = 1
                result = self.check_result(profile, False, "timeout")
                self.assertLess(result["duration_ms"], 1800)
                self.assertNotIn("accepted", device.events)

    def test_overall_timeout_for_shell_prompt_and_netconf_hello(self):
        for protocol in ("telnet", "netconf"):
            with self.subTest(protocol=protocol):
                if protocol == "telnet":
                    _, profile = self.device(protocol)
                    _, profile["connector"] = self.proxy("ssh_shell", stall_prompt=True)
                else:
                    _, profile = self.device(protocol, stall_hello=True)
                profile["timeout_seconds"] = 1
                result = self.check_result(profile, False, "timeout")
                self.assertLess(result["duration_ms"], 1800)

    def test_deadline_is_shared_across_bastion_and_device_authentication(self):
        _, profile = self.device("ssh", auth_delay=0.65)
        _, profile["connector"] = self.proxy("ssh_tunnel", auth_delay=0.65)
        profile["timeout_seconds"] = 1
        result = self.check_result(profile, False, "timeout")
        self.assertLess(result["duration_ms"], 1800)

    def test_partial_ssh_authentication_is_not_success_and_never_prompts(self):
        for method in ("password", "ssh_key"):
            with self.subTest(method=method):
                device, profile = self.device("ssh", partial_auth=True, allowed_key=self.login_key)
                if method == "ssh_key":
                    profile.pop("password")
                    profile.update(authentication_type="ssh_key", private_key=self.pasted(self.login_key))
                self.check_result(profile, False, "device_auth")
                self.assertNotIn("unexpected_interactive_auth", device.events)

    def test_keyboard_interactive_is_not_a_silent_password_fallback(self):
        device, profile = self.device("ssh", interactive_only=True)
        self.check_result(profile, False, "device_auth")
        self.assertNotIn("unexpected_interactive_auth", device.events)

    def test_bad_telnet_prompt_cannot_succeed(self):
        _, profile = self.device("telnet", bad_prompt=True)
        profile["timeout_seconds"] = 1
        self.check_result(profile, False, "timeout")

    def test_fragmented_telnet_negotiation(self):
        device, profile = self.device("telnet", fragmented_negotiation=True)
        self.check_result(profile)
        self.assertIn("telnet_negotiated", device.events)

    def test_invalid_proxy_protocol_responses(self):
        for kind in ("socks5", "http_connect"):
            with self.subTest(connector=kind):
                _, profile = self.device("telnet")
                _, profile["connector"] = self.proxy(kind, malformed=True)
                self.check_result(profile, False, "protocol")

    def test_invalid_netconf_hello_namespace_capability_session_and_entities(self):
        valid = (
            b'<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><capabilities>'
            b"<capability>urn:ietf:params:netconf:base:1.0</capability></capabilities>"
            b"<session-id>7</session-id></hello>]]>]]>"
        )
        for hello in (
            b"<not-hello/>]]>]]>",
            valid.replace(b'xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"', b'xmlns="urn:wrong"'),
            valid.replace(b">7<", b">0<"),
            valid.replace(b"</hello>", b"<session-id>8</session-id></hello>"),
            valid.replace(b"</capabilities>", b"<unexpected/></capabilities>"),
            valid.replace(b"params:netconf:base:1.0", b"params:netconf:base:1.1"),
            b'<!DOCTYPE hello [<!ENTITY secret "sensitive-secret">]>' + valid,
            ('<!DOCTYPE hello [<!ENTITY secret "sensitive-secret">]>' +
             valid[:-6].decode()).encode("utf-16") + b"]]>]]>",
            b"x" * 65536 + b"]]>]]>",
        ):
            with self.subTest(hello=hello[:30]):
                _, profile = self.device("netconf", hello=hello)
                self.check_result(profile, False, "protocol")

    def test_netconf_unterminated_framing_is_bounded(self):
        _, profile = self.device("netconf", hello=b"<hello/>")
        profile["timeout_seconds"] = 1
        result = self.check_result(profile, False, "timeout")
        self.assertLess(result["duration_ms"], 1800)

    def test_demo_rejects_off_loopback_before_dns_or_any_socket(self):
        base = {"protocol": "telnet", "host": "127.0.0.1", "port": 23,
                "username": "device", "password": "device-password", "timeout_seconds": 1}
        cases = []
        for host in ("192.0.2.1", "example.invalid", "127.0.0.1.example.invalid", "::ffff:192.0.2.1"):
            cases.append({**base, "host": host})
            cases.append({**base, "connector": {"type": "http_connect", "host": host, "port": 8080}})
            cases.append({**base, "host": host, "connector": {"type": "socks5", "host": "127.0.0.1", "port": 1080}})
        for profile in cases:
            with self.subTest(profile=profile), patch("socket.getaddrinfo") as dns, patch("socket.socket") as connect:
                self.check_result(profile, False, "demo_policy")
                dns.assert_not_called()
                connect.assert_not_called()

    def test_demo_localhost_is_pinned_without_dns(self):
        _, profile = self.device("telnet")
        profile["host"] = "localhost"
        with patch("socket.getaddrinfo", side_effect=AssertionError("Unexpected DNS")):
            self.check_result(profile)

    def test_demo_private_key_and_external_trust_paths_rejected_before_io(self):
        for field, value in (("private_key_path", "C:\\sensitive-secret"),
                             ("known_hosts_path", "C:\\sensitive-secret")):
            profile = {"protocol": "ssh", "host": "127.0.0.1", "port": 22,
                       "username": "device", "password": "device-password", field: value}
            with self.subTest(field=field), patch("builtins.open") as file, patch("socket.socket") as connect:
                self.check_result(profile, False, "demo_policy")
                file.assert_not_called()
                connect.assert_not_called()

    def test_unsupported_combinations_rejected_before_network(self):
        base = {"host": "127.0.0.1", "port": 23, "username": "device", "password": "device-password"}
        cases = [
            {**base, "protocol": protocol, "connector": {"type": "ssh_shell"}}
            for protocol in ("ssh", "netconf")
        ] + [
            {**base, "protocol": "telnet", "authentication_type": "ssh_key", "private_key": "sensitive-secret"},
            {**base, "protocol": "telnet", "connector": {"type": "made-up"}},
            {**base, "protocol": "telnet", "connector": {}},
            {**base, "protocol": "ftp"},
        ]
        for profile in cases:
            with self.subTest(profile=profile), patch("socket.socket") as connect:
                self.check_result(profile, False, "unsupported")
                connect.assert_not_called()

    def test_unresolved_saved_proxy_never_falls_back_to_direct(self):
        base = {"protocol": "telnet", "host": "127.0.0.1", "port": 23, "proxy_id": "saved-proxy",
                "username": "device", "password": "device-password"}
        for profile in (base, {**base, "connector": {"type": "direct"}}):
            with self.subTest(profile=profile), patch("socket.socket") as connect:
                self.check_result(profile, False, "validation")
                connect.assert_not_called()

    def test_invalid_ports_timeout_and_command_injection_before_network(self):
        base = {"protocol": "telnet", "host": "127.0.0.1", "port": 23,
                "username": "device", "password": "device-password", "timeout_seconds": 1}
        cases = [{**base, "port": value} for value in (0, 65536, True, 22.1, "abc")]
        cases += [{**base, "timeout_seconds": value} for value in (0, 31, True, float("nan"))]
        cases += [{**base, field: value} for field, value in
                  (("host", "127.0.0.1;touch"), ("username", "device\nconfigure"), ("password", "secret\rcommand"))]
        for profile in cases:
            with self.subTest(profile=profile), patch("socket.socket") as connect:
                self.check_result(profile, False, "validation")
                connect.assert_not_called()

    def test_dns_wait_is_bounded_and_resolver_slot_is_released(self):
        released = threading.Event()

        def slow_lookup(*args, **kwargs):
            released.wait(2)
            return []

        started = time.monotonic()
        with patch("socket.getaddrinfo", side_effect=slow_lookup):
            try:
                with Deadline(0.1) as deadline:
                    with self.assertRaises(ConnectorError) as error:
                        _resolve("test.invalid", 22, deadline)
                    self.assertEqual(error.exception.stage, "timeout")
            finally:
                released.set()
        self.assertLess(time.monotonic() - started, 0.6)

    def test_refused_tcp_is_failure_not_success(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        result = run_connection_test({
            "protocol": "telnet", "host": "127.0.0.1", "port": port,
            "username": "device", "password": "device-password", "timeout_seconds": 1,
        }, demo_mode=True)
        self.assertFalse(result["success"], result)
        self.assertIn(result["stage"], {"timeout", "device_connect"})


if __name__ == "__main__":
    unittest.main()
