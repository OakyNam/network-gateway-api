"""SQLite-resolved private profiles exercised against real local connectors."""

import io
import json
import os
import shutil
import unittest
import uuid
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

import paramiko
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from app.bl.services.connection_tests import run_connection_test
from app.dal.db.store import GatewayStore
from demo.emulators.proxy_protocols import HttpConnectPeer, SSHPeer, TelnetPeer


ROOT = Path(__file__).resolve().parents[2]


class ResolvedConnectionTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.directory = ROOT / ".cache" / ("connection-store-" + uuid.uuid4().hex)
        self.directory.mkdir(parents=True)
        self.files = []
        self.store = GatewayStore(sqlite_path=self.directory / "inventory.sqlite",
                                  secret_key=Fernet.generate_key())

    def tearDown(self):
        self.stack.close()
        self.store.close()
        for path in self.files:
            path.unlink(missing_ok=True)
        shutil.rmtree(self.directory)

    def start(self, peer):
        return self.stack.enter_context(peer)

    def trust(self, peer):
        path = ROOT / "test" / "fixtures" / ("connection_store_hosts_" + uuid.uuid4().hex)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            f"[127.0.0.1]:{peer.port} {peer.host_key.get_name()} {peer.host_key.get_base64()}\n",
            encoding="utf-8",
        )
        self.files.append(path)
        return str(path)

    def role(self, name, username, password):
        return self.store.save("role_accounts", {
            "name": name, "username": username, "authentication_type": "password", "password": password,
        })

    def test_separate_saved_roles_proxy_trust_and_encrypted_pkcs8_netconf_login(self):
        key = ed25519.Ed25519PrivateKey.generate()
        authorized = paramiko.Ed25519Key.from_private_key(io.StringIO(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
            serialization.NoEncryption(),
        ).decode("ascii")))
        private_key = key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(b"role-key-passphrase"),
        ).decode("ascii")
        device = self.start(SSHPeer(paramiko.ECDSAKey.generate(), allowed_key=authorized, password=None))
        bastion = self.start(SSHPeer(paramiko.ECDSAKey.generate(), bastion=True,
                                     username="bastion", password="bastion-role-password"))
        device_role = self.store.save("role_accounts", {
            "name": "Device key", "username": "device", "authentication_type": "ssh_key",
            "private_key": private_key, "key_passphrase": "role-key-passphrase",
        })
        proxy_role = self.role("Bastion password", "bastion", "bastion-role-password")
        proxy = self.store.save("proxies", {
            "name": "Trusted bastion", "type": "ssh_tunnel", "host": bastion.host, "port": bastion.port,
            "known_hosts_path": self.trust(bastion), "role_account_id": proxy_role["id"],
        })
        connection = self.store.save("connections", {
            "name": "NETCONF through bastion", "protocol": "netconf", "host": device.host, "port": device.port,
            "timeout_seconds": 3, "known_hosts_path": self.trust(device),
            "role_account_id": device_role["id"], "proxy_id": proxy["id"],
        })
        profile = self.store.resolve_connection(connection["id"])
        self.assertEqual(profile["authentication_type"], "ssh_key")
        self.assertEqual(profile["connector"]["authentication_type"], "password")
        result = run_connection_test(profile, demo_mode=True)
        self.assertTrue(result["success"], result)
        self.assertIn("key_authenticated", device.events)
        self.assertIn("password_authenticated", bastion.events)
        self.assertIn("client_hello", device.events)
        public = json.dumps([connection, proxy, device_role, proxy_role, result])
        for secret in (private_key, "role-key-passphrase", "bastion-role-password"):
            self.assertNotIn(secret, public)

    def test_batch_snapshot_remains_usable_after_shared_proxy_and_role_edits(self):
        device = self.start(TelnetPeer())
        proxy_peer = self.start(HttpConnectPeer(username="proxy", password="proxy-role-password"))
        device_role = self.role("Device password", "device", "device-password")
        proxy_role = self.role("Proxy password", "proxy", "proxy-role-password")
        proxy = self.store.save("proxies", {
            "name": "Saved HTTP proxy", "type": "http_connect", "host": proxy_peer.host, "port": proxy_peer.port,
            "role_account_id": proxy_role["id"],
        })
        connection = self.store.save("connections", {
            "name": "Snapshotted Telnet login", "protocol": "telnet", "host": device.host, "port": device.port,
            "timeout_seconds": 3, "role_account_id": device_role["id"], "proxy_id": proxy["id"],
        })
        job = self.store.create_job([connection["id"]])
        self.store.save("role_accounts", {"password": "replacement-password"}, proxy_role["id"])
        self.store.save("proxies", {"host": "192.0.2.1"}, proxy["id"])
        latest = run_connection_test(self.store.resolve_connection(connection["id"]), demo_mode=True)
        self.assertFalse(latest["success"])
        self.assertEqual(latest["stage"], "demo_policy")
        [(connection_id, snapshot)] = self.store.get_job_connections(job["id"])
        self.assertEqual(connection_id, connection["id"])
        result = run_connection_test(snapshot, demo_mode=True)
        self.assertTrue(result["success"], result)
        self.assertEqual(snapshot["connector"]["host"], "127.0.0.1")
        self.assertEqual(snapshot["connector"]["password"], "proxy-role-password")
        self.assertNotIn("proxy-role-password", json.dumps(self.store.get_job(job["id"])))

    def test_bootstrap_configured_local_demo_storage_allows_its_trust_file_only(self):
        device = self.start(SSHPeer(paramiko.ECDSAKey.generate()))
        trust_file = self.directory / "known_hosts"
        trust_file.write_text(
            f"[127.0.0.1]:{device.port} {device.host_key.get_name()} {device.host_key.get_base64()}\n",
            encoding="utf-8",
        )
        profile = {
            "protocol": "ssh", "host": device.host, "port": device.port,
            "username": "device", "password": "device-password",
            "known_hosts_path": str(trust_file), "timeout_seconds": 3,
        }
        with patch.dict(os.environ, {"GATEWAY_DEMO_STORAGE_DIR": ""}):
            self.assertEqual(run_connection_test(profile, demo_mode=True)["stage"], "demo_policy")
        with patch.dict(os.environ, {"GATEWAY_DEMO_STORAGE_DIR": str(self.directory)}):
            result = run_connection_test(profile, demo_mode=True)
            self.assertTrue(result["success"], result)
            blocked = {**profile, "private_key_path": str(self.directory / "private_key")}
            self.assertEqual(run_connection_test(blocked, demo_mode=True)["stage"], "demo_policy")
        for root in ("relative-storage", "\\\\remote.invalid\\share"):
            with self.subTest(root=root), patch.dict(os.environ, {"GATEWAY_DEMO_STORAGE_DIR": root}):
                self.assertEqual(run_connection_test(profile, demo_mode=True)["stage"], "demo_policy")


if __name__ == "__main__":
    unittest.main()
