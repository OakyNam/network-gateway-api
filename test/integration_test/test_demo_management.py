"""Persistent isolated demo bootstrap and cleanup regression tests."""

import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from starlette.datastructures import State

from app.dal.db.store import GatewayStore, StoreError
from demo import demo_config, run_demo
from demo.emulators.hostkeys import ensure_bastion_trust_files, ensure_demo_trust_files
from demo.env_safety import DemoSafetyError, prepare_demo_environment
from demo.management_seed import configure_management_key, seed_demo_settings, seed_management


class DemoManagementTests(unittest.TestCase):
    def setUp(self):
        cache = demo_config.DEMO_ROOT.parent / ".cache"
        cache.mkdir(exist_ok=True)
        directory = tempfile.TemporaryDirectory(prefix="demo-management-", dir=cache)
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.environment = patch.dict(os.environ, {}, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def test_conflicting_environment_aborts_before_mutation_or_construction(self):
        conflicts = (
            {"DB_BACKEND": "postgresql"},
            {"DB_HOST": "production.invalid"},
            {"GATEWAY_DATABASE_URL": "postgresql://production.invalid/db"},
            {"GATEWAY_SQLITE_PATH": str(self.directory / "ambient.sqlite3")},
            {"GATEWAY_SECRET_KEY": "inherited-key"},
            {"DB_SQLITE_PATH": str(self.directory / "ambient-legacy.sqlite3")},
            {"CLIENT_CONFIG_PATH": "config/client_config.example.json"},
            {"PROXY_CONFIG_PATH": ""},
            {"DB_CLIENT_CONFIG_PATH": "removed-demo-config.json"},
            {"ROUTER_KNOWN_HOSTS_PATH": str(self.directory / "ambient-trust")},
            {"GATEWAY_DEMO_MODE": "false"},
            {"GATEWAY_DEVICE_DATA_PROVIDER": "disabled"},
            {"GATEWAY_DEVICE_DATA_PROVIDER": ""},
            {"GATEWAY_DEVICE_DATA_PROVIDER": "invalid-sensitive-value"},
        )
        for environment in conflicts:
            with self.subTest(environment=list(environment)), patch.dict(os.environ, environment, clear=True):
                with patch("sqlalchemy.create_engine") as engine, patch("socket.socket") as socket:
                    with patch.object(Path, "mkdir") as mkdir, patch.object(Path, "write_text") as write:
                        with patch("app.dal.db.store.GatewayStore") as constructor:
                            with self.assertRaises(DemoSafetyError):
                                run_demo.main(["--storage-dir", str(self.directory)])
                            constructor.assert_not_called()
                    mkdir.assert_not_called()
                    write.assert_not_called()
                engine.assert_not_called()
                socket.assert_not_called()
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_explicit_storage_directory_is_selected_without_writes(self):
        destination = self.directory / "explicit"
        self.assertEqual(prepare_demo_environment(destination), destination)
        self.assertEqual(os.environ["GATEWAY_SQLITE_PATH"], str(destination / "gateway.sqlite3"))
        self.assertEqual(os.environ["DB_SQLITE_PATH"], str(destination / "demo_devices.sqlite3"))
        self.assertEqual(os.environ["GATEWAY_DEMO_MODE"], "true")
        self.assertEqual(os.environ["GATEWAY_DEVICE_DATA_PROVIDER"], "fake")
        self.assertFalse(destination.exists())

    def test_invalid_provider_is_sanitized_and_not_overwritten(self):
        value = "invalid-sensitive-value"
        with patch.dict(os.environ, {"GATEWAY_DEVICE_DATA_PROVIDER": value}, clear=True):
            with self.assertRaises(DemoSafetyError) as raised:
                prepare_demo_environment(self.directory)
            self.assertNotIn(value, str(raised.exception))
            self.assertEqual(os.environ["GATEWAY_DEVICE_DATA_PROVIDER"], value)
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_network_storage_directory_is_rejected_before_writes(self):
        with patch.object(Path, "mkdir") as mkdir, patch.object(Path, "write_text") as write:
            with self.assertRaises(DemoSafetyError):
                prepare_demo_environment(Path(r"\\remote-server\share\demo"))
        mkdir.assert_not_called()
        write.assert_not_called()

    def test_seed_reopen_preserves_renames_edits_and_encrypted_credentials(self):
        prepare_demo_environment(self.directory)
        key = configure_management_key(self.directory)
        store = GatewayStore()
        try:
            self.assertEqual(seed_management(store, self.directory), {"role_accounts": 4, "proxies": 5, "connections": 8})
            connection = store.list("connections")[0]
            store.save("connections", {"name": "My renamed device", "port": 19999}, connection["id"])
            role = store.list("role_accounts")[0]
            store.save("role_accounts", {"name": "My edited role", "password": "changed-demo-password"}, role["id"])
        finally:
            store.close()
        self.assertEqual(configure_management_key(self.directory), key)
        store = GatewayStore()
        try:
            self.assertEqual(seed_management(store, self.directory), {"role_accounts": 4, "proxies": 5, "connections": 8})
            self.assertEqual(store.get("connections", connection["id"])["name"], "My renamed device")
            self.assertEqual(store.get("connections", connection["id"])["port"], 19999)
            self.assertEqual(store.get("role_accounts", role["id"])["name"], "My edited role")
        finally:
            store.close()
        database = (self.directory / "gateway.sqlite3").read_bytes()
        for secret in (
            demo_config.DEMO_PASSWORD, demo_config.BASTION_PASSWORD, "changed-demo-password",
            "fake-device-password", "fake-proxy-password",
        ):
            self.assertNotIn(secret.encode(), database)

    def test_existing_database_without_original_key_fails_closed(self):
        (self.directory / "gateway.sqlite3").write_bytes(b"existing database")
        with self.assertRaises(DemoSafetyError):
            configure_management_key(self.directory)
        self.assertFalse((self.directory / "gateway.key").exists())

    def test_seeded_fake_graph_resolves_real_database_roles_without_sockets(self):
        from app.dal.device.fake_client import FakeDeviceClient, test_fake_connection

        prepare_demo_environment(self.directory)
        configure_management_key(self.directory)
        with patch("socket.socket", side_effect=AssertionError("Fake graph opened a socket")) as socket:
            with patch("socket.getaddrinfo", side_effect=AssertionError("Fake graph resolved DNS")) as dns:
                store = GatewayStore()
                try:
                    seed_management(store, self.directory)
                    profile = next(row for row in store.list("connections") if row["client_type"] == "fake")
                    device_role = store.get("role_accounts", profile["role_account_id"])
                    proxy = store.get("proxies", profile["proxy_id"])
                    proxy_role = store.get("role_accounts", proxy["role_account_id"])
                    self.assertEqual(profile["name"], "Fake transport device")
                    self.assertEqual((profile["protocol"], profile["host"], profile["port"]),
                                     ("ssh", "fake-device.invalid", 22))
                    self.assertEqual((device_role["name"], device_role["username"]),
                                     ("Fake device login", "fake-device-user"))
                    self.assertEqual((proxy["name"], proxy["type"], proxy["host"], proxy["port"]),
                                     ("Fake bastion", "ssh_tunnel", "fake-bastion.invalid", 22))
                    self.assertEqual((proxy_role["name"], proxy_role["username"]),
                                     ("Fake proxy login", "fake-proxy-user"))
                    self.assertFalse(profile.get("known_hosts_path"))
                    self.assertFalse(proxy.get("known_hosts_path"))
                    resolved = store.resolve_connection(profile["id"])
                    self.assertEqual(resolved["password"], "fake-device-password")
                    self.assertEqual(resolved["connector"]["password"], "fake-proxy-password")
                    self.assertTrue(test_fake_connection(resolved)["success"])
                    self.assertTrue(test_fake_connection(resolved)["simulated"])
                    inventory = FakeDeviceClient(store, profile["id"]).inventory()
                    self.assertEqual(inventory["provider"], "fake")
                    self.assertTrue(inventory["simulated"])
                    self.assertEqual(inventory["access"], {
                        "role_account_id": device_role["id"], "proxy_id": proxy["id"],
                        "proxy_role_account_id": proxy_role["id"], "connector_type": "ssh_tunnel",
                    })
                finally:
                    store.close()
                store = GatewayStore()
                try:
                    seed_management(store, self.directory)
                    self.assertEqual(FakeDeviceClient(store, profile["id"]).inventory(), inventory)
                finally:
                    store.close()
            socket.assert_not_called()
            dns.assert_not_called()

    def test_fake_graph_edits_survive_restart_without_converting_network_profiles(self):
        prepare_demo_environment(self.directory)
        key = configure_management_key(self.directory)
        store = GatewayStore()
        try:
            seed_management(store, self.directory)
            profile = next(row for row in store.list("connections") if row["client_type"] == "fake")
            proxy = store.get("proxies", profile["proxy_id"])
            store.save("connections", {"name": "Edited fake device", "host": "edited-device.invalid"}, profile["id"])
            store.save("proxies", {"name": "Edited fake proxy", "host": "edited-proxy.invalid"}, proxy["id"])
            for role_id in (profile["role_account_id"], proxy["role_account_id"]):
                store.save("role_accounts", {
                    "name": f"Edited {role_id}", "password": f"changed-{role_id}",
                }, role_id)
        finally:
            store.close()
        self.assertEqual(configure_management_key(self.directory), key)
        store = GatewayStore()
        try:
            self.assertEqual(seed_management(store, self.directory), {
                "role_accounts": 4, "proxies": 5, "connections": 8,
            })
            resolved = store.resolve_connection(profile["id"])
            self.assertEqual((resolved["name"], resolved["host"]), ("Edited fake device", "edited-device.invalid"))
            self.assertEqual((resolved["connector"]["name"], resolved["connector"]["host"]),
                             ("Edited fake proxy", "edited-proxy.invalid"))
            self.assertEqual(resolved["password"], f"changed-{profile['role_account_id']}")
            self.assertEqual(resolved["connector"]["password"], f"changed-{proxy['role_account_id']}")
            network = [row for row in store.list("connections") if row["client_type"] == "network"]
            self.assertEqual(len(network), 7)
            self.assertTrue(all(row["host"] == "127.0.0.1" for row in network))
        finally:
            store.close()

    def test_fake_seed_name_does_not_convert_an_existing_network_profile(self):
        prepare_demo_environment(self.directory)
        configure_management_key(self.directory)
        store = GatewayStore()
        try:
            existing = store.save("connections", {
                "name": "Fake transport device", "protocol": "ssh",
                "host": "127.0.0.1", "port": 2222,
                "username": "operator", "password": "operator-password",
            })
            self.assertEqual(existing["client_type"], "network")
            seed_management(store, self.directory)
            retained = store.get("connections", existing["id"])
            self.assertEqual(retained["client_type"], "network")
            self.assertEqual((retained["host"], retained["port"]), ("127.0.0.1", 2222))
            self.assertIsNone(retained["proxy_id"])
            self.assertIsNone(retained["role_account_id"])
        finally:
            store.close()

    def test_fake_client_rejects_edited_persisted_credentials_and_destinations(self):
        from app.dal.device.fake_client import FakeDeviceClient, test_fake_connection

        prepare_demo_environment(self.directory)
        configure_management_key(self.directory)
        store = GatewayStore()
        self.addCleanup(store.close)
        seed_management(store, self.directory)
        profile = next(row for row in store.list("connections") if row["client_type"] == "fake")
        proxy = store.get("proxies", profile["proxy_id"])
        client = FakeDeviceClient(store, profile["id"])
        cases = (
            ("role_accounts", profile["role_account_id"],
             {"password": "wrong-device-password"}, {"password": "fake-device-password"}),
            ("role_accounts", proxy["role_account_id"],
             {"password": "wrong-proxy-password"}, {"password": "fake-proxy-password"}),
            ("proxies", proxy["id"], {"host": "changed-bastion.invalid"}, {"host": "fake-bastion.invalid"}),
            ("connections", profile["id"], {"proxy_id": None}, {"proxy_id": proxy["id"]}),
            ("connections", profile["id"], {"host": "changed-device.invalid"}, {"host": "fake-device.invalid"}),
        )
        with patch("socket.socket", side_effect=AssertionError("Fake graph opened a socket")) as socket:
            with patch("socket.getaddrinfo", side_effect=AssertionError("Fake graph resolved DNS")) as dns:
                for resource, item_id, edited, original in cases:
                    with self.subTest(resource=resource, fields=list(edited)):
                        store.save(resource, edited, item_id)
                        try:
                            with self.assertRaises(StoreError) as raised:
                                client.inventory()
                            self.assertEqual(raised.exception.status_code, 403)
                            result = test_fake_connection(store.resolve_connection(profile["id"]))
                            self.assertFalse(result["success"])
                            self.assertTrue(result["simulated"])
                        finally:
                            store.save(resource, original, item_id)
                        self.assertTrue(client.inventory()["simulated"])
            socket.assert_not_called()
            dns.assert_not_called()

    def test_database_mapping_edits_survive_reopen_and_reseed(self):
        prepare_demo_environment(self.directory)
        configure_management_key(self.directory)
        store = GatewayStore()
        try:
            seed_demo_settings(store)
            client_mapping = store.get_config("client_mapping")
            self.assertIn("demo-juniper:netconf", client_mapping["map"])
            edited = {"table": "my_inventory", "search_column": "my_hostname"}
            store.save_config("device_lookup", edited)
        finally:
            store.close()
        store = GatewayStore()
        try:
            seed_demo_settings(store)
            self.assertEqual(store.get_config("device_lookup"), edited)
            self.assertEqual(store.get_config("client_mapping"), client_mapping)
        finally:
            store.close()

    def test_standalone_seed_bootstraps_isolated_database_mappings(self):
        from demo.seed_demo_db import main

        main(["--storage-dir", str(self.directory)])
        self.assertTrue((self.directory / "demo_devices.sqlite3").is_file())
        store = GatewayStore()
        try:
            self.assertEqual(store.get_config("device_lookup"), {"table": "devices", "search_column": "hostname"})
            self.assertIn("demo-ios:ssh", store.get_config("client_mapping")["map"])
        finally:
            store.close()

    def test_standalone_seed_rejects_obsolete_override_before_writes(self):
        from demo.seed_demo_db import main

        with patch.dict(os.environ, {"DB_CLIENT_CONFIG_PATH": "old.json"}, clear=True):
            with patch("app.dal.db.store.GatewayStore") as constructor:
                with patch.object(Path, "mkdir") as mkdir:
                    with self.assertRaises(DemoSafetyError):
                        main(["--storage-dir", str(self.directory)])
                constructor.assert_not_called()
                mkdir.assert_not_called()
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_device_and_bastion_trust_are_independent_and_persistent(self):
        device_key = ensure_demo_trust_files(self.directory)
        bastion_key = ensure_bastion_trust_files(self.directory)
        self.assertNotEqual(device_key.get_base64(), bastion_key.get_base64())
        self.assertEqual(device_key, ensure_demo_trust_files(self.directory))
        self.assertEqual(bastion_key, ensure_bastion_trust_files(self.directory))
        self.assertIn(device_key.get_base64(), (self.directory / "demo_known_hosts").read_text())
        self.assertNotIn(bastion_key.get_base64(), (self.directory / "demo_known_hosts").read_text())
        self.assertIn(bastion_key.get_base64(), (self.directory / "demo_bastion_known_hosts").read_text())

    def test_failed_emulator_start_stops_every_previously_started_peer(self):
        peers = [MagicMock() for _ in range(7)]
        peers[-1].start.side_effect = OSError("occupied port")
        with self.assertRaises(OSError):
            run_demo._start_emulators(peers)
        for peer in peers[:-1]:
            peer.stop.assert_called_once_with()

    def test_application_start_failure_closes_peers_and_legacy_engine(self):
        from app.main import app

        peers = [MagicMock() for _ in range(7)]
        original_state = app.state
        original_demo_mode = app.state.demo_mode
        original_provider = getattr(app.state, "device_data_provider", None)

        def fail_start(app, **kwargs):
            self.assertTrue(app.state.demo_mode)
            self.assertEqual(app.state.device_data_provider, "fake")
            self.assertEqual(kwargs["host"], "127.0.0.1")
            raise RuntimeError("application startup failed")

        isolated_state = State({"demo_mode": False, "device_data_provider": "disabled"})
        with patch.object(app, "state", isolated_state):
            with patch.object(run_demo, "_build_emulators", return_value=peers):
                with patch("uvicorn.run", side_effect=fail_start):
                    with self.assertRaisesRegex(RuntimeError, "application startup failed"):
                        run_demo.main(["--storage-dir", str(self.directory)])
        self.assertIs(app.state, original_state)
        self.assertEqual(app.state.demo_mode, original_demo_mode)
        self.assertEqual(getattr(app.state, "device_data_provider", None), original_provider)
        for peer in peers:
            peer.start.assert_called_once_with()
            peer.stop.assert_called_once_with()
        from app.dal.db import db_client
        self.assertIsNone(db_client._engine)
        self.assertIsNone(db_client._session_factory)

    def test_all_eight_seeded_profiles_dispatch_through_management_service(self):
        from app.bl.services.management import ManagementService

        prepare_demo_environment(self.directory)
        configure_management_key(self.directory)
        device_key = ensure_demo_trust_files(self.directory)
        bastion_key = ensure_bastion_trust_files(self.directory)
        port_names = (
            "NETCONF_EMULATOR_PORT", "SSH_EMULATOR_PORT", "TELNET_EMULATOR_PORT",
            "SSH_TUNNEL_EMULATOR_PORT", "SSH_SHELL_EMULATOR_PORT",
            "SOCKS5_EMULATOR_PORT", "HTTP_CONNECT_EMULATOR_PORT",
        )
        with patch.multiple(demo_config, **dict.fromkeys(port_names, 0)):
            peers = run_demo._start_emulators(run_demo._build_emulators(device_key, bastion_key))
        try:
            ports = dict(zip(port_names, (peer.port for peer in peers)))
            with patch.multiple(demo_config, **ports):
                ensure_demo_trust_files(self.directory)
                ensure_bastion_trust_files(self.directory)
                store = GatewayStore()
                try:
                    seed_management(store, self.directory)
                    service = ManagementService(store, demo_mode=True, device_data_provider="fake")
                    profiles = store.list("connections")
                    network_profiles = [profile for profile in profiles if profile["client_type"] == "network"]
                    fake_profiles = [profile for profile in profiles if profile["client_type"] == "fake"]
                    self.assertEqual(len(profiles), 8)
                    self.assertEqual(len(network_profiles), 7)
                    self.assertEqual(len(fake_profiles), 1)
                    for profile in network_profiles:
                        with self.subTest(profile=profile["name"]):
                            result = service.test(profile["id"])
                            self.assertTrue(result["success"], result)
                            self.assertIs(result["simulated"], False)
                    with patch("socket.socket", side_effect=AssertionError("Fake graph opened a socket")) as socket:
                        with patch("socket.getaddrinfo", side_effect=AssertionError("Fake graph resolved DNS")) as dns:
                            result = service.test(fake_profiles[0]["id"])
                            self.assertTrue(result["success"], result)
                            self.assertIs(result["simulated"], True)
                        socket.assert_not_called()
                        dns.assert_not_called()
                finally:
                    store.close()
        finally:
            for peer in reversed(peers):
                peer.stop()


if __name__ == "__main__":
    unittest.main()
