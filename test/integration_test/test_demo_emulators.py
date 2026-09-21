"""End-to-end offline tests for the demo loopback protocol emulators.

Everything here binds to 127.0.0.1 only and uses fake, demo-only credentials.
Each transport is exercised through the real, unmodified gateway client
classes (JuniperNCCClient / IOSNCCClient / GenericTelnetNCCClient) talking to
a real local server, not a mocked client object.
"""

import os
import socket
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import paramiko

from app.dal.device.nccclient_ios import IOSNCCClient
from app.dal.device.nccclient_juniper import JuniperNCCClient
from app.dal.device.telnet_client import GenericTelnetNCCClient
from app.dal.db import db_client
from app.common.errors import GatewayError
from demo import demo_config, run_demo
from demo.emulators.netconf_emulator import NetconfEmulator
from demo.emulators.ssh_emulator import SSHEmulator
from demo.emulators.telnet_emulator import TelnetEmulator
from demo.env_safety import DemoSafetyError, validate_demo_environment
from demo.seed_demo_db import DEVICES_TABLE, seed

USERNAME = "demo-fake-user"
PASSWORD = "demo-fake-pass"
WRONG_PASSWORD = "not-the-password"


def _generate_key() -> paramiko.PKey:
    return paramiko.ECDSAKey.generate()


def _use_isolated_mappings(test):
    from cryptography.fernet import Fernet
    from app.dal.db.store import GatewayStore
    from demo.management_seed import seed_demo_settings

    store = GatewayStore(sqlite_path=":memory:", secret_key=Fernet.generate_key())
    test.addCleanup(store.close)
    seed_demo_settings(store)
    replacement = patch("app.bl.factories.proxy_factory.get_store", return_value=store)
    replacement.start()
    test.addCleanup(replacement.stop)


class NetconfEmulatorTests(unittest.TestCase):
    """Real NETCONF-over-SSH hello/RPC exchange via JuniperNCCClient."""

    def setUp(self):
        _use_isolated_mappings(self)
        self.tmp_dir_ctx = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp_dir_ctx.cleanup)
        self.tmp_dir = self.tmp_dir_ctx.name
        self.key = _generate_key()
        self.emulator = NetconfEmulator(
            demo_config.LOOPBACK_HOST, 0, self.key, USERNAME, PASSWORD
        )
        self.emulator.start()
        self.addCleanup(self.emulator.stop)

        known_hosts_path = os.path.join(self.tmp_dir, "known_hosts")
        with open(known_hosts_path, "w", encoding="utf-8") as fh:
            fh.write(
                f"[{demo_config.LOOPBACK_HOST}]:{self.emulator.port} "
                f"{self.key.get_name()} {self.key.get_base64()}\n"
            )
        ssh_config_path = os.path.join(self.tmp_dir, "ssh_config")
        with open(ssh_config_path, "w", encoding="utf-8") as fh:
            fh.write(f"Host {demo_config.LOOPBACK_HOST}\n    UserKnownHostsFile {known_hosts_path}\n")

        self.env_patch = patch.dict(
            os.environ,
            {
                "ROUTER_NETCONF_HOSTKEY_VERIFY": "true",
                "ROUTER_SSH_CONFIG_PATH": ssh_config_path,
                "ROUTER_CONNECT_TIMEOUT": "5",
            },
        )
        self.env_patch.start()
        self.addCleanup(self.env_patch.stop)

    def _router_info(self, password=PASSWORD):
        return {
            "netconf_port": self.emulator.port,
            "username": USERNAME,
            "password": password,
        }

    def test_get_config_round_trip_and_cleanup(self):
        client = JuniperNCCClient(demo_config.LOOPBACK_HOST, self._router_info())
        self.assertEqual(client.port, self.emulator.port)  # custom port honored
        try:
            xml = client.get_config()
            self.assertIn("simulated", xml)
            self.assertIsNotNone(client.session)
        finally:
            client.cleanup()
        self.assertIsNone(client.session)

    def test_authentication_failure_raises_gateway_error(self):
        client = JuniperNCCClient(demo_config.LOOPBACK_HOST, self._router_info(WRONG_PASSWORD))
        with self.assertRaises(GatewayError):
            client.get_config()
        client.cleanup()


class SSHEmulatorTests(unittest.TestCase):
    """Real SSH exec_command transport via IOSNCCClient."""

    def setUp(self):
        _use_isolated_mappings(self)
        self.tmp_dir_ctx = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp_dir_ctx.cleanup)
        self.tmp_dir = self.tmp_dir_ctx.name
        self.key = _generate_key()
        self.emulator = SSHEmulator(demo_config.LOOPBACK_HOST, 0, self.key, USERNAME, PASSWORD)
        self.emulator.start()
        self.addCleanup(self.emulator.stop)

        known_hosts_path = os.path.join(self.tmp_dir, "known_hosts")
        with open(known_hosts_path, "w", encoding="utf-8") as fh:
            fh.write(
                f"[{demo_config.LOOPBACK_HOST}]:{self.emulator.port} "
                f"{self.key.get_name()} {self.key.get_base64()}\n"
            )
        self.env_patch = patch.dict(
            os.environ,
            {"ROUTER_KNOWN_HOSTS_PATH": known_hosts_path, "ROUTER_CONNECT_TIMEOUT": "5"},
        )
        self.env_patch.start()
        self.addCleanup(self.env_patch.stop)

    def _router_info(self, password=PASSWORD):
        return {"ssh_port": self.emulator.port, "username": USERNAME, "password": password}

    def test_show_interface_round_trip_and_cleanup(self):
        client = IOSNCCClient(demo_config.LOOPBACK_HOST, self._router_info())
        self.assertEqual(client.ssh_port, self.emulator.port)  # custom port honored
        try:
            result = client.show_interface()
            self.assertIn("SIMULATED", result["output"])
        finally:
            client.cleanup()
        self.assertIsNone(client.ssh_client)

    def test_authentication_failure_raises_gateway_error(self):
        client = IOSNCCClient(demo_config.LOOPBACK_HOST, self._router_info(WRONG_PASSWORD))
        with self.assertRaises(GatewayError):
            client.show_interface()
        client.cleanup()


class TelnetEmulatorTests(unittest.TestCase):
    """Generic simulated Telnet login via GenericTelnetNCCClient."""

    def setUp(self):
        self.emulator = TelnetEmulator(demo_config.LOOPBACK_HOST, 0, USERNAME, PASSWORD)
        self.emulator.start()
        self.addCleanup(self.emulator.stop)

    def _router_info(self, password=PASSWORD):
        return {"telnet_port": self.emulator.port, "username": USERNAME, "password": password}

    def test_show_interface_round_trip_and_cleanup(self):
        client = GenericTelnetNCCClient(demo_config.LOOPBACK_HOST, self._router_info())
        self.assertEqual(client.port, self.emulator.port)  # custom port honored
        try:
            result = client.show_interface()
            self.assertIn("SIMULATED", result["output"])
        finally:
            client.cleanup()
        self.assertIsNone(client._sock)

    def test_authentication_failure_raises_gateway_error(self):
        client = GenericTelnetNCCClient(demo_config.LOOPBACK_HOST, self._router_info(WRONG_PASSWORD))
        with self.assertRaises(GatewayError):
            client.show_interface()
        client.cleanup()

    def test_unsupported_operations_fail_explicitly(self):
        client = GenericTelnetNCCClient(demo_config.LOOPBACK_HOST, self._router_info())
        try:
            with self.assertRaises(GatewayError):
                client.get_config()
            with self.assertRaises(GatewayError):
                client.set_bgp("<x/>")
        finally:
            client.cleanup()


class SqliteSeedReopenTests(unittest.TestCase):
    """SQLite demo backend: seed/init, reopen persistence, upsert safety."""

    def setUp(self):
        self.tmp_dir_ctx = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp_dir_ctx.cleanup)
        self.tmp_dir = self.tmp_dir_ctx.name
        self.db_path = os.path.join(self.tmp_dir, "demo_devices_test.sqlite3")
        self.env_patch = patch.dict(
            os.environ, {"DB_BACKEND": "sqlite", "DB_SQLITE_PATH": self.db_path}
        )
        self.env_patch.start()
        self.addCleanup(self.env_patch.stop)

        self._orig_engine = db_client._engine
        self._orig_factory = db_client._session_factory
        db_client._engine = None
        db_client._session_factory = None
        self.addCleanup(self._restore_singleton)

    def _restore_singleton(self):
        if db_client._engine is not None:
            db_client._engine.dispose()
        db_client._engine = self._orig_engine
        db_client._session_factory = self._orig_factory

    def _reset_engine(self):
        db_client._engine.dispose()
        db_client._engine = None
        db_client._session_factory = None

    def test_seed_is_idempotent_and_reopen_preserves_extra_rows(self):
        count = seed(demo_config.DEMO_DEVICES)
        self.assertEqual(count, 3)

        # Reopen the same file with a fresh engine/session (simulates process restart).
        self._reset_engine()
        engine = db_client.get_engine()
        with engine.begin() as connection:
            connection.execute(
                DEVICES_TABLE.insert(),
                {"hostname": "user-added-device", "vendor": "custom", "protocol": "ssh"},
            )
        self._reset_engine()

        # Re-running seed must not duplicate or wipe the user-added row.
        count2 = seed(demo_config.DEMO_DEVICES)
        self.assertEqual(count2, 3)

        engine = db_client.get_engine()
        with engine.connect() as connection:
            rows = connection.execute(DEVICES_TABLE.select()).fetchall()
        hostnames = {row.hostname for row in rows}
        self.assertIn("user-added-device", hostnames)
        for device in demo_config.DEMO_DEVICES:
            self.assertIn(device["hostname"], hostnames)
        self.assertEqual(len(rows), 4)

    def test_get_device_info_returns_custom_port_and_protocol(self):
        from cryptography.fernet import Fernet
        from app.dal.db.store import GatewayStore
        from demo.management_seed import seed_demo_settings

        seed(demo_config.DEMO_DEVICES)
        store = GatewayStore(sqlite_path=":memory:", secret_key=Fernet.generate_key())
        self.addCleanup(store.close)
        seed_demo_settings(store)
        with patch.object(db_client, "get_store", return_value=store):
            info = db_client.get_device_info("demo-router-netconf")
        self.assertIsNotNone(info)
        self.assertEqual(info["protocol"], "netconf")
        self.assertEqual(info["netconf_port"], demo_config.NETCONF_EMULATOR_PORT)
        self.assertEqual(info["username"], demo_config.DEMO_USERNAME)

    def test_seed_preserves_existing_edits_unless_reset(self):
        """A re-seed must not clobber a user's edit to an already-seeded
        demo row - only `reset=True` may restore canonical values."""
        seed(demo_config.DEMO_DEVICES)

        engine = db_client.get_engine()
        with engine.begin() as connection:
            connection.execute(
                DEVICES_TABLE.update()
                .where(DEVICES_TABLE.c.hostname == "demo-router-ssh")
                .values(notes="user-edited-note", ssh_port=19999)
            )

        # Default (non-reset) re-seed: the edit must survive.
        seed(demo_config.DEMO_DEVICES)
        with engine.connect() as connection:
            row = connection.execute(
                DEVICES_TABLE.select().where(DEVICES_TABLE.c.hostname == "demo-router-ssh")
            ).fetchone()
        self.assertEqual(row.notes, "user-edited-note")
        self.assertEqual(row.ssh_port, 19999)

        # Explicit reset: canonical demo values are restored.
        seed(demo_config.DEMO_DEVICES, reset=True)
        with engine.connect() as connection:
            row = connection.execute(
                DEVICES_TABLE.select().where(DEVICES_TABLE.c.hostname == "demo-router-ssh")
            ).fetchone()
        self.assertEqual(row.ssh_port, demo_config.SSH_EMULATOR_PORT)
        self.assertNotEqual(row.notes, "user-edited-note")

    def test_seed_rejects_non_sqlite_backend_before_engine_creation(self):
        """An inherited, non-demo DB_BACKEND must abort before any engine
        or session is created - never silently mutate another backend."""
        with patch.dict(os.environ, {"DB_BACKEND": "postgresql"}):
            with patch.object(db_client, "get_engine", MagicMock()) as mock_get_engine:
                with self.assertRaises(DemoSafetyError):
                    seed(demo_config.DEMO_DEVICES)
                mock_get_engine.assert_not_called()


class ValidateDemoEnvironmentTests(unittest.TestCase):
    """`validate_demo_environment` must fail closed on any inherited,
    non-demo environment value instead of silently using it."""

    def _valid_env(self):
        return {
            "DB_BACKEND": "sqlite",
            "DB_SQLITE_PATH": str(demo_config.SQLITE_PATH),
            "GATEWAY_DEVICE_DATA_PROVIDER": "fake",
        }

    def test_valid_demo_environment_passes(self):
        with patch.dict(os.environ, self._valid_env(), clear=False):
            validate_demo_environment()  # must not raise

    def test_rejects_inherited_non_sqlite_backend(self):
        env = self._valid_env()
        env["DB_BACKEND"] = "postgresql"
        with patch.dict(os.environ, env, clear=False):
            with self.assertRaises(DemoSafetyError):
                validate_demo_environment()

    def test_rejects_sqlite_path_outside_demo_data_dir(self):
        env = self._valid_env()
        with tempfile.TemporaryDirectory() as tmp_dir:
            env["DB_SQLITE_PATH"] = os.path.join(tmp_dir, "not_demo.sqlite3")
            with patch.dict(os.environ, env, clear=False):
                with self.assertRaises(DemoSafetyError):
                    validate_demo_environment()

    def test_rejects_inherited_production_client_config_path(self):
        env = self._valid_env()
        env["CLIENT_CONFIG_PATH"] = str(
            demo_config.DEMO_ROOT.parent / "config" / "client_config.json"
        )
        with patch.dict(os.environ, env, clear=False):
            with self.assertRaises(DemoSafetyError):
                validate_demo_environment()

    def test_rejects_all_obsolete_json_mapping_overrides(self):
        for name in ("CLIENT_CONFIG_PATH", "PROXY_CONFIG_PATH", "DB_CLIENT_CONFIG_PATH"):
            with self.subTest(variable=name):
                with patch.dict(os.environ, {**self._valid_env(), name: ""}, clear=True):
                    with self.assertRaises(DemoSafetyError):
                        validate_demo_environment()


class _FakeEmulator:
    """Lightweight stand-in used only to test `_start_emulators` rollback
    semantics without needing three real sockets per test case."""

    def __init__(self, fail: bool = False):
        self.fail = fail
        self.started = False
        self.stopped = False

    def start(self):
        if self.fail:
            raise OSError("simulated: address already in use")
        self.started = True

    def stop(self):
        self.stopped = True


class StartEmulatorsCleanupTests(unittest.TestCase):
    """`run_demo._start_emulators` must roll back (stop) every emulator that
    already started if a later one fails, and must not leak a real bound
    socket on the failing emulator itself."""

    def test_partial_failure_stops_already_started_emulators(self):
        first = _FakeEmulator()
        second = _FakeEmulator()
        failing = _FakeEmulator(fail=True)

        with self.assertRaises(OSError):
            run_demo._start_emulators([first, second, failing])

        self.assertTrue(first.started)
        self.assertTrue(second.started)
        self.assertTrue(first.stopped)
        self.assertTrue(second.stopped)
        # The emulator that never started successfully has nothing to stop;
        # `_start_emulators` must not call .stop() on it (it was never
        # appended to the "started" list).
        self.assertFalse(failing.stopped)

    def test_occupied_port_start_failure_cleans_up_and_frees_the_port(self):
        """Exercise the real SSHEmulator/NetconfEmulator socket-level
        cleanup: binding a second emulator to an already-occupied port must
        raise, must not leak the failing listener socket, and must stop the
        first (already-started) real emulator."""
        occupier = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            # On Windows, SO_REUSEADDR alone does not make two binds to the
            # same host:port actually conflict; SO_EXCLUSIVEADDRUSE forces a
            # genuine "address already in use" failure for the second bind,
            # matching real occupied-port behavior being tested here.
            occupier.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        else:
            occupier.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        occupier.bind((demo_config.LOOPBACK_HOST, 0))
        occupier.listen(1)
        occupied_port = occupier.getsockname()[1]
        self.addCleanup(occupier.close)

        key = _generate_key()
        first = SSHEmulator(demo_config.LOOPBACK_HOST, 0, key, USERNAME, PASSWORD)
        second = NetconfEmulator(
            demo_config.LOOPBACK_HOST, occupied_port, key, USERNAME, PASSWORD
        )

        with self.assertRaises(OSError):
            run_demo._start_emulators([first, second])

        # The first emulator (already bound/started) must have been stopped.
        self.assertTrue(first._stop.is_set())
        # The failing emulator must not have leaked its (never-listening)
        # socket object.
        self.assertIsNone(second._listener)


if __name__ == "__main__":
    unittest.main()
