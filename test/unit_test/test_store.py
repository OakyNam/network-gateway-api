import json
import shutil
import threading
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from sqlalchemy import create_mock_engine, insert, select
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.schema import CreateTable

from app.dal.db.secrets import SecretError, SecretVault
from app.dal.db.storage import configurations, configured_url, connections, jobs, metadata, role_accounts
from app.dal.db.store import GatewayStore, StoreError


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(__file__).resolve().parents[2] / ".cache" / ("store-tests-" + uuid.uuid4().hex)
        self.directory.mkdir(parents=True)
        self.path = self.directory / "inventory.sqlite"
        self.key = Fernet.generate_key()
        self.store = GatewayStore(sqlite_path=self.path, secret_key=self.key)

    def tearDown(self):
        self.store.close()
        shutil.rmtree(self.directory)

    def role(self, **overrides):
        return self.store.save("role_accounts", {
            "name": "Operator", "username": "operator", "authentication_type": "password",
            "password": "store-test-password-unmistakable", **overrides,
        })

    def device(self, **overrides):
        return self.store.save("connections", {
            "name": "Router", "protocol": "ssh", "host": "127.0.0.1", "port": 22,
            "username": "operator", "password": "device-unique-password", **overrides,
        })

    def proxy(self, **overrides):
        return self.store.save("proxies", {
            "name": "Bastion", "type": "ssh_tunnel", "host": "localhost", "port": 2222,
            "username": "bastion", "password": "proxy-unique-password", **overrides,
        })

    @staticmethod
    def private_key(password=None, openssh=False):
        key = ed25519.Ed25519PrivateKey.generate() if openssh else rsa.generate_private_key(65537, 2048)
        encryption = serialization.BestAvailableEncryption(password.encode()) if password else serialization.NoEncryption()
        return key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.OpenSSH if openssh else serialization.PrivateFormat.PKCS8,
            encryption,
        ).decode()

    def assert_error(self, status, operation):
        with self.assertRaises(StoreError) as error:
            operation()
        self.assertEqual(error.exception.status_code, status)
        return str(error.exception)

    def test_role_password_is_encrypted_and_public_is_redacted(self):
        role = self.role()
        self.assertEqual(set(role), {"id", "name", "username", "authentication_type",
                                     "password_configured", "private_key_configured"})
        self.assertTrue(role["password_configured"])
        self.assertNotIn("password", role)
        with self.store.engine.connect() as db:
            encrypted = db.execute(select(role_accounts.c.secrets)).scalar_one()
        self.assertNotIn("store-test-password", encrypted)
        self.assertEqual(SecretVault(self.key).decrypt(encrypted)["password"], "store-test-password-unmistakable")
        self.assertNotIn(b"store-test-password", self.path.read_bytes())

    def test_private_key_encryption_and_same_method_omission(self):
        key = self.private_key("passphrase-unique")
        role = self.role(authentication_type="ssh_key", password="", private_key=key,
                         key_passphrase="passphrase-unique")
        updated = self.store.save("role_accounts", {"name": "Renamed"}, role["id"])
        self.assertTrue(updated["private_key_configured"])
        device = self.device(role_account_id=role["id"], username="", password="")
        private = self.store.resolve_connection(device["id"])
        self.assertEqual(private["private_key"], key)
        self.assertEqual(private["key_passphrase"], "passphrase-unique")
        self.assertNotIn(b"BEGIN PRIVATE KEY", self.path.read_bytes())
        self.assertNotIn(b"BEGIN ENCRYPTED PRIVATE KEY", self.path.read_bytes())
        self.assertNotIn(b"passphrase-unique", self.path.read_bytes())
        self.assertNotIn("private_key", json.dumps(self.store.list("connections")))

    def test_openssh_ed25519_key_supported(self):
        role = self.role(authentication_type="ssh_key", password="", private_key=self.private_key(openssh=True))
        self.assertTrue(role["private_key_configured"])

    def test_only_ssh_supported_ecdsa_curves_are_accepted(self):
        for curve in (ec.SECP256R1(), ec.SECP384R1(), ec.SECP521R1(), ec.SECP256K1()):
            key = ec.generate_private_key(curve).private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ).decode()
            create = lambda: self.role(authentication_type="ssh_key", password="", private_key=key)
            if isinstance(curve, ec.SECP256K1):
                message = self.assert_error(400, create)
                self.assertNotIn(key, message)
            else:
                self.assertTrue(create()["private_key_configured"])

    def test_invalid_keys_and_passphrase_errors_never_echo_input(self):
        for key, passphrase in (("PRIVATE_INVALID_SECRET", "KEY_PASSPHRASE"),
                                (self.private_key("actual"), "WRONG_PASSPHRASE")):
            message = self.assert_error(400, lambda: self.role(
                authentication_type="ssh_key", password="", private_key=key, key_passphrase=passphrase))
            self.assertNotIn(key, message)
            self.assertNotIn(passphrase, message)
        self.assertEqual(self.store.list("role_accounts"), [])

    def test_role_switch_requires_new_secret_and_clears_obsolete(self):
        role = self.role()
        self.assert_error(400, lambda: self.store.save("role_accounts", {"authentication_type": "ssh_key"}, role["id"]))
        self.assertTrue(self.store.get("role_accounts", role["id"])["password_configured"])
        key = self.private_key()
        updated = self.store.save("role_accounts", {"authentication_type": "ssh_key", "private_key": key}, role["id"])
        self.assertFalse(updated["password_configured"])
        self.assert_error(400, lambda: self.store.save("role_accounts", {"authentication_type": "password"}, role["id"]))
        updated = self.store.save("role_accounts", {"authentication_type": "password", "password": "new"}, role["id"])
        self.assertFalse(updated["private_key_configured"])
        with self.store.engine.connect() as db:
            secrets = self.store._vault.decrypt(db.execute(select(role_accounts.c.secrets)).scalar_one())
        self.assertEqual(secrets, {"password": "new"})

    def test_conflicting_role_credentials_rejected_atomically(self):
        role = self.role()
        self.assert_error(400, lambda: self.store.save(
            "role_accounts", {"password": "new", "private_key": "a-key"}, role["id"]))
        device = self.device(role_account_id=role["id"], username="", password="")
        self.assertEqual(self.store.resolve_connection(device["id"])["password"], "store-test-password-unmistakable")

    def test_omitted_inline_password_preserved_and_explicit_empty_clears(self):
        device = self.device()
        self.store.save("connections", {"name": "Changed"}, device["id"])
        self.assertEqual(self.store.resolve_connection(device["id"])["password"], "device-unique-password")
        result = self.store.save("connections", {"password": ""}, device["id"])
        self.assertFalse(result["password_configured"])
        self.assertNotIn("password", self.store.resolve_connection(device["id"]))

    def test_nullable_paths_match_ui_payload_and_explicit_null_clears(self):
        device = self.device(private_key_path=None, known_hosts_path=None)
        self.assertTrue(device["password_configured"])
        self.store.save("connections", {"known_hosts_path": "trust-file"}, device["id"])
        self.store.save("connections", {"known_hosts_path": None}, device["id"])
        self.assertNotIn("known_hosts_path", self.store.resolve_connection(device["id"]))
        proxy = self.proxy(password="", private_key_path="key-file", known_hosts_path="trust-file")
        cleared = self.store.save("proxies", {"private_key_path": None, "known_hosts_path": None}, proxy["id"])
        self.assertNotIn("private_key_path", cleared)
        self.assertNotIn("known_hosts_path", cleared)
        role = self.role()
        linked = self.device(role_account_id=role["id"], username="", password="",
                             private_key_path=None, known_hosts_path=None)
        self.assertTrue(linked["password_configured"])

    def test_inline_connector_nullable_paths_clear_existing_paths(self):
        device = self.device(connector={"type": "ssh_tunnel", "host": "localhost", "port": 22,
                                        "private_key_path": "key-file", "known_hosts_path": "trust-file"})
        self.store.save("connections", {"connector": {"private_key_path": None, "known_hosts_path": None}}, device["id"])
        connector = self.store.resolve_connection(device["id"])["connector"]
        self.assertNotIn("private_key_path", connector)
        self.assertNotIn("known_hosts_path", connector)

    def test_omitted_role_password_preserved(self):
        role = self.role()
        result = self.store.save("role_accounts", {"username": "new-operator"}, role["id"])
        self.assertTrue(result["password_configured"])
        self.assert_error(400, lambda: self.store.save("role_accounts", {"password": ""}, role["id"]))

    def test_role_and_proxy_update_propagate_to_devices(self):
        role = self.role()
        proxy = self.proxy(role_account_id=role["id"], username="", password="")
        device = self.device(proxy_id=proxy["id"], role_account_id=role["id"], username="", password="")
        self.store.save("role_accounts", {"username": "updated", "password": "updated-secret"}, role["id"])
        self.store.save("proxies", {"host": "127.0.0.2", "port": 2022}, proxy["id"])
        runtime = self.store.resolve_connection(device["id"])
        self.assertEqual(runtime["password"], "updated-secret")
        self.assertEqual(runtime["connector"]["password"], "updated-secret")
        self.assertEqual(runtime["connector"]["host"], "127.0.0.2")
        self.assertEqual(runtime["connector"]["port"], 2022)
        self.assertEqual(runtime["username"], "updated")
        self.assertNotIn("updated-secret", json.dumps(self.store.get("connections", device["id"])))

    def test_selecting_role_clears_obsolete_inline_credentials(self):
        device = self.device(private_key_path="", known_hosts_path="known-hosts")
        role = self.role()
        self.store.save("connections", {"role_account_id": role["id"]}, device["id"])
        with self.store.engine.connect() as db:
            row = db.execute(select(connections)).mappings().one()
        self.assertEqual(self.store._vault.decrypt(row["secrets"]), {})
        self.assertNotIn("username", row["configuration"])
        self.assertEqual(row["configuration"]["known_hosts_path"], "known-hosts")
        self.assert_error(400, lambda: self.store.save("connections", {"password": "conflict"}, device["id"]))

    def test_saved_proxy_conflicts_with_inline_connector(self):
        proxy = self.proxy()
        self.assert_error(400, lambda: self.device(proxy_id=proxy["id"], connector={"type": "direct"}))
        device = self.device(connector={"type": "socks5", "host": "localhost", "port": 1080, "password": "inline-secret"})
        self.store.save("connections", {"proxy_id": proxy["id"]}, device["id"])
        self.assertNotIn("inline-secret", json.dumps(self.store.resolve_connection(device["id"])))
        self.store.save("connections", {"proxy_id": None, "connector": {"type": "direct"}}, device["id"])
        self.assertEqual(self.store.resolve_connection(device["id"])["connector"], {"type": "direct"})

    def test_inline_connector_secret_preserved_and_encrypted(self):
        device = self.device(connector={"type": "socks5", "host": "localhost", "port": 1080, "password": "inline-proxy-secret"})
        self.store.save("connections", {"connector": {"host": "127.0.0.2"}}, device["id"])
        self.assertEqual(self.store.resolve_connection(device["id"])["connector"]["password"], "inline-proxy-secret")
        self.assertNotIn("inline-proxy-secret", json.dumps(self.store.get("connections", device["id"])))
        self.assertNotIn(b"inline-proxy-secret", self.path.read_bytes())

    def test_proxy_password_omission_and_explicit_clear(self):
        proxy = self.proxy()
        self.store.save("proxies", {"name": "Renamed"}, proxy["id"])
        device = self.device(proxy_id=proxy["id"])
        self.assertEqual(self.store.resolve_connection(device["id"])["connector"]["password"], "proxy-unique-password")
        self.assertNotIn(b"proxy-unique-password", self.path.read_bytes())
        result = self.store.save("proxies", {"password": ""}, proxy["id"])
        self.assertFalse(result["password_configured"])
        self.assertNotIn("password", self.store.resolve_connection(device["id"])["connector"])

    def test_reference_deletion_and_missing_reference(self):
        role = self.role()
        proxy = self.proxy(role_account_id=role["id"], username="", password="")
        device = self.device(proxy_id=proxy["id"])
        self.assert_error(409, lambda: self.store.delete("role_accounts", role["id"]))
        self.assert_error(409, lambda: self.store.delete("proxies", proxy["id"]))
        self.assert_error(404, lambda: self.device(role_account_id="missing", username="", password=""))
        self.store.delete("connections", device["id"])
        self.store.delete("proxies", proxy["id"])
        self.store.delete("role_accounts", role["id"])
        self.assertEqual(self.store.list("role_accounts"), [])

    def test_device_role_reference_prevents_deletion(self):
        role = self.role()
        self.device(role_account_id=role["id"], username="", password="")
        self.assert_error(409, lambda: self.store.delete("role_accounts", role["id"]))

    def test_failed_update_is_atomic(self):
        device = self.device()
        self.assert_error(404, lambda: self.store.save("connections", {
            "name": "Must not persist", "role_account_id": "missing"}, device["id"]))
        self.assertEqual(self.store.get("connections", device["id"])["name"], "Router")
        self.assertEqual(self.store.resolve_connection(device["id"])["password"], "device-unique-password")

    def test_validation_and_missing_resource(self):
        for patch_values in ({"port": 0}, {"port": True}, {"port": 65536},
                             {"protocol": "smtp"}, {"timeout_seconds": 31}, {"host": ""},
                             {"password": "p", "private_key_path": "key"}, {"unknown": "secret"}):
            self.assert_error(400, lambda: self.device(**patch_values))
        for resource in ("connections", "proxies", "role_accounts"):
            self.assert_error(404, lambda: self.store.get(resource, "missing"))
            self.assert_error(404, lambda: self.store.delete(resource, "missing"))
        self.assert_error(404, lambda: self.store.list("missing"))

    def test_database_enforces_foreign_keys_and_port_constraints(self):
        device = self.device()
        from sqlalchemy import update
        for values in ({"role_account_id": "missing"}, {"port": 0}, {"timeout_seconds": 50}):
            with self.assertRaises(IntegrityError):
                with self.store.engine.begin() as db:
                    db.execute(update(connections).where(connections.c.id == device["id"]).values(**values))

    def test_job_snapshot_is_immutable_and_persistent(self):
        role = self.role()
        proxy = self.proxy(role_account_id=role["id"], username="", password="")
        device = self.device(role_account_id=role["id"], username="", password="", proxy_id=proxy["id"])
        job = self.store.create_job([device["id"]])
        self.store.save("role_accounts", {"password": "changed-after-snapshot"}, role["id"])
        self.store.save("proxies", {"host": "127.0.0.2"}, proxy["id"])
        self.store.delete("connections", device["id"])
        self.store.close()
        self.store = GatewayStore(sqlite_path=self.path, secret_key=self.key)
        snapshot = self.store.get_job_connections(job["id"])[0][1]
        self.assertEqual(snapshot["password"], "store-test-password-unmistakable")
        self.assertEqual(snapshot["connector"]["host"], "localhost")
        result = self.store.get_job(job["id"])
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["error"], "Interrupted by gateway restart.")
        self.assertNotIn("store-test-password", json.dumps(result))
        self.assertNotIn(b"store-test-password", self.path.read_bytes())

    def test_job_results_and_errors_redacted_and_persisted(self):
        device = self.device()
        job = self.store.create_job([device["id"]])
        self.store.set_job_status(job["id"], "running")
        self.store.record_job_result(job["id"], {
            "connection_id": device["id"], "name": "bogus", "success": False,
            "detail": "Authentication failed: device-unique-password", "stage": "auth",
            "duration_ms": 1.5, "password": "device-unique-password",
        })
        self.store.set_job_status(job["id"], "failed", "failure device-unique-password")
        public = self.store.get_job(job["id"])
        self.assertNotIn("device-unique-password", json.dumps(public))
        self.assertEqual(public["results"][0]["name"], "Router")
        self.assertEqual(public["completed"], 1)
        self.store.close()
        self.store = GatewayStore(sqlite_path=self.path, secret_key=self.key)
        self.assertEqual(self.store.get_job(job["id"]), public)

    def test_restart_retains_partial_results_and_releases_active_slot(self):
        first = self.device()
        second = self.device(name="Other")
        job = self.store.create_job([first["id"], second["id"]])
        self.store.set_job_status(job["id"], "running")
        self.store.record_job_result(job["id"], {"connection_id": first["id"], "success": True})
        self.store.close()
        self.store = GatewayStore(sqlite_path=self.path, secret_key=self.key)
        interrupted = self.store.get_job(job["id"])
        self.assertEqual(interrupted["status"], "failed")
        self.assertEqual(interrupted["completed"], 1)
        self.assertEqual(interrupted["total"], 2)
        self.assertEqual(len(interrupted["results"]), 1)
        self.assertEqual(self.store.create_job([second["id"]])["status"], "queued")

    def test_job_completion_and_duplicate_result_guards(self):
        device = self.device()
        job = self.store.create_job([device["id"]])
        self.assert_error(409, lambda: self.store.create_job([device["id"]]))
        self.store.set_job_status(job["id"], "running")
        self.assert_error(409, lambda: self.store.set_job_status(job["id"], "completed"))
        self.assert_error(400, lambda: self.store.record_job_result(job["id"], {"connection_id": "wrong", "success": True}))
        result = {"connection_id": device["id"], "success": True, "detail": "Connected", "stage": "complete"}
        self.store.record_job_result(job["id"], result)
        self.assert_error(409, lambda: self.store.record_job_result(job["id"], result))
        self.store.set_job_status(job["id"], "completed")
        self.assert_error(409, lambda: self.store.set_job_status(job["id"], "running"))
        self.assert_error(409, lambda: self.store.record_job_result(job["id"], result))
        self.assertEqual(self.store.create_job([device["id"]])["status"], "queued")

    def test_job_invalid_selection_and_progress_inputs(self):
        device = self.device()
        for ids in ([], "id", [device["id"], device["id"]], [None]):
            self.assert_error(400, lambda: self.store.create_job(ids))
        job = self.store.create_job([device["id"]])
        self.assert_error(400, lambda: self.store.record_job_result(job["id"], {
            "connection_id": device["id"], "success": True, "duration_ms": float("nan")}))
        self.assert_error(400, lambda: self.store.record_job_result(job["id"], {
            "connection_id": device["id"], "success": "yes"}))
        self.assertEqual(self.store.get_job(job["id"])["completed"], 0)

    def test_one_active_job_concurrent_stores(self):
        second = GatewayStore(sqlite_path=self.path, secret_key=self.key)
        self.addCleanup(second.close)
        device = self.device()
        barrier = threading.Barrier(2)
        outcomes = []

        def create(store):
            barrier.wait()
            try:
                outcomes.append(store.create_job([device["id"]])["status"])
            except StoreError as exc:
                outcomes.append(exc.status_code)
        workers = [threading.Thread(target=create, args=(store,)) for store in (self.store, second)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(10)
            self.assertFalse(worker.is_alive())
        self.assertCountEqual(outcomes, ["queued", 409])
        second.close()

    def test_wrong_key_refuses_startup_without_destroying_data(self):
        device = self.device()
        self.store.close()
        message = self.assert_error(503, lambda: GatewayStore(sqlite_path=self.path, secret_key=Fernet.generate_key()))
        self.assertNotIn("device-unique-password", message)
        self.store = GatewayStore(sqlite_path=self.path, secret_key=self.key)
        self.assertEqual(self.store.resolve_connection(device["id"])["password"], "device-unique-password")

    def test_configurable_path_and_non_destructive_initialization(self):
        device = self.device()
        self.store.close()
        self.store = GatewayStore(database_url="sqlite+pysqlite:///" + self.path.as_posix(), secret_key=self.key)
        self.assertEqual(self.store.get("connections", device["id"])["name"], "Router")
        nested = self.directory / "nested" / "other.db"
        store = GatewayStore(sqlite_path=nested, secret_key=self.key)
        store.close()
        self.assertTrue(nested.exists())

    def test_configuration_errors_are_safe_and_defaults_lazy(self):
        import app.dal.db.store as module
        with patch.dict("os.environ", {}, clear=True):
            self.assert_error(503, lambda: GatewayStore())
            self.assert_error(503, lambda: GatewayStore(secret_key=self.key))
            with patch.object(module, "_default_store", None):
                self.assert_error(503, module.get_store)
        message = self.assert_error(503, lambda: GatewayStore(
            database_url="invalid://user:db-password@host/db", secret_key=self.key))
        self.assertNotIn("db-password", message)
        self.assert_error(503, lambda: GatewayStore(sqlite_path=":memory:", secret_key="bad"))
        self.assert_error(503, lambda: configured_url("sqlite:///:memory:", ":memory:"))

    def test_explicit_configuration_ignores_unrelated_environment(self):
        with patch.dict("os.environ", {"GATEWAY_DATABASE_URL": "postgresql://unused:secret@invalid/db"}):
            store = GatewayStore(sqlite_path=":memory:", secret_key=self.key)
            self.assertEqual(store.list("connections"), [])
            store.close()

    def test_environment_configuration_and_lazy_singleton(self):
        import app.dal.db.store as module
        with patch.dict("os.environ", {
            "GATEWAY_SQLITE_PATH": str(self.directory / "environment.db"),
            "GATEWAY_SECRET_KEY": self.key.decode(),
        }, clear=True), patch.object(module, "_default_store", None):
            first = module.get_store()
            self.assertIs(module.get_store(), first)
            first.close()
            replacement = module.get_store()
            self.assertIsNot(replacement, first)
            replacement.close()

    def test_encryption_rejects_tampering(self):
        vault = SecretVault(self.key)
        encrypted = vault.encrypt({"password": "secret"})
        with self.assertRaises(SecretError):
            vault.decrypt(encrypted[:-4] + "AAAA")

    def test_closed_store_is_unavailable(self):
        self.store.close()
        self.assert_error(503, lambda: self.store.list("connections"))

    def test_database_exception_details_are_not_exposed(self):
        failure = OperationalError("SELECT secret_sql", {"password": "parameter-secret"},
                                   RuntimeError("postgresql://user:database-secret@host/db"))
        with patch.object(self.store.engine, "begin", side_effect=failure):
            message = self.assert_error(503, lambda: self.store.list("connections"))
        self.assertEqual(message, "Gateway database operation failed.")
        for secret in ("secret_sql", "parameter-secret", "database-secret"):
            self.assertNotIn(secret, message)

    def test_configuration_upserts_are_fresh_and_persistent(self):
        initial = {"table": "inventory", "search_column": "name"}
        self.assertEqual(self.store.save_config("device_lookup", initial), initial)
        self.assertEqual(self.store.get_config("device_lookup"), initial)
        updated = {"table": "devices", "search_column": "hostname"}
        self.store.save_config("device_lookup", updated)
        self.assertEqual(self.store.get_config("device_lookup"), updated)
        self.store.close()
        self.store = GatewayStore(sqlite_path=self.path, secret_key=self.key)
        self.assertEqual(self.store.get_config("device_lookup"), updated)

    def test_configuration_validation_and_missing_names(self):
        self.assert_error(404, lambda: self.store.get_config("device_lookup"))
        self.assert_error(404, lambda: self.store.get_config("unrecognized"))
        self.assert_error(404, lambda: self.store.save_config("unrecognized", {}))
        invalid = [
            ("device_lookup", {"table": "inventory;DROP TABLE inventory", "search_column": "name"}),
            ("device_lookup", {"table": "inventory", "search_column": "none"}),
            ("device_lookup", {"table": "inventory", "search_column": "name", "password": "secret"}),
            ("client_mapping", {"key_columns": ["vendor"], "map": {"default": "os.system"}}),
            ("client_mapping", {"key_columns": [], "map": {"default": "app.dal.device.nccclient_ios.IOSNCCClient"}}),
            ("client_mapping", {"key_columns": ["vendor"], "map": {}}),
            ("proxy_mapping", {"key_columns": ["owner"], "map": {"default": {"password": "secret"}}}),
            ("proxy_mapping", {"key_columns": ["owner"], "map": {"default": "user:secret@host"}}),
            ("proxy_mapping", {"key_columns": ["owner", "owner"], "map": {}}),
        ]
        for name, payload in invalid:
            with self.subTest(name=name, payload=payload):
                self.assert_error(400, lambda: self.store.save_config(name, payload))
        self.assert_error(404, lambda: self.store.get_config("device_lookup"))

    def test_configuration_client_allowlist_and_explicit_direct_proxy(self):
        from app.dal.db.store import CLIENT_CLASSES
        for client in CLIENT_CLASSES:
            config = {"key_columns": ["vendor"], "map": {"default": client}}
            self.assertEqual(self.store.save_config("client_mapping", config), config)
        for mapping in ({}, {"team": None, "default": "127.0.0.1"}):
            config = {"key_columns": ["owner"], "map": mapping}
            self.assertEqual(self.store.save_config("proxy_mapping", config), config)

    def test_corrupt_configuration_read_is_validated_without_echoing_input(self):
        with self.store.engine.begin() as db:
            db.execute(configurations.insert().values(name="proxy_mapping", payload={
                "key_columns": ["owner"], "map": {"default": "user:secret-password@host"},
            }))
        message = self.assert_error(400, lambda: self.store.get_config("proxy_mapping"))
        self.assertNotIn("secret-password", message)


class StorePostgreSQLCompilationTests(unittest.TestCase):
    def test_all_schema_ddl_compiles_offline_for_postgresql_and_sqlite(self):
        for dialect in (postgresql.dialect(), sqlite.dialect()):
            statements = [str(CreateTable(table).compile(dialect=dialect)) for table in metadata.sorted_tables]
            self.assertEqual(len(statements), 8)
            self.assertIn("FOREIGN KEY", "\n".join(statements))
            self.assertIn("one_active_gateway_job", "\n".join(statements))
            self.assertIn("job_active_slot", "\n".join(statements))

    def test_postgresql_create_all_and_lock_sql_compile_without_connection(self):
        statements = []
        engine = create_mock_engine("postgresql+psycopg2://", lambda sql, *args, **kwargs: statements.append(
            str(sql.compile(dialect=postgresql.dialect()))))
        metadata.create_all(engine)
        self.assertEqual(len(statements), 13)
        sql = str(select(connections).with_for_update().compile(dialect=postgresql.dialect()))
        self.assertIn("FOR UPDATE", sql)
        sql = str(insert(jobs).values(id="test", status="queued", total=1, completed=0,
                                      snapshot="encrypted", results=[], active_slot=1).compile(dialect=postgresql.dialect()))
        self.assertIn("INSERT INTO gateway_jobs", sql)
        self.assertEqual(configured_url("postgresql://user:password@localhost/database").get_backend_name(), "postgresql")
        from sqlalchemy.dialects.postgresql import insert as pg_insert
        statement = pg_insert(configurations).values(
            name="device_lookup", payload={"table": "inventory", "search_column": "name"})
        statement = statement.on_conflict_do_update(
            index_elements=[configurations.c.name], set_={"payload": statement.excluded.payload})
        self.assertIn("ON CONFLICT", str(statement.compile(dialect=postgresql.dialect())))


if __name__ == "__main__":
    unittest.main()
