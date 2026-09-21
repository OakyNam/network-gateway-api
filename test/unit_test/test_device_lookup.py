"""Exercise metadata lookup and API dispatch without external connections."""

import asyncio
import json
import unittest
from unittest.mock import patch

from fastapi import FastAPI
from cryptography.fernet import Fernet
from sqlalchemy import Column, MetaData, String, Table, create_engine, delete, event, update
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.dal.db import db_client
from app.common.errors import ClientMappingError, ConfigNotFoundError, DatabaseError, ProxyMappingError
from app.common.identity import AuthenticatedUser, current_user
from app.bl.factories import client_factory, proxy_factory
from app.dal.db.storage import configurations
from app.dal.db.store import GatewayStore
from app.routes import router
from test.fixtures.fake_client import FakeDeviceClient


CLIENT_CLASS = "app.dal.device.nccclient_ios.IOSNCCClient"


class TrackingSession(Session):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.closed = False

    def close(self):
        try:
            super().close()
        finally:
            self.closed = True


async def get_response(app, path):
    """Call ASGI directly, without a server, sockets, or optional HTTP clients."""
    messages = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        messages.append(message)

    await app(
        {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": path,
            "raw_path": path.encode(),
            "query_string": b"",
            "headers": [],
            "client": ("offline", 1),
            "server": ("offline", 80),
            "root_path": "",
        },
        receive,
        send,
    )
    status = next(m["status"] for m in messages if m["type"] == "http.response.start")
    body = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
    return status, json.loads(body)


class DeviceLookupTests(unittest.TestCase):
    def setUp(self):
        # Windows initializes an internal socketpair for event-loop wakeups.
        # Create it before blocking application network connections.
        self.loop = asyncio.new_event_loop()
        self.addCleanup(self.loop.close)
        # Fail closed if a regression tries to initialize the production engine
        # or open a network connection instead of using the injected local engine.
        self.start_patch(
            patch("socket.socket.connect", side_effect=AssertionError("Network forbidden"))
        )
        self.start_patch(
            patch("socket.create_connection", side_effect=AssertionError("Network forbidden"))
        )
        self.start_patch(
            patch.object(
                db_client, "create_engine",
                side_effect=AssertionError("Production engine forbidden"),
            )
        )
        self.engine = create_engine(
            "sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False}
        )
        self.addCleanup(self.engine.dispose)
        metadata = MetaData()
        self.inventory = Table(
            "inventory", metadata,
            Column("device_name", String),
            Column("vendor", String),
            Column("software", String),
            Column("mgmt_ip", String),
            Column("custom_metadata", String),
        )
        metadata.create_all(self.engine)
        self.expected = {
            "device_name": "edge-1",
            "vendor": "test-vendor",
            "software": "1.0",
            "mgmt_ip": "192.0.2.1",
            "custom_metadata": "retained",
        }
        with self.engine.begin() as connection:
            connection.execute(self.inventory.insert(), self.expected)
        self.sessions = []
        factory = sessionmaker(bind=self.engine, class_=TrackingSession)

        def new_session():
            session = factory()
            self.sessions.append(session)
            return session

        self.start_patch(patch.object(db_client, "_session_factory", new_session))
        self.store = GatewayStore(sqlite_path=":memory:", secret_key=Fernet.generate_key())
        self.addCleanup(self.store.close)
        self.store.save_config("device_lookup", {"table": "inventory", "search_column": "device_name"})
        self.store.save_config("client_mapping", {"key_columns": ["vendor", "software"],
                                                  "map": {"test-vendor:*": CLIENT_CLASS}})
        self.store.save_config("proxy_mapping", {"key_columns": ["owner"], "map": {}})
        for module in (db_client, client_factory, proxy_factory):
            self.start_patch(patch.object(module, "get_store", return_value=self.store))
        self.start_patch(patch(CLIENT_CLASS, FakeDeviceClient))
        FakeDeviceClient.instances.clear()

    def start_patch(self, patcher):
        result = patcher.start()
        self.addCleanup(patcher.stop)
        return result

    def test_lookup_returns_all_metadata_and_closes_session(self):
        self.assertEqual(db_client.get_device_info("edge-1"), self.expected)
        self.assertEqual(len(self.sessions), 1)
        self.assertTrue(self.sessions[0].closed)

    def test_missing_device_returns_none_and_closes_session(self):
        self.assertIsNone(db_client.get_device_info("missing"))
        self.assertTrue(self.sessions[0].closed)

    def test_each_lookup_uses_a_fresh_session(self):
        db_client.get_device_info("edge-1")
        db_client.get_device_info("edge-1")
        self.assertEqual(len(self.sessions), 2)
        self.assertIsNot(self.sessions[0], self.sessions[1])
        self.assertTrue(all(session.closed for session in self.sessions))

    def test_database_failure_closes_session_and_next_lookup_recovers(self):
        with patch.object(TrackingSession, "execute", side_effect=RuntimeError("offline failure")):
            with self.assertRaises(DatabaseError):
                db_client.get_device_info("edge-1")
        self.assertTrue(self.sessions[0].closed)
        self.assertEqual(db_client.get_device_info("edge-1"), self.expected)
        self.assertEqual(len(self.sessions), 2)
        self.assertTrue(self.sessions[1].closed)

    def test_search_value_is_bound_and_not_interpolated(self):
        value = "edge-1' OR 1=1 --"
        statements = []

        def capture(connection, cursor, statement, parameters, context, executemany):
            statements.append((statement, parameters))

        event.listen(self.engine, "before_cursor_execute", capture)
        self.assertIsNone(db_client.get_device_info(value))
        statement, parameters = statements[-1]
        self.assertNotIn(value, statement)
        self.assertIn(value, parameters)
        self.assertEqual(db_client.get_device_info("edge-1"), self.expected)

    def test_invalid_identifiers_fail_before_session_creation(self):
        for field in ("table", "search_column"):
            for value in ("inventory; DROP TABLE inventory", "", None, "none", 42):
                with self.subTest(field=field, value=value):
                    cfg = {"table": "inventory", "search_column": "device_name"}
                    cfg[field] = value
                    with self.store.engine.begin() as connection:
                        connection.execute(update(configurations).where(
                            configurations.c.name == "device_lookup").values(payload=cfg))
                    with self.assertRaises(ConfigNotFoundError):
                        db_client.get_device_info("edge-1")
        self.assertEqual(self.sessions, [])

    def test_missing_config_fails_before_session_creation(self):
        with self.store.engine.begin() as connection:
            connection.execute(delete(configurations).where(configurations.c.name == "device_lookup"))
        with self.assertRaises(ConfigNotFoundError):
            db_client.get_device_info("edge-1")
        self.assertEqual(self.sessions, [])

    def test_query_compiles_for_postgresql_with_wildcard_and_bound_value(self):
        statements = []

        def capture(connection, clause, multiparams, params, execution_options):
            statements.append(clause)

        event.listen(self.engine, "before_execute", capture)
        db_client.get_device_info("edge-1")
        compiled = statements[-1].compile(dialect=postgresql.dialect())
        self.assertIn("SELECT *", str(compiled))
        self.assertIn("inventory.device_name = %(search_value)s", str(compiled))
        self.assertNotIn("edge-1", str(compiled))
        self.assertIn("LIMIT", str(compiled))

    def test_configured_reserved_identifiers_are_quoted(self):
        metadata = MetaData()
        custom = Table(
            "Order", metadata, Column("select", String), Column("metadata", String)
        )
        metadata.create_all(self.engine)
        with self.engine.begin() as connection:
            connection.execute(custom.insert(), {"select": "edge-2", "metadata": "custom"})
        self.store.save_config("device_lookup", {"table": "Order", "search_column": "select"})
        self.assertEqual(
            db_client.get_device_info("edge-2"),
            {"select": "edge-2", "metadata": "custom"},
        )

    def test_config_is_reloaded_for_each_lookup(self):
        self.assertEqual(db_client.get_device_info("edge-1"), self.expected)
        self.store.save_config("device_lookup", {"table": "inventory", "search_column": "mgmt_ip"})
        self.assertEqual(db_client.get_device_info("192.0.2.1"), self.expected)

    def test_client_mapping_updates_are_read_fresh(self):
        client_factory.NCCClientFactory.get_client("edge-1")
        self.store.save_config("client_mapping", {"key_columns": ["vendor"], "map": {"other-vendor": CLIENT_CLASS}})
        with self.assertRaises(ClientMappingError):
            client_factory.NCCClientFactory.get_client("edge-1")
        self.store.save_config("client_mapping", {"key_columns": ["vendor"], "map": {"default": CLIENT_CLASS}})
        client_factory.NCCClientFactory.get_client("edge-1")
        self.assertEqual(len(FakeDeviceClient.instances), 2)

    def test_missing_and_invalid_client_mapping_fail_without_import_fallback(self):
        for invalid in (None, {"key_columns": ["vendor"], "map": {"default": "os.system"}}):
            with self.store.engine.begin() as connection:
                if invalid is None:
                    connection.execute(delete(configurations).where(configurations.c.name == "client_mapping"))
                else:
                    connection.execute(configurations.insert().values(name="client_mapping", payload=invalid))
            with self.assertRaises(ClientMappingError):
                client_factory.NCCClientFactory.get_client("edge-1")
        self.assertEqual(FakeDeviceClient.instances, [])

    def test_proxy_mapping_is_fresh_and_explicit_direct_overrides_default(self):
        self.store.save_config("proxy_mapping", {"key_columns": ["owner", "site"],
                                                "map": {"team:*": "bastion-one", "default": "bastion-default"}})
        with patch.object(proxy_factory, "ProxyClient") as proxy_class:
            proxy_factory.ProxyFactory.get_proxy({"owner": "TEAM", "site": "west"})
            proxy_class.assert_called_with("bastion-one")
            self.store.save_config("proxy_mapping", {"key_columns": ["owner"],
                                                    "map": {"team": "bastion-two", "default": "bastion-default"}})
            proxy_factory.ProxyFactory.get_proxy({"owner": "team"})
            proxy_class.assert_called_with("bastion-two")
            self.store.save_config("proxy_mapping", {"key_columns": ["owner"],
                                                    "map": {"team": None, "default": "bastion-default"}})
            self.assertIsNone(proxy_factory.ProxyFactory.get_proxy({"owner": "team"}))
            self.assertEqual(proxy_class.call_count, 2)

    def test_missing_or_invalid_proxy_map_does_not_fall_back_to_direct(self):
        with self.store.engine.begin() as connection:
            connection.execute(delete(configurations).where(configurations.c.name == "proxy_mapping"))
        with self.assertRaises(ProxyMappingError):
            proxy_factory.ProxyFactory.get_proxy(self.expected)
        with self.store.engine.begin() as connection:
            connection.execute(configurations.insert().values(name="proxy_mapping", payload={
                "key_columns": ["owner"], "map": {"default": {"password": "not-allowed"}},
            }))
        with self.assertRaises(ProxyMappingError):
            proxy_factory.ProxyFactory.get_proxy(self.expected)

    def test_api_config_dispatch_and_response_compatibility(self):
        app = FastAPI()
        app.include_router(router)
        app.dependency_overrides[current_user] = lambda: AuthenticatedUser(
            subject="test-viewer", tenant_id=None, name="Test Viewer", email=None,
            roles=frozenset({"Viewer"}), auth_mode="demo",
        )
        for path in ("/devices/edge-1/config", "/routers/edge-1/get-config"):
            with self.subTest(path=path):
                status, body = self.loop.run_until_complete(get_response(app, path))
                self.assertEqual(status, 200)
                self.assertEqual(body, {"config": "<config/>"})
                client = FakeDeviceClient.instances[-1]
                self.assertEqual(client.host, "192.0.2.1")
                self.assertEqual(client.router_info, self.expected)
        self.assertTrue(FakeDeviceClient.instances[0].cleaned_up)
        self.assertTrue(all(session.closed for session in self.sessions))

    def test_api_missing_device_remains_404_without_client_creation(self):
        app = FastAPI()
        app.include_router(router)
        app.dependency_overrides[current_user] = lambda: AuthenticatedUser(
            subject="test-viewer", tenant_id=None, name="Test Viewer", email=None,
            roles=frozenset({"Viewer"}), auth_mode="demo",
        )
        for path in ("/devices/missing/config", "/routers/missing/get-config"):
            with self.subTest(path=path):
                status, body = self.loop.run_until_complete(get_response(app, path))
                self.assertEqual(status, 404)
                self.assertEqual(body, {"detail": "Device not found: missing"})
        self.assertEqual(FakeDeviceClient.instances, [])
        self.assertTrue(all(session.closed for session in self.sessions))


if __name__ == "__main__":
    unittest.main()
