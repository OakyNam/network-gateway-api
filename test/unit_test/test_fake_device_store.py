import csv
import io
import json
import shutil
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from cryptography.fernet import Fernet
from sqlalchemy import select, update
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.schema import CreateTable

from app.bl.services.batches import BatchService, EXPORT_FIELDS
from app.bl.services.management import ManagementService
from app.dal.db.storage import (
    connections, jobs, static_route_initializations, static_routes,
)
from app.dal.db.store import GatewayStore, StoreError
from app.dal.device.fake_client import (
    FAKE_CONNECTION_NAME, FAKE_DEVICE_HOST, FAKE_DEVICE_PASSWORD, FAKE_DEVICE_PORT,
    FAKE_DEVICE_PROTOCOL, FAKE_DEVICE_ROLE_NAME, FAKE_DEVICE_USERNAME, FAKE_PROXY_HOST,
    FAKE_PROXY_NAME, FAKE_PROXY_PASSWORD, FAKE_PROXY_PORT, FAKE_PROXY_ROLE_NAME,
    FAKE_PROXY_TYPE, FAKE_PROXY_USERNAME, FakeDeviceClient,
    test_fake_connection as check_fake_connection,
)


class FakeDeviceStoreTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(__file__).resolve().parents[2] / ".cache" / ("fake-store-" + uuid.uuid4().hex)
        self.directory.mkdir(parents=True)
        self.path = self.directory / "inventory.sqlite"
        self.key = Fernet.generate_key()
        self.store = GatewayStore(sqlite_path=self.path, secret_key=self.key)
        for target in ("socket.socket", "socket.create_connection", "socket.getaddrinfo"):
            guard = patch(target, side_effect=AssertionError("Fake data must not use networking"))
            self.addCleanup(guard.stop)
            guard.start()
        self.device_role = self.store.save("role_accounts", {
            "name": FAKE_DEVICE_ROLE_NAME, "authentication_type": "password",
            "username": FAKE_DEVICE_USERNAME, "password": FAKE_DEVICE_PASSWORD,
        })
        self.proxy_role = self.store.save("role_accounts", {
            "name": FAKE_PROXY_ROLE_NAME, "authentication_type": "password",
            "username": FAKE_PROXY_USERNAME, "password": FAKE_PROXY_PASSWORD,
        })
        self.proxy = self.store.save("proxies", {
            "name": FAKE_PROXY_NAME, "type": FAKE_PROXY_TYPE, "host": FAKE_PROXY_HOST,
            "port": FAKE_PROXY_PORT, "role_account_id": self.proxy_role["id"],
        })
        self.device = self.new_device()
        self.client = FakeDeviceClient(self.store, self.device["id"])

    def tearDown(self):
        self.store.close()
        shutil.rmtree(self.directory)

    def new_device(self, **overrides):
        return self.store.save("connections", {
            "name": FAKE_CONNECTION_NAME, "client_type": "fake", "protocol": FAKE_DEVICE_PROTOCOL,
            "host": FAKE_DEVICE_HOST, "port": FAKE_DEVICE_PORT,
            "role_account_id": self.device_role["id"], "proxy_id": self.proxy["id"], **overrides,
        })

    @staticmethod
    def route(**overrides):
        return {"destination": "203.0.113.0/24", "next_hop": "192.0.2.1",
                "interface": "eth0", "metric": 0, "description": "Custom simulated route",
                "enabled": True, **overrides}

    def assert_error(self, code, operation):
        with self.assertRaises(StoreError) as error:
            operation()
        self.assertEqual(error.exception.status_code, code)
        for password in (FAKE_DEVICE_PASSWORD, FAKE_PROXY_PASSWORD):
            self.assertNotIn(password, str(error.exception))

    def reopen(self):
        self.store.close()
        self.store = GatewayStore(sqlite_path=self.path, secret_key=self.key)
        self.client = FakeDeviceClient(self.store, self.device["id"])

    def test_inventory_resolves_full_real_graph_and_defensive_copies(self):
        inventory = self.client.inventory()
        self.assertEqual(set(inventory), {"provider", "simulated", "device", "access",
                                          "system", "interfaces", "bgp", "mpls"})
        self.assertEqual(inventory["provider"], "fake")
        self.assertIs(inventory["simulated"], True)
        self.assertEqual(inventory["access"], {
            "role_account_id": self.device_role["id"], "proxy_id": self.proxy["id"],
            "proxy_role_account_id": self.proxy_role["id"], "connector_type": FAKE_PROXY_TYPE,
        })
        self.assertEqual(set(inventory["device"]), {"id", "name", "protocol", "host", "port"})
        self.assertEqual(set(inventory["system"]), {
            "hostname", "model", "software_version", "serial_number", "uptime_seconds",
        })
        for interface in inventory["interfaces"]:
            self.assertEqual(set(interface), {"name", "description", "admin_status", "oper_status",
                                              "mtu", "mac_address", "addresses", "rx_bytes", "tx_bytes"})
        inventory["interfaces"][0]["addresses"].clear()
        inventory["bgp"]["neighbors"].clear()
        inventory["mpls"]["lsps"][0]["label"] = 999
        fresh = self.client.inventory()
        self.assertEqual(fresh["interfaces"][0]["addresses"], ["192.0.2.2/24"])
        self.assertEqual(len(fresh["bgp"]["neighbors"]), 1)
        self.assertEqual(fresh["mpls"]["lsps"][0]["label"], 16001)
        self.assertNotIn(FAKE_DEVICE_PASSWORD, json.dumps(fresh))
        self.assertNotIn(FAKE_PROXY_PASSWORD, json.dumps(fresh))
        self.store.save("connections", {"name": "Edited fake name"}, self.device["id"])
        self.assertEqual(self.client.inventory()["device"]["name"], "Edited fake name")
        self.assertTrue(check_fake_connection(self.store.resolve_connection(self.device["id"]))["success"])

    def test_role_and_proxy_mutations_reject_every_operation(self):
        route = self.client.create_static_route(self.route())
        mutations = (
            ("role_accounts", self.device_role["id"], {"password": "wrong-device-password"},
             {"password": FAKE_DEVICE_PASSWORD}),
            ("role_accounts", self.proxy_role["id"], {"password": "wrong-proxy-password"},
             {"password": FAKE_PROXY_PASSWORD}),
            ("role_accounts", self.device_role["id"], {"username": "wrong-device-user"},
             {"username": FAKE_DEVICE_USERNAME}),
            ("role_accounts", self.proxy_role["id"], {"username": "wrong-proxy-user"},
             {"username": FAKE_PROXY_USERNAME}),
            ("proxies", self.proxy["id"], {"host": "changed.invalid"}, {"host": FAKE_PROXY_HOST}),
            ("proxies", self.proxy["id"], {"port": 2222}, {"port": FAKE_PROXY_PORT}),
            ("proxies", self.proxy["id"], {"type": "ssh_shell"}, {"type": FAKE_PROXY_TYPE}),
            ("proxies", self.proxy["id"], {"role_account_id": self.device_role["id"]},
             {"role_account_id": self.proxy_role["id"]}),
            ("connections", self.device["id"], {"role_account_id": self.proxy_role["id"]},
             {"role_account_id": self.device_role["id"]}),
            ("connections", self.device["id"], {"host": "wrong.invalid"}, {"host": FAKE_DEVICE_HOST}),
            ("connections", self.device["id"], {"port": 2222}, {"port": FAKE_DEVICE_PORT}),
            ("connections", self.device["id"], {"protocol": "telnet"}, {"protocol": FAKE_DEVICE_PROTOCOL}),
            ("connections", self.device["id"], {"proxy_id": None}, {"proxy_id": self.proxy["id"]}),
        )
        for resource, item_id, change, restore in mutations:
            with self.subTest(resource=resource, change=change):
                self.store.save(resource, change, item_id)
                for operation in (
                    self.client.inventory, self.client.list_static_routes,
                    lambda: self.client.create_static_route(self.route(destination="192.0.2.0/24")),
                    lambda: self.client.update_static_route(route["id"], self.route(metric=100)),
                    lambda: self.client.delete_static_route(route["id"]),
                ):
                    self.assert_error(403, operation)
                result = check_fake_connection(self.store.resolve_connection(self.device["id"]))
                self.assertFalse(result["success"])
                self.assertTrue(result["simulated"])
                self.store.save(resource, restore, item_id)
                self.assertTrue(self.client.inventory()["simulated"])
        self.assertEqual(self.store.list_static_routes(self.device["id"])[-1]["metric"], route["metric"])

    def test_inline_credentials_and_connector_cannot_replace_references(self):
        inline_role = self.new_device(role_account_id=None, username=FAKE_DEVICE_USERNAME,
                                      password=FAKE_DEVICE_PASSWORD)
        self.assert_error(403, FakeDeviceClient(self.store, inline_role["id"]).inventory)
        inline_proxy = self.new_device(proxy_id=None, connector={
            "type": FAKE_PROXY_TYPE, "host": FAKE_PROXY_HOST, "port": FAKE_PROXY_PORT,
            "username": FAKE_PROXY_USERNAME, "password": FAKE_PROXY_PASSWORD,
        })
        self.assert_error(403, FakeDeviceClient(self.store, inline_proxy["id"]).inventory)
        self.store.save("proxies", {
            "role_account_id": None, "username": FAKE_PROXY_USERNAME, "password": FAKE_PROXY_PASSWORD,
        }, self.proxy["id"])
        self.assert_error(403, self.client.inventory)

    def test_client_type_default_validation_and_old_configuration_compatibility(self):
        for invalid in (None, "", "FAKE", "other", 1, True, [], {}):
            self.assert_error(400, lambda: self.new_device(client_type=invalid))
        network = self.new_device(client_type="network")
        defaulted = self.store.save("connections", {
            "name": "Default network device", "protocol": "ssh", "host": "192.0.2.100", "port": 22,
        })
        self.assertEqual(defaulted["client_type"], "network")
        self.assert_error(501, FakeDeviceClient(self.store, network["id"]).inventory)
        self.assert_error(501, lambda: self.store.list_static_routes(network["id"]))
        with self.store._transaction() as db:
            db.execute(update(connections).where(connections.c.id == network["id"]).values(configuration={}))
        self.assertEqual(self.store.get("connections", network["id"])["client_type"], "network")
        self.assertEqual(self.store.resolve_connection(network["id"])["client_type"], "network")
        updated = self.store.save("connections", {"name": "Name only"}, self.device["id"])
        self.assertEqual(updated["client_type"], "fake")
        self.reopen()
        self.assertEqual(self.store.get("connections", self.device["id"])["client_type"], "fake")
        self.assertEqual(self.store.get("connections", network["id"])["client_type"], "network")

    def test_route_crud_persistence_canonicalization_and_last_delete(self):
        seeds = self.client.list_static_routes()
        self.assertEqual(len(seeds), 2)
        route = self.client.create_static_route(self.route())
        self.assertEqual(set(route), {"id", "connection_id", *self.route()})
        ipv6 = self.client.create_static_route(self.route(
            destination="2001:0DB8:0003::/64", next_hop="2001:0DB8:0001::1", interface=None, metric=65535,
        ))
        self.assertEqual(ipv6["destination"], "2001:db8:3::/64")
        self.assertEqual(ipv6["next_hop"], "2001:db8:1::1")
        changed = self.client.update_static_route(seeds[0]["id"], self.route(
            destination=seeds[0]["destination"], next_hop=seeds[0]["next_hop"],
            description="Operator changed seed", enabled=False,
        ))
        self.reopen()
        rows = self.client.list_static_routes()
        self.assertIn(changed, rows)
        self.assertIn(route, rows)
        self.assertIn(ipv6, rows)
        rows[0]["description"] = "Response mutated"
        self.assertNotIn("Response mutated", json.dumps(self.client.list_static_routes()))
        for row in self.client.list_static_routes():
            self.client.delete_static_route(row["id"])
        self.assertEqual(self.client.list_static_routes(), [])
        self.reopen()
        self.assertEqual(self.client.list_static_routes(), [])
        self.assertEqual(self.client.create_static_route(self.route())["destination"], "203.0.113.0/24")
        self.assertEqual(len(self.client.list_static_routes()), 1)

    def test_duplicate_and_ownership_checks_are_atomic(self):
        route = self.client.create_static_route(self.route())
        self.assert_error(409, lambda: self.client.create_static_route(self.route()))
        alternate = self.client.create_static_route(self.route(destination="192.0.2.0/24"))
        self.assert_error(409, lambda: self.client.update_static_route(alternate["id"], self.route()))
        self.assertIn(alternate, self.client.list_static_routes())
        other = self.new_device(name="Independent device")
        other_client = FakeDeviceClient(self.store, other["id"])
        other_route = other_client.create_static_route(self.route())
        self.assertNotEqual(other_route["id"], route["id"])
        self.assert_error(404, lambda: other_client.update_static_route(route["id"], self.route()))
        self.assert_error(404, lambda: other_client.delete_static_route(route["id"]))
        self.assert_error(404, lambda: self.client.update_static_route("missing", self.route()))
        self.assert_error(404, lambda: self.client.delete_static_route("missing"))
        for operation in (
            lambda: self.store.list_static_routes("missing"),
            lambda: self.store.create_static_route("missing", self.route()),
            lambda: self.store.update_static_route("missing", route["id"], self.route()),
            lambda: self.store.delete_static_route("missing", route["id"]),
        ):
            self.assert_error(404, operation)
        self.assertIn(route, self.client.list_static_routes())
        self.assertIn(other_route, other_client.list_static_routes())
        ipv6 = self.route(destination="2001:db8:4::/64", next_hop="2001:db8:1::1")
        self.client.create_static_route(ipv6)
        self.assert_error(409, lambda: self.client.create_static_route({
            **ipv6, "destination": "2001:0DB8:0004::/64",
        }))

    def test_route_validation_is_enforced_by_store(self):
        route = self.client.create_static_route(self.route())
        cases = [
            {"destination": "192.0.2.1/24"}, {"destination": "2001:db8:5::1/64"},
            {"destination": "192.0.2.0"}, {"destination": "192.0.2.0/255.255.255.0"},
            {"destination": "192.0.2.0/33"}, {"destination": "not-a-network"},
            {"destination": True}, {"destination": None},
            {"destination": "fe80::%eth0/64"}, {"next_hop": "fe80::1%eth0"},
            {"next_hop": "bad-address"}, {"next_hop": "192.0.2.1/24"}, {"next_hop": 1},
            {"next_hop": "2001:db8::1"}, {"interface": "eth2"}, {"interface": []},
            {"metric": -1}, {"metric": 65536}, {"metric": True}, {"metric": 1.0},
            {"metric": "1"}, {"description": "x" * 201}, {"description": None},
            {"description": "bad\x00value"}, {"enabled": 1}, {"enabled": "true"},
        ]
        for invalid in cases:
            with self.subTest(invalid=invalid):
                for operation in (
                    lambda: self.store.create_static_route(self.device["id"], self.route(**invalid)),
                    lambda: self.store.update_static_route(self.device["id"], route["id"], self.route(**invalid)),
                ):
                    self.assert_error(400, operation)
        for invalid in (None, [], {}, {**self.route(), "id": "forged"},
                        {key: value for key, value in self.route().items() if key != "enabled"}):
            self.assert_error(400, lambda: self.store.create_static_route(self.device["id"], invalid))
        self.assertIn(route, self.client.list_static_routes())
        self.assertEqual(len(self.client.list_static_routes()), 3)

    def test_device_deletion_cascades_routes_and_seed_marker(self):
        self.client.list_static_routes()
        other = self.new_device(name="Untouched device")
        other_client = FakeDeviceClient(self.store, other["id"])
        other_routes = other_client.list_static_routes()
        self.store.delete("connections", self.device["id"])
        self.assert_error(404, self.client.inventory)
        self.assert_error(404, self.client.list_static_routes)
        with self.store.engine.connect() as db:
            self.assertEqual(db.execute(select(static_route_initializations.c.connection_id)).scalars().all(),
                             [other["id"]])
            self.assertEqual(set(db.execute(select(static_routes.c.connection_id)).scalars()), {other["id"]})
        self.assertEqual(other_client.list_static_routes(), other_routes)

    def test_encrypted_snapshots_preserve_client_type_and_credentials(self):
        job = self.store.create_job([self.device["id"]])
        self.store.save("role_accounts", {"password": "edited-after-snapshot"}, self.device_role["id"])
        self.store.save("proxies", {"host": "edited-after-snapshot.invalid"}, self.proxy["id"])
        self.store.save("connections", {"client_type": "network"}, self.device["id"])
        _, profile = self.store.get_job_connections(job["id"])[0]
        self.assertEqual(profile["client_type"], "fake")
        self.assertEqual(profile["password"], FAKE_DEVICE_PASSWORD)
        self.assertEqual(profile["connector"]["password"], FAKE_PROXY_PASSWORD)
        result = check_fake_connection(profile)
        self.assertTrue(result["success"])
        self.assertEqual(result["stage"], "simulation")
        self.store.record_job_result(job["id"], {"connection_id": self.device["id"], **result})
        self.assertIs(self.store.get_job(job["id"])["results"][0]["simulated"], True)
        self.store.set_job_status(job["id"], "running")
        self.store.set_job_status(job["id"], "completed")
        with self.store.engine.connect() as db:
            snapshot = db.execute(select(jobs.c.snapshot)).scalar_one()
        self.assertNotIn(FAKE_DEVICE_PASSWORD, snapshot)
        self.assertNotIn(FAKE_PROXY_PASSWORD, snapshot)
        self.assertNotIn(FAKE_DEVICE_PASSWORD.encode(), self.path.read_bytes())
        self.reopen()
        self.assertTrue(self.store.get_job(job["id"])["results"][0]["simulated"])

    def test_results_validate_simulated_flag_and_old_results_default_false(self):
        network = self.new_device(client_type="network")
        job = self.store.create_job([network["id"], self.device["id"]])
        for item_id, bad_flag in (
            (network["id"], True), (self.device["id"], False),
            (network["id"], 0), (self.device["id"], "true"),
        ):
            self.assert_error(400, lambda: self.store.record_job_result(job["id"], {
                "connection_id": item_id, "success": True, "simulated": bad_flag,
            }))
        self.store.record_job_result(job["id"], {"connection_id": network["id"], "success": True})
        self.store.record_job_result(job["id"], {"connection_id": self.device["id"], "success": False})
        results = self.store.get_job(job["id"])["results"]
        self.assertIs(results[0]["simulated"], False)
        self.assertIs(results[1]["simulated"], True)
        with self.store._transaction() as db:
            legacy = dict(results[0])
            legacy.pop("simulated")
            db.execute(update(jobs).where(jobs.c.id == job["id"]).values(results=[legacy]))
        self.assertIs(self.store.get_job(job["id"])["results"][0]["simulated"], False)

    def test_schema_compiles_for_sqlite_and_postgresql(self):
        for dialect in (sqlite.dialect(), postgresql.dialect()):
            for table in (static_routes, static_route_initializations):
                statement = str(CreateTable(table).compile(dialect=dialect))
                self.assertIn("ON DELETE CASCADE", statement)
                self.assertIn("connection_id", statement)

    def test_two_store_instances_initialize_once_and_reject_concurrent_duplicates(self):
        other_store = GatewayStore(sqlite_path=self.path, secret_key=self.key)
        self.addCleanup(other_store.close)
        other_client = FakeDeviceClient(other_store, self.device["id"])
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda client: client.list_static_routes(), (self.client, other_client)))
            self.assertEqual(results[0], results[1])
            self.assertEqual(len(results[0]), 2)

            def create(client):
                try:
                    return client.create_static_route(self.route())
                except StoreError as exc:
                    return exc.status_code

            outcomes = list(pool.map(create, (self.client, other_client)))
        self.assertEqual(sum(isinstance(outcome, dict) for outcome in outcomes), 1)
        self.assertIn(409, outcomes)
        self.assertEqual(len(self.client.list_static_routes()), 3)
        other_store.close()

    def test_legacy_encrypted_job_snapshot_defaults_to_network(self):
        device = self.new_device(client_type="network")
        job = self.store.create_job([device["id"]])
        with self.store._transaction() as db:
            row = db.execute(select(jobs).where(jobs.c.id == job["id"])).mappings().one()
            snapshot = self.store._vault.decrypt(row["snapshot"])
            snapshot[0]["profile"].pop("client_type")
            db.execute(update(jobs).where(jobs.c.id == job["id"]).values(
                snapshot=self.store._vault.encrypt(snapshot),
            ))
        self.assertEqual(self.store.get_job_connections(job["id"])[0][1]["client_type"], "network")

    def test_legacy_completed_job_reopens_and_exports_without_rewriting_history(self):
        device = self.new_device(client_type="network", name="Historical network device", host="192.0.2.50")
        job = self.store.create_job([device["id"]])
        self.store.record_job_result(job["id"], {
            "connection_id": device["id"], "success": True, "stage": "complete",
            "detail": "Historical SSH authentication completed.", "duration_ms": 12.5,
        })
        self.store.set_job_status(job["id"], "running")
        self.store.set_job_status(job["id"], "completed")
        with self.store._transaction() as db:
            row = db.execute(select(jobs).where(jobs.c.id == job["id"])).mappings().one()
            snapshot = self.store._vault.decrypt(row["snapshot"])
            snapshot[0]["profile"].pop("client_type")
            legacy_results = [{key: value for key, value in result.items() if key != "simulated"}
                              for result in row["results"]]
            db.execute(update(jobs).where(jobs.c.id == job["id"]).values(
                snapshot=self.store._vault.encrypt(snapshot), results=legacy_results,
            ))
            original = dict(db.execute(select(jobs).where(jobs.c.id == job["id"])).mappings().one())

        self.reopen()
        expected_results = [{"simulated": False, **result} for result in legacy_results]
        public = self.store.get_job(job["id"])
        self.assertEqual(public, {
            "id": job["id"], "status": "completed", "total": 1, "completed": 1, "results": expected_results,
        })
        resolved = self.store.get_job_connections(job["id"])
        self.assertEqual(resolved, [(device["id"], {"client_type": "network", **snapshot[0]["profile"]})])
        self.assertIs(public["results"][0]["simulated"], False)
        batches = BatchService(ManagementService(self.store))
        try:
            json_text, json_type, json_name = batches.export(job["id"], "json")
            csv_text, csv_type, csv_name = batches.export(job["id"], "csv")
        finally:
            batches.shutdown()
        self.assertEqual(json_type, "application/json")
        self.assertEqual(csv_type, "text/csv")
        self.assertEqual(json_name, f"connection-tests-{job['id']}.json")
        self.assertEqual(csv_name, f"connection-tests-{job['id']}.csv")
        self.assertEqual(json.loads(json_text), public)
        self.assertIs(json.loads(json_text)["results"][0]["simulated"], False)
        reader = csv.DictReader(io.StringIO(csv_text))
        csv_rows = list(reader)
        self.assertEqual(reader.fieldnames, list(EXPORT_FIELDS))
        self.assertIn("simulated", reader.fieldnames)
        self.assertEqual(csv_rows, [{
            field: str(expected_results[0][field]) for field in EXPORT_FIELDS
        }])
        self.assertEqual(csv_rows[0]["simulated"], "False")
        with self.store.engine.connect() as db:
            persisted = dict(db.execute(select(jobs).where(jobs.c.id == job["id"])).mappings().one())
        self.assertEqual(persisted, original)


if __name__ == "__main__":
    unittest.main()
