"""Actual HTTP -> BL -> encrypted SQLite graph -> fake device, without sockets."""

import csv
import io
import json
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

from cryptography.fernet import Fernet
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select, update

from app.api.routes.device_data import router as device_data_router
from app.api.routes.management import get_store, router as management_router
from app.bl.services.batches import BatchService, EXPORT_FIELDS
from app.bl.services.management import ManagementService
from app.common.identity import AuthenticatedUser, current_user
from app.dal.db.secrets import SecretVault
from app.dal.db.storage import jobs
from app.dal.db.store import GatewayStore
from app.dal.device.fake_client import (
    FAKE_DEVICE_HOST, FAKE_DEVICE_PASSWORD, FAKE_DEVICE_PORT, FAKE_DEVICE_PROTOCOL,
    FAKE_DEVICE_USERNAME, FAKE_PROXY_HOST, FAKE_PROXY_PASSWORD, FAKE_PROXY_PORT,
    FAKE_PROXY_TYPE, FAKE_PROXY_USERNAME,
)


ROOT = Path(__file__).resolve().parents[2]
ROUTE = {
    "destination": "198.51.100.0/25", "next_hop": "192.0.2.1", "interface": "eth0",
    "metric": 20, "description": "Operator-created simulation", "enabled": True,
}
ROUTE_KEYS = {"id", "connection_id", *ROUTE}
TEST_KEYS = {"success", "simulated", "stage", "detail", "duration_ms"}


class DeviceDataIntegrationTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="device-data-api-", dir=ROOT / ".cache")
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "inventory.sqlite"
        self.key = Fernet.generate_key()
        self.store = GatewayStore(sqlite_path=self.path, secret_key=self.key)
        self.addCleanup(lambda: self.store.close())
        self.app = FastAPI()
        self.app.state.device_data_provider = "fake"
        self.app.include_router(management_router)
        self.app.include_router(device_data_router)
        self.app.dependency_overrides[get_store] = lambda: self.store
        self.app.dependency_overrides[current_user] = lambda: AuthenticatedUser(
            subject="test-admin", tenant_id=None, name="Test Administrator", email=None,
            roles=frozenset({"Administrator"}), auth_mode="demo",
        )
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.client = self.stack.enter_context(TestClient(self.app))
        self.addCleanup(self.shutdown_worker)
        self.socket_guards = [
            self.stack.enter_context(patch(name, side_effect=AssertionError("Fake access opened a socket.")))
            for name in (
                "socket.socket.__init__", "socket.socket.connect", "socket.socket.connect_ex",
                "socket.create_connection", "socket.getaddrinfo",
            )
        ]
        self.role_body = {
            "name": "Fake device login", "username": FAKE_DEVICE_USERNAME,
            "authentication_type": "password", "password": FAKE_DEVICE_PASSWORD,
        }
        self.proxy_role_body = {
            "name": "Fake proxy login", "username": FAKE_PROXY_USERNAME,
            "authentication_type": "password", "password": FAKE_PROXY_PASSWORD,
        }
        self.role = self.post("/api/v1/role-accounts", self.role_body)
        self.proxy_role = self.post("/api/v1/role-accounts", self.proxy_role_body)
        self.proxy_body = {
            "name": "Fake bastion", "type": FAKE_PROXY_TYPE, "host": FAKE_PROXY_HOST,
            "port": FAKE_PROXY_PORT, "role_account_id": self.proxy_role["id"],
        }
        self.proxy = self.post("/api/v1/proxies", self.proxy_body)
        self.device_body = {
            "name": "Fake transport device", "client_type": "fake",
            "protocol": FAKE_DEVICE_PROTOCOL, "host": FAKE_DEVICE_HOST, "port": FAKE_DEVICE_PORT,
            "role_account_id": self.role["id"], "proxy_id": self.proxy["id"],
        }
        self.device = self.post("/api/v1/connections", self.device_body)
        self.base = f"/api/v1/connections/{self.device['id']}"
        self.routes = self.base + "/static-routes"

    def tearDown(self):
        for guard in self.socket_guards:
            guard.assert_not_called()

    def shutdown_worker(self):
        worker = getattr(self.app.state, "management_batches", None)
        if worker:
            worker.shutdown()
            del self.app.state.management_batches

    def reopen(self):
        self.shutdown_worker()
        self.store.close()
        self.store = GatewayStore(sqlite_path=self.path, secret_key=self.key)

    def post(self, path, body):
        response = self.client.post(path, json=body)
        self.assertEqual(response.status_code, 201, response.text)
        self.assert_no_credentials(response.text)
        return response.json()

    def assert_no_credentials(self, text):
        for secret in (FAKE_DEVICE_PASSWORD, FAKE_PROXY_PASSWORD, "mutated-secret"):
            self.assertNotIn(secret, text)

    def test_inventory_exact_public_graph_and_nested_shapes(self):
        response = self.client.get(self.base + "/inventory")
        self.assertEqual(response.status_code, 200, response.text)
        inventory = response.json()
        self.assertEqual(set(inventory), {
            "provider", "simulated", "device", "access", "system", "interfaces", "bgp", "mpls",
        })
        self.assertEqual(inventory["provider"], "fake")
        self.assertIs(inventory["simulated"], True)
        self.assertEqual(inventory["device"], {
            "id": self.device["id"], "name": self.device_body["name"],
            "protocol": FAKE_DEVICE_PROTOCOL, "host": FAKE_DEVICE_HOST, "port": FAKE_DEVICE_PORT,
        })
        self.assertEqual(inventory["access"], {
            "role_account_id": self.role["id"], "proxy_id": self.proxy["id"],
            "proxy_role_account_id": self.proxy_role["id"], "connector_type": FAKE_PROXY_TYPE,
        })
        self.assertEqual(set(inventory["system"]), {
            "hostname", "model", "software_version", "serial_number", "uptime_seconds",
        })
        self.assertEqual({row["name"] for row in inventory["interfaces"]}, {"eth0", "eth1", "lo"})
        for interface in inventory["interfaces"]:
            self.assertEqual(set(interface), {
                "name", "description", "admin_status", "oper_status", "mtu", "mac_address",
                "addresses", "rx_bytes", "tx_bytes",
            })
        self.assertEqual(set(inventory["bgp"]), {"local_asn", "router_id", "neighbors"})
        for neighbor in inventory["bgp"]["neighbors"]:
            self.assertEqual(set(neighbor), {
                "address", "remote_asn", "state", "uptime_seconds", "prefixes_received", "prefixes_sent",
            })
        self.assertEqual(set(inventory["mpls"]), {"interfaces", "ldp_neighbors", "lsps"})
        for interface in inventory["mpls"]["interfaces"]:
            self.assertEqual(set(interface), {"name", "enabled"})
        for neighbor in inventory["mpls"]["ldp_neighbors"]:
            self.assertEqual(set(neighbor), {"router_id", "address", "state", "uptime_seconds"})
        for lsp in inventory["mpls"]["lsps"]:
            self.assertEqual(set(lsp), {"name", "source", "destination", "state", "label"})
        self.assert_no_credentials(response.text)
        inventory["interfaces"][0]["addresses"].append("modified")
        self.assertEqual(self.client.get(self.base + "/inventory").json(), response.json())

    def test_route_crud_exact_shapes_and_reopen_without_reseeding(self):
        created = self.post(self.routes, ROUTE)
        self.assertEqual(set(created), {"provider", "simulated", "item"})
        self.assertEqual(created["provider"], "fake")
        self.assertIs(created["simulated"], True)
        route = created["item"]
        self.assertEqual(set(route), ROUTE_KEYS)
        self.assertEqual(route, {**ROUTE, "id": route["id"], "connection_id": self.device["id"]})
        path = self.routes + "/" + route["id"]
        changed = {**ROUTE, "metric": 65535, "interface": None, "description": "Saved edit", "enabled": False}
        response = self.client.put(path, json=changed)
        self.assertEqual(response.status_code, 200, response.text)
        expected = {**created, "item": {**changed, "id": route["id"], "connection_id": self.device["id"]}}
        self.assertEqual(response.json(), expected)
        self.reopen()
        response = self.client.get(self.routes)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(set(response.json()), {"provider", "simulated", "items"})
        self.assertIn(expected["item"], response.json()["items"])
        for item in response.json()["items"]:
            deleted = self.client.delete(self.routes + "/" + item["id"])
            self.assertEqual(deleted.status_code, 204, deleted.text)
            self.assertEqual(deleted.content, b"")
        self.reopen()
        self.assertEqual(self.client.get(self.routes).json(), {
            "provider": "fake", "simulated": True, "items": [],
        })
        self.assertEqual(self.client.delete(path).status_code, 404)
        self.assertEqual(self.client.put(path, json=ROUTE).status_code, 404)

    def test_route_validation_and_ipv6_canonical_duplicates(self):
        before = self.client.get(self.routes).json()
        invalid = [
            {"destination": "198.51.100.1/24"}, {"destination": "not-a-cidr"},
            {"destination": "198.51.100.1"}, {"destination": "198.51.100.0/99"},
            {"destination": "198.51.100.0/255.255.255.0"},
            {"destination": "fe80::%eth0/64", "next_hop": "fe80::1"},
            {"next_hop": "invalid"}, {"next_hop": "2001:db8::1"}, {"metric": True},
            {"metric": -1}, {"metric": 65536}, {"metric": 1.5}, {"metric": "1"},
            {"enabled": 1}, {"enabled": "false"}, {"interface": "eth9"},
            {"description": "x" * 201}, {"password": "mutated-secret"},
            {"id": "extra"}, {"connection_id": self.device["id"]},
        ]
        for change in invalid:
            with self.subTest(change=change):
                response = self.client.post(self.routes, json={**ROUTE, **change})
                self.assertEqual(response.status_code, 422, response.text)
                self.assertEqual(response.json(), {"detail": "Invalid request fields."})
        self.assertEqual(self.client.get(self.routes).json(), before)
        ipv6 = {**ROUTE, "destination": "2001:0db8:0042:0000::/64",
                "next_hop": "2001:0db8:0001::1", "interface": "eth1", "metric": 0}
        route = self.post(self.routes, ipv6)["item"]
        self.assertEqual(route["destination"], "2001:db8:42::/64")
        self.assertEqual(route["next_hop"], "2001:db8:1::1")
        self.assertEqual(self.client.post(self.routes, json={
            **ipv6, "destination": route["destination"],
        }).status_code, 409)
        self.assertEqual(self.client.post(self.routes, json={
            **ipv6, "next_hop": "fe80::1%eth1",
        }).status_code, 422)
        route4 = self.post(self.routes, ROUTE)["item"]
        self.assertEqual(self.client.put(self.routes + "/" + route4["id"], json=ipv6).status_code, 409)

    def test_per_device_route_ownership_and_connection_delete(self):
        second = self.post("/api/v1/connections", {**self.device_body, "name": "Second simulation"})
        second_routes = f"/api/v1/connections/{second['id']}/static-routes"
        route = self.post(self.routes, ROUTE)["item"]
        other_route = self.post(second_routes, ROUTE)["item"]
        self.assertNotEqual(route["id"], other_route["id"])
        self.assertEqual(self.client.put(second_routes + "/" + route["id"], json=ROUTE).status_code, 404)
        self.assertEqual(self.client.delete(second_routes + "/" + route["id"]).status_code, 404)
        self.assertEqual(self.client.delete(self.base).status_code, 204)
        self.assertEqual(self.client.get(self.routes).status_code, 404)
        self.assertEqual(self.client.get(self.base + "/inventory").status_code, 404)
        self.reopen()
        self.assertIn(other_route, self.client.get(second_routes).json()["items"])
        with self.store.engine.connect() as db:
            from sqlalchemy import select
            from app.dal.db.storage import static_routes

            self.assertEqual(db.execute(select(static_routes).where(
                static_routes.c.connection_id == self.device["id"],
            )).all(), [])

    def test_every_operation_rejects_mutated_roles_and_proxy_graph(self):
        route = self.post(self.routes, ROUTE)["item"]
        item_path = self.routes + "/" + route["id"]
        mutations = [
            (f"/api/v1/role-accounts/{self.role['id']}", self.role_body, {"password": "mutated-secret"}),
            (f"/api/v1/role-accounts/{self.role['id']}", self.role_body, {"username": "wrong"}),
            (f"/api/v1/role-accounts/{self.proxy_role['id']}", self.proxy_role_body, {"password": "mutated-secret"}),
            (f"/api/v1/role-accounts/{self.proxy_role['id']}", self.proxy_role_body, {"username": "wrong"}),
            (f"/api/v1/proxies/{self.proxy['id']}", self.proxy_body, {"host": "other.invalid"}),
            (f"/api/v1/proxies/{self.proxy['id']}", self.proxy_body, {"port": 2222}),
            (f"/api/v1/proxies/{self.proxy['id']}", self.proxy_body, {"type": "ssh_shell"}),
            (self.base, self.device_body, {"proxy_id": None}),
            (self.base, self.device_body, {"host": "other.invalid"}),
            (self.base, self.device_body, {"protocol": "telnet"}),
            (self.base, self.device_body, {"protocol": "netconf"}),
        ]
        for path, original, change in mutations:
            with self.subTest(path=path, change=change):
                response = self.client.put(path, json={**original, **change})
                self.assertEqual(response.status_code, 200, response.text)
                requests = [
                    self.client.get(self.base + "/inventory"), self.client.get(self.routes),
                    self.client.post(self.routes, json=ROUTE),
                    self.client.put(item_path, json=ROUTE), self.client.delete(item_path),
                ]
                for response in requests:
                    self.assertEqual(response.status_code, 403, response.text)
                    self.assertEqual(response.json(), {"detail": "Device access was rejected."})
                    self.assert_no_credentials(response.text)
                result = self.client.post(self.base + "/test", json={})
                self.assertEqual(result.status_code, 200, result.text)
                self.assertEqual(set(result.json()), TEST_KEYS)
                self.assertIs(result.json()["success"], False)
                self.assertIs(result.json()["simulated"], True)
                self.assert_no_credentials(result.text)
                self.assertEqual(self.client.put(path, json=original).status_code, 200)
                self.assertEqual(self.client.get(self.base + "/inventory").status_code, 200)
        self.assertIn(route, self.client.get(self.routes).json()["items"])

    def test_explicit_provider_gate_and_no_network_inventory_fallback(self):
        route = self.post(self.routes, ROUTE)["item"]
        network = self.post("/api/v1/connections", {
            **self.device_body, "name": "Real network profile", "client_type": "network",
        })
        base = f"/api/v1/connections/{network['id']}"
        for path in (base + "/inventory", base + "/static-routes"):
            self.assertEqual(self.client.get(path).status_code, 501)
        self.assertEqual(self.client.post(base + "/static-routes", json=ROUTE).status_code, 501)
        self.assertEqual(self.client.put(base + "/static-routes/" + route["id"], json=ROUTE).status_code, 501)
        self.assertEqual(self.client.delete(base + "/static-routes/" + route["id"]).status_code, 501)
        for provider in ("disabled", "invalid", None):
            with self.subTest(provider=provider):
                self.shutdown_worker()
                if provider is None:
                    del self.app.state.device_data_provider
                else:
                    self.app.state.device_data_provider = provider
                for path in (self.base + "/inventory", self.routes):
                    self.assertEqual(self.client.get(path).status_code, 503)
                self.assertEqual(self.client.post(self.routes, json=ROUTE).status_code, 503)
                self.assertEqual(self.client.put(self.routes + "/" + route["id"], json=ROUTE).status_code, 503)
                self.assertEqual(self.client.delete(self.routes + "/" + route["id"]).status_code, 503)
                self.assertEqual(self.client.post(self.base + "/test", json={}).status_code, 503)
                self.assertEqual(self.client.post("/api/v1/connection-tests", json={
                    "connection_ids": [self.device["id"]],
                }).status_code, 503)

    def test_cached_batch_worker_obeys_current_application_provider_gate(self):
        selection = {"connection_ids": [self.device["id"]]}
        response = self.client.post("/api/v1/connection-tests", json=selection)
        self.assertEqual(response.status_code, 202, response.text)
        worker = self.app.state.management_batches
        worker._future.result(timeout=5)
        self.app.state.device_data_provider = "disabled"
        response = self.client.post("/api/v1/connection-tests", json=selection)
        self.assertEqual(response.status_code, 503, response.text)
        self.assertIs(self.app.state.management_batches, worker)
        self.app.state.device_data_provider = "fake"
        response = self.client.post("/api/v1/connection-tests", json=selection)
        self.assertEqual(response.status_code, 202, response.text)
        worker._future.result(timeout=5)

    def test_single_batch_json_and_csv_preserve_simulated_field(self):
        single = self.client.post(self.base + "/test", json={})
        self.assertEqual(single.status_code, 200, single.text)
        expected = {
            "success": True, "simulated": True, "stage": "simulation",
            "detail": "Simulated device and proxy authentication passed; no network connection was made.",
            "duration_ms": 0.0,
        }
        self.assertEqual(single.json(), expected)
        response = self.client.post("/api/v1/connection-tests", json={"connection_ids": [self.device["id"]]})
        self.assertEqual(response.status_code, 202, response.text)
        self.app.state.management_batches._future.result(timeout=5)
        job_id = response.json()["id"]
        job_path = f"/api/v1/connection-tests/{job_id}"
        job = self.client.get(job_path).json()
        self.assertEqual(job["status"], "completed")
        self.assertEqual(job["completed"], 1)
        result = {
            **expected, "connection_id": self.device["id"], "name": self.device_body["name"],
            "protocol": FAKE_DEVICE_PROTOCOL, "host": FAKE_DEVICE_HOST,
            "port": FAKE_DEVICE_PORT, "connector_type": FAKE_PROXY_TYPE,
        }
        self.assertEqual(job["results"], [result])
        self.assertEqual(self.store.get_job(job_id)["results"], [result])
        exported = self.client.get(job_path + "/export?format=json")
        self.assertEqual(exported.status_code, 200, exported.text)
        self.assertEqual(exported.json()["results"], [result])
        csv_response = self.client.get(job_path + "/export?format=csv")
        self.assertEqual(csv_response.status_code, 200, csv_response.text)
        reader = csv.DictReader(io.StringIO(csv_response.text))
        self.assertEqual(reader.fieldnames, [
            "connection_id", "name", "protocol", "host", "port", "connector_type",
            "success", "simulated", "stage", "detail", "duration_ms",
        ])
        self.assertEqual(set(reader.fieldnames), set(result))
        self.assertEqual(list(reader), [{key: str(result[key]) for key in EXPORT_FIELDS}])
        self.assert_no_credentials(exported.text + csv_response.text)
        self.reopen()
        self.assertEqual(self.client.get(job_path).json()["results"], [result])
        self.assertEqual(self.client.get(job_path + "/export?format=json").json()["results"], [result])

    def test_batch_authentication_failure_isolated_from_valid_fake_profile(self):
        bad_role = self.post("/api/v1/role-accounts", {
            **self.role_body, "name": "Changed credentials", "password": "mutated-secret",
        })
        bad_device = self.post("/api/v1/connections", {
            **self.device_body, "name": "Rejected simulation", "role_account_id": bad_role["id"],
        })
        response = self.client.post("/api/v1/connection-tests", json={
            "connection_ids": [bad_device["id"], self.device["id"]],
        })
        self.assertEqual(response.status_code, 202, response.text)
        self.app.state.management_batches._future.result(timeout=5)
        job = self.client.get("/api/v1/connection-tests/" + response.json()["id"]).json()
        self.assertEqual((job["status"], job["completed"]), ("completed", 2))
        self.assertEqual([result["success"] for result in job["results"]], [False, True])
        self.assertTrue(all(result["simulated"] is True for result in job["results"]))
        self.assert_no_credentials(json.dumps(job))

    def test_batch_uses_persisted_immutable_graph_snapshot(self):
        job = self.store.create_job([self.device["id"]])
        changed = self.client.put(f"/api/v1/role-accounts/{self.proxy_role['id']}", json={
            **self.proxy_role_body, "password": "mutated-secret",
        })
        self.assertEqual(changed.status_code, 200)
        self.assertEqual(self.client.get(self.base + "/inventory").status_code, 403)
        worker = BatchService(ManagementService(self.store, device_data_provider="fake"))
        try:
            worker._run(job["id"])
        finally:
            worker.shutdown()
        result = self.client.get("/api/v1/connection-tests/" + job["id"]).json()["results"][0]
        self.assertTrue(result["success"], result)
        self.assertIs(result["simulated"], True)

    def test_historical_network_job_reopens_and_exports_without_rewriting_history(self):
        network = self.post("/api/v1/connections", {
            "name": "Historical network device", "protocol": "ssh",
            "host": "192.0.2.40", "port": 22, "username": "historical-user",
            "password": "historical-secret",
        })
        profile = self.store.resolve_connection(network["id"])
        del profile["client_type"]
        legacy_result = {
            "connection_id": network["id"], "name": network["name"],
            "protocol": "ssh", "host": "192.0.2.40", "port": 22,
            "connector_type": "direct", "success": True, "stage": "complete",
            "detail": "Historical successful connection test.", "duration_ms": 12.5,
        }
        job_id = self.store.create_job([network["id"]])["id"]
        encrypted_snapshot = SecretVault(self.key).encrypt([{
            "id": network["id"], "profile": profile,
        }])
        with self.store.engine.begin() as db:
            db.execute(update(jobs).where(jobs.c.id == job_id).values(
                status="completed", completed=1, active_slot=None,
                snapshot=encrypted_snapshot, results=[legacy_result],
            ))
            original_row = dict(db.execute(select(jobs).where(
                jobs.c.id == job_id,
            )).mappings().one())
        self.assertNotIn("simulated", original_row["results"][0])
        self.assertNotIn("client_type", SecretVault(self.key).decrypt(
            original_row["snapshot"],
        )[0]["profile"])
        self.assertEqual(self.client.delete("/api/v1/connections/" + network["id"]).status_code, 204)
        self.reopen()

        expected_result = {**legacy_result, "simulated": False}
        expected_job = {
            "id": job_id, "status": "completed", "total": 1, "completed": 1,
            "results": [expected_result],
        }
        self.assertEqual(self.store.get_job(job_id), expected_job)
        self.assertEqual(self.store.get_job_connections(job_id), [
            (network["id"], {**profile, "client_type": "network"}),
        ])
        path = "/api/v1/connection-tests/" + job_id
        response = self.client.get(path)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json(), {**expected_job, "error": None})
        exported = self.client.get(path + "/export?format=json")
        self.assertEqual(exported.status_code, 200, exported.text)
        self.assertEqual(exported.json(), expected_job)
        exported_csv = self.client.get(path + "/export?format=csv")
        self.assertEqual(exported_csv.status_code, 200, exported_csv.text)
        reader = csv.DictReader(io.StringIO(exported_csv.text))
        self.assertEqual(reader.fieldnames, [
            "connection_id", "name", "protocol", "host", "port", "connector_type",
            "success", "simulated", "stage", "detail", "duration_ms",
        ])
        self.assertEqual(list(reader), [
            {key: str(expected_result[key]) for key in reader.fieldnames},
        ])
        self.assertNotIn("historical-secret", response.text + exported.text + exported_csv.text)
        self.reopen()
        with self.store.engine.connect() as db:
            preserved_row = dict(db.execute(select(jobs).where(
                jobs.c.id == job_id,
            )).mappings().one())
        self.assertEqual(preserved_row, original_row)
        self.assertEqual(self.client.get(path + "/export?format=json").json(), expected_job)

    def test_mutation_origin_json_validation_and_openapi(self):
        before = self.client.get(self.routes).json()
        for headers in ({"Origin": "https://other.invalid"}, {"Sec-Fetch-Site": "cross-site"}):
            self.assertEqual(self.client.post(self.routes, json=ROUTE, headers=headers).status_code, 403)
            self.assertEqual(self.client.put(self.routes + "/missing", json=ROUTE, headers=headers).status_code, 403)
            self.assertEqual(self.client.delete(self.routes + "/missing", headers=headers).status_code, 403)
        self.assertEqual(self.client.post(self.routes, data=ROUTE).status_code, 415)
        response = self.client.post(self.routes, content='{"mutated-secret":',
                                    headers={"Content-Type": "application/json"})
        self.assertEqual(response.status_code, 422)
        self.assert_no_credentials(response.text)
        self.assertEqual(self.client.get(self.routes).json(), before)
        paths = self.client.get("/openapi.json").json()["paths"]
        self.assertIn("/api/v1/connections/{connection_id}/inventory", paths)
        self.assertEqual(set(paths["/api/v1/connections/{connection_id}/static-routes"]), {"get", "post"})
        self.assertEqual(set(paths["/api/v1/connections/{connection_id}/static-routes/{route_id}"]), {"put", "delete"})

    def test_client_type_is_persisted_defaulted_and_strictly_validated(self):
        self.assertEqual(self.device["client_type"], "fake")
        self.assertEqual(self.store.resolve_connection(self.device["id"])["client_type"], "fake")
        network_body = {key: value for key, value in self.device_body.items() if key != "client_type"}
        network = self.post("/api/v1/connections", {**network_body, "name": "Default network"})
        self.assertEqual(network["client_type"], "network")
        self.assertEqual(self.store.resolve_connection(network["id"])["client_type"], "network")
        for invalid in ("globalfake", None, True, 1):
            response = self.client.put(self.base, json={**self.device_body, "client_type": invalid})
            self.assertEqual(response.status_code, 422, response.text)
        self.reopen()
        self.assertEqual(self.client.get(self.base).json()["client_type"], "fake")



    def transaction_rows(self, **filters):
        return self.store.list_transactions(filters=filters or None, limit=200)["items"]

    def test_successful_route_mutations_persist_atomic_audit_records(self):
        created = self.post(self.routes, ROUTE)["item"]
        route_id = created["id"]
        rows = self.transaction_rows(connection_id=self.device["id"], resource_type="static_route")
        create_row = next(r for r in rows if r["action"] == "static_route.create" and r["resource_id"] == route_id)
        self.assertEqual(create_row["outcome"], "succeeded")
        self.assertEqual(create_row["actor_subject"], "test-admin")
        self.assertEqual(create_row["actor_name"], "Test Administrator")
        self.assertEqual(create_row["actor_roles"], ["Administrator"])
        self.assertEqual(create_row["auth_mode"], "demo")
        self.assertIsNone(create_row["before_state"])
        self.assertEqual(create_row["after_state"], created)
        self.assertEqual(create_row["request_method"], "POST")
        self.assertEqual(create_row["request_path"], self.routes)
        self.assertTrue(create_row["correlation_id"])

        changed = {**ROUTE, "metric": 111}
        path = self.routes + "/" + route_id
        put_response = self.client.put(path, json=changed)
        self.assertEqual(put_response.status_code, 200, put_response.text)
        self.assertEqual(put_response.headers["X-Correlation-ID"], create_row["correlation_id"]
                          if False else put_response.headers["X-Correlation-ID"])
        rows = self.transaction_rows(connection_id=self.device["id"], resource_type="static_route")
        update_row = next(r for r in rows if r["action"] == "static_route.update" and r["resource_id"] == route_id)
        self.assertEqual(update_row["outcome"], "succeeded")
        self.assertEqual(update_row["before_state"], created)
        self.assertEqual(update_row["after_state"], put_response.json()["item"])
        self.assertEqual(update_row["correlation_id"], put_response.headers["X-Correlation-ID"])

        delete_response = self.client.delete(path)
        self.assertEqual(delete_response.status_code, 204, delete_response.text)
        self.assertTrue(delete_response.headers["X-Correlation-ID"])
        rows = self.transaction_rows(connection_id=self.device["id"], resource_type="static_route")
        delete_row = next(r for r in rows if r["action"] == "static_route.delete" and r["resource_id"] == route_id)
        self.assertEqual(delete_row["outcome"], "succeeded")
        self.assertEqual(delete_row["before_state"], update_row["after_state"])
        self.assertIsNone(delete_row["after_state"])
        self.assertEqual(delete_row["correlation_id"], delete_response.headers["X-Correlation-ID"])

    def test_correlation_id_header_is_honored_when_valid_and_minted_when_absent(self):
        supplied = "11111111-2222-4333-8444-555555555555"
        response = self.client.post(
            self.routes, json={**ROUTE, "destination": "203.0.113.0/28"},
            headers={"X-Correlation-ID": supplied},
        )
        self.assertEqual(response.status_code, 201, response.text)
        self.assertEqual(response.headers["X-Correlation-ID"], supplied)
        rows = self.transaction_rows(connection_id=self.device["id"], action="static_route.create")
        row = next(r for r in rows if r["resource_id"] == response.json()["item"]["id"])
        self.assertEqual(row["correlation_id"], supplied)

        response2 = self.client.post(self.routes, json={**ROUTE, "destination": "203.0.113.16/28"})
        self.assertEqual(response2.status_code, 201, response2.text)
        minted = response2.headers["X-Correlation-ID"]
        self.assertNotEqual(minted, supplied)
        self.assertEqual(len(minted), 36)

    def test_failed_static_route_mutations_are_audited_without_state_change(self):
        before_routes = self.client.get(self.routes).json()
        missing_id = "00000000-0000-4000-8000-000000000000"
        put_response = self.client.put(self.routes + "/" + missing_id, json=ROUTE)
        self.assertEqual(put_response.status_code, 404, put_response.text)
        delete_response = self.client.delete(self.routes + "/" + missing_id)
        self.assertEqual(delete_response.status_code, 404, delete_response.text)
        self.assertEqual(self.client.get(self.routes).json(), before_routes)

        rows = self.transaction_rows(connection_id=self.device["id"], outcome="failed")
        update_failure = next(r for r in rows if r["action"] == "static_route.update")
        delete_failure = next(r for r in rows if r["action"] == "static_route.delete")
        for failed_row in (update_failure, delete_failure):
            self.assertEqual(failed_row["outcome"], "failed")
            self.assertEqual(failed_row["resource_id"], missing_id)
            self.assertIsNone(failed_row["before_state"])
            self.assertIsNone(failed_row["after_state"])
            self.assertTrue(failed_row["detail"])
            self.assertEqual(failed_row["actor_subject"], "test-admin")

    def test_audit_state_never_contains_secret_fields_even_if_injected(self):
        with self.store._transaction() as db:
            self.store._insert_transaction(db, {
                "correlation_id": None,
                "actor_subject": "test-admin", "actor_tenant_id": None,
                "actor_name": "Test Administrator", "actor_email": None,
                "actor_roles": ["Administrator"], "auth_mode": "demo",
                "action": "static_route.create", "resource_type": "static_route",
                "resource_id": None, "connection_id": self.device["id"],
                "outcome": "succeeded",
                "before_state": None,
                "after_state": {"destination": "198.51.100.0/24", "password": "super-secret-value"},
                "detail": "Authorization: Bearer super-secret-value",
            })
        rows = self.transaction_rows(connection_id=self.device["id"], action="static_route.create")
        injected = next(r for r in rows if r["after_state"] and "password" in r["after_state"])
        self.assertEqual(injected["after_state"]["password"], "[redacted]")
        self.assertNotIn("super-secret-value", str(injected["after_state"]))
        self.assertNotIn("super-secret-value", injected["detail"] or "")

    def test_no_successful_mutation_persists_if_audit_insert_fails(self):
        original = self.store._insert_transaction

        def failing_insert(db, payload):
            if payload.get("action") == "static_route.create":
                raise Exception("Simulated audit backend outage.")
            return original(db, payload)

        before_routes = self.client.get(self.routes).json()["items"]
        with patch.object(type(self.store), "_insert_transaction", failing_insert):
            response = self.client.post(self.routes, json=ROUTE)
            self.assertEqual(response.status_code, 500, response.text)
        self.assertEqual(self.client.get(self.routes).json()["items"], before_routes)
        rows = self.transaction_rows(connection_id=self.device["id"], action="static_route.create")
        self.assertEqual(rows, [])

if __name__ == "__main__":
    unittest.main()
