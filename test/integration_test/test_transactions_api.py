"""HTTP behavior for the read-only /api/v1/transactions audit endpoint."""

import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path

from cryptography.fernet import Fernet
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.routes.device_data import router as device_data_router
from app.api.routes.management import get_store, router as management_router
from app.api.routes.transactions import router as transactions_router
from app.common.identity import AuthenticatedUser, current_user
from app.dal.db.store import GatewayStore
from app.dal.device.fake_client import (
    FAKE_DEVICE_HOST, FAKE_DEVICE_PASSWORD, FAKE_DEVICE_PORT, FAKE_DEVICE_PROTOCOL, FAKE_DEVICE_USERNAME,
    FAKE_PROXY_HOST, FAKE_PROXY_PASSWORD, FAKE_PROXY_PORT, FAKE_PROXY_TYPE, FAKE_PROXY_USERNAME,
)


ROOT = Path(__file__).resolve().parents[2]
ROUTE = {
    "destination": "198.51.100.0/25", "next_hop": "192.0.2.1", "interface": "eth0",
    "metric": 20, "description": "Transactions test route", "enabled": True,
}


def make_user(role):
    return AuthenticatedUser(
        subject=f"test-{role.lower()}", tenant_id=None, name=f"Test {role}", email=None,
        roles=frozenset({role}), auth_mode="demo",
    )


class TransactionsApiTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="transactions-api-", dir=ROOT / ".cache")
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "inventory.sqlite"
        key = Fernet.generate_key()
        self.store = GatewayStore(sqlite_path=path, secret_key=key)
        self.addCleanup(lambda: self.store.close())
        self.app = FastAPI()
        self.app.state.device_data_provider = "fake"
        self.app.include_router(management_router)
        self.app.include_router(device_data_router)
        self.app.include_router(transactions_router)
        self.app.dependency_overrides[get_store] = lambda: self.store
        self.app.dependency_overrides[current_user] = lambda: make_user("Administrator")
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.client = self.stack.enter_context(TestClient(self.app))
        self.addCleanup(self.shutdown_worker)

        role_body = {
            "name": "Fake device login", "username": FAKE_DEVICE_USERNAME,
            "authentication_type": "password", "password": FAKE_DEVICE_PASSWORD,
        }
        role = self.client.post("/api/v1/role-accounts", json=role_body).json()
        proxy_role_body = {
            "name": "Fake proxy login", "username": FAKE_PROXY_USERNAME,
            "authentication_type": "password", "password": FAKE_PROXY_PASSWORD,
        }
        proxy_role = self.client.post("/api/v1/role-accounts", json=proxy_role_body).json()
        proxy_body = {
            "name": "Fake bastion", "type": FAKE_PROXY_TYPE, "host": FAKE_PROXY_HOST,
            "port": FAKE_PROXY_PORT, "role_account_id": proxy_role["id"],
        }
        proxy = self.client.post("/api/v1/proxies", json=proxy_body).json()
        device_body = {
            "name": "Fake transport device", "client_type": "fake",
            "protocol": FAKE_DEVICE_PROTOCOL, "host": FAKE_DEVICE_HOST, "port": FAKE_DEVICE_PORT,
            "role_account_id": role["id"], "proxy_id": proxy["id"],
        }
        self.device = self.client.post("/api/v1/connections", json=device_body).json()
        self.routes = f"/api/v1/connections/{self.device['id']}/static-routes"

    def shutdown_worker(self):
        worker = getattr(self.app.state, "management_batches", None)
        if worker:
            worker.shutdown()
            del self.app.state.management_batches

    def as_role(self, role):
        self.app.dependency_overrides[current_user] = lambda: make_user(role)

    def test_transactions_endpoint_rejects_mutation_verbs(self):
        for method in ("post", "put", "patch"):
            response = getattr(self.client, method)("/api/v1/transactions", json={})
            self.assertEqual(response.status_code, 405, response.text)
        self.assertEqual(self.client.delete("/api/v1/transactions").status_code, 405)

    def test_transactions_pagination_and_filters(self):
        created = [self.client.post(self.routes, json={
            **ROUTE, "destination": f"203.0.113.{index}/32", "metric": index,
        }).json()["item"] for index in range(0, 3)]
        for item in created:
            self.client.delete(self.routes + "/" + item["id"])

        first_page = self.client.get("/api/v1/transactions", params={
            "connection_id": self.device["id"], "limit": 2, "offset": 0,
        })
        self.assertEqual(first_page.status_code, 200, first_page.text)
        body = first_page.json()
        self.assertEqual(set(body), {"items", "total"})
        self.assertEqual(len(body["items"]), 2)
        self.assertGreaterEqual(body["total"], 6)

        second_page = self.client.get("/api/v1/transactions", params={
            "connection_id": self.device["id"], "limit": 2, "offset": 2,
        })
        self.assertEqual(len(second_page.json()["items"]), 2)
        self.assertNotEqual(
            {row["id"] for row in first_page.json()["items"]},
            {row["id"] for row in second_page.json()["items"]},
        )

        creates_only = self.client.get("/api/v1/transactions", params={
            "connection_id": self.device["id"], "action": "static_route.create", "limit": 50,
        }).json()
        self.assertTrue(creates_only["items"])
        self.assertTrue(all(row["action"] == "static_route.create" for row in creates_only["items"]))

        by_actor = self.client.get("/api/v1/transactions", params={
            "actor_subject": "test-administrator", "limit": 50,
        }).json()
        self.assertTrue(by_actor["items"])
        self.assertTrue(all(row["actor_subject"] == "test-administrator" for row in by_actor["items"]))

        by_outcome = self.client.get("/api/v1/transactions", params={
            "connection_id": self.device["id"], "outcome": "failed", "limit": 50,
        }).json()
        self.assertEqual(by_outcome["items"], [])

        bad_outcome = self.client.get("/api/v1/transactions", params={"outcome": "bogus"})
        self.assertEqual(bad_outcome.status_code, 422, bad_outcome.text)

    def test_transactions_records_reflect_static_route_lifecycle(self):
        created = self.client.post(self.routes, json=ROUTE).json()["item"]
        rows = self.client.get("/api/v1/transactions", params={
            "connection_id": self.device["id"], "action": "static_route.create",
        }).json()["items"]
        row = next(item for item in rows if item["resource_id"] == created["id"])
        self.assertEqual(row["outcome"], "succeeded")
        self.assertEqual(row["resource_type"], "static_route")
        self.assertEqual(row["after_state"], created)
        self.assertIn("timestamp_utc", row)
        self.assertTrue(row["correlation_id"])

    def test_transactions_endpoint_enforces_viewer_minimum_role(self):
        self.as_role("Viewer")
        response = self.client.get("/api/v1/transactions")
        self.assertEqual(response.status_code, 200, response.text)


if __name__ == "__main__":
    unittest.main()
