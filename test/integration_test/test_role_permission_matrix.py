"""Three-role (Viewer/Operator/Administrator) permission matrix and 401 vs 403 semantics.

Local `current_user` dependency overrides are used to exercise the policy matrix
directly, as permitted by the audit contract; the actor for these checks never
comes from the request body or headers -- it is fully server-controlled here via
the FastAPI dependency override, exactly mirroring how real authentication would
inject an `AuthenticatedUser` before the route body ever executes.
"""

import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path

from cryptography.fernet import Fernet
from fastapi import FastAPI, HTTPException
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
ROLE_RANK = {"Viewer": 1, "Operator": 2, "Administrator": 3}
ROLES = ("Viewer", "Operator", "Administrator")


def make_user(role):
    return AuthenticatedUser(
        subject=f"test-{role.lower()}", tenant_id=None, name=f"Test {role}", email=None,
        roles=frozenset({role}), auth_mode="demo",
    )


def unauthenticated():
    raise HTTPException(status_code=401, detail="Authentication is required.")


class RolePermissionMatrixTests(unittest.TestCase):
    """Exercises representative endpoints from every router against every role."""

    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="role-matrix-", dir=ROOT / ".cache")
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
        self.device_body = {
            "name": "Fake transport device", "client_type": "fake",
            "protocol": FAKE_DEVICE_PROTOCOL, "host": FAKE_DEVICE_HOST, "port": FAKE_DEVICE_PORT,
            "role_account_id": role["id"], "proxy_id": proxy["id"],
        }
        self.device = self.client.post("/api/v1/connections", json=self.device_body).json()
        self.routes = f"/api/v1/connections/{self.device['id']}/static-routes"
        self.route_body = {
            "destination": "198.51.100.0/25", "next_hop": "192.0.2.1", "interface": "eth0",
            "metric": 20, "description": "Role matrix route", "enabled": True,
        }
        self.route = self.client.post(self.routes, json=self.route_body).json()["item"]
        self.role_id = role["id"]
        self.proxy_id = proxy["id"]

    def shutdown_worker(self):
        worker = getattr(self.app.state, "management_batches", None)
        if worker:
            worker.shutdown()
            del self.app.state.management_batches

    def as_role(self, role):
        self.app.dependency_overrides[current_user] = lambda: make_user(role)

    def as_unauthenticated(self):
        self.app.dependency_overrides[current_user] = unauthenticated

    def endpoints(self):
        """(method, path, json_body, minimum_role) for a representative endpoint set."""
        return [
            ("GET", "/api/v1/capabilities", None, "Viewer"),
            ("GET", "/api/v1/connections", None, "Viewer"),
            ("GET", f"/api/v1/connections/{self.device['id']}", None, "Viewer"),
            ("GET", "/api/v1/proxies", None, "Viewer"),
            ("GET", "/api/v1/role-accounts", None, "Viewer"),
            ("GET", "/api/v1/transactions", None, "Viewer"),
            ("GET", f"/api/v1/connections/{self.device['id']}/inventory", None, "Viewer"),
            ("GET", self.routes, None, "Viewer"),
            ("POST", f"/api/v1/connections/{self.device['id']}/test", {}, "Operator"),
            ("POST", "/api/v1/connection-tests", {"connection_ids": [self.device["id"]]}, "Operator"),
            ("POST", self.routes, {**self.route_body, "destination": "203.0.113.32/28"}, "Operator"),
            ("PUT", self.routes + "/" + self.route["id"], self.route_body, "Operator"),
            ("DELETE", self.routes + "/does-not-exist", None, "Operator"),
            ("POST", "/api/v1/connections", self.device_body, "Administrator"),
            ("PUT", f"/api/v1/connections/{self.device['id']}", self.device_body, "Administrator"),
            ("DELETE", "/api/v1/connections/does-not-exist", None, "Administrator"),
            ("POST", "/api/v1/proxies", {}, "Administrator"),
            ("PUT", f"/api/v1/proxies/{self.proxy_id}", {}, "Administrator"),
            ("DELETE", "/api/v1/proxies/does-not-exist", None, "Administrator"),
            ("POST", "/api/v1/role-accounts", {}, "Administrator"),
            ("PUT", f"/api/v1/role-accounts/{self.role_id}", {}, "Administrator"),
            ("DELETE", "/api/v1/role-accounts/does-not-exist", None, "Administrator"),
            ("GET", "/api/v1/mappings/proxy_types", None, "Administrator"),
        ]

    def call(self, method, path, body):
        if method == "GET":
            return self.client.get(path)
        if method == "DELETE":
            return self.client.delete(path)
        return getattr(self.client, method.lower())(path, json=body)

    def test_every_role_below_the_required_tier_is_rejected_with_403(self):
        for method, path, body, required in self.endpoints():
            for role in ROLES:
                if ROLE_RANK[role] >= ROLE_RANK[required]:
                    continue
                with self.subTest(method=method, path=path, role=role, required=required):
                    self.as_role(role)
                    response = self.call(method, path, body)
                    self.assertEqual(response.status_code, 403, response.text)

    def test_every_role_at_or_above_the_required_tier_passes_the_gate(self):
        for method, path, body, required in self.endpoints():
            for role in ROLES:
                if ROLE_RANK[role] < ROLE_RANK[required]:
                    continue
                with self.subTest(method=method, path=path, role=role, required=required):
                    self.as_role(role)
                    response = self.call(method, path, body)
                    self.assertNotIn(response.status_code, (401, 403), response.text)

    def test_unauthenticated_requests_are_rejected_with_401_not_403(self):
        for method, path, body, _required in self.endpoints():
            with self.subTest(method=method, path=path):
                self.as_unauthenticated()
                response = self.call(method, path, body)
                self.assertEqual(response.status_code, 401, response.text)

    def test_viewer_cannot_write_anywhere_and_operator_cannot_administer(self):
        self.as_role("Viewer")
        self.assertEqual(self.client.post(self.routes, json=self.route_body).status_code, 403)
        self.assertEqual(self.client.post("/api/v1/connections", json=self.device_body).status_code, 403)
        self.as_role("Operator")
        self.assertEqual(self.client.post("/api/v1/connections", json=self.device_body).status_code, 403)
        self.assertEqual(self.client.post("/api/v1/role-accounts", json={}).status_code, 403)
        self.assertEqual(self.client.delete(f"/api/v1/connections/{self.device['id']}").status_code, 403)


if __name__ == "__main__":
    unittest.main()
