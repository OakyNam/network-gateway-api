"""Real SQLite persistence behind the API; connection tests never use a network."""

import io
import threading
import unittest
from unittest.mock import patch

import paramiko
from cryptography.fernet import Fernet
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.routes.management import get_batch_service, get_management_service, router
from app.bl.services.batches import BatchService
from app.bl.services.management import ManagementService
from app.common.identity import AuthenticatedUser, current_user
from app.dal.db.store import GatewayStore


DEVICE = {
    "name": "local fixture", "protocol": "ssh", "host": "127.0.0.1", "port": 2222,
    "timeout_seconds": 2, "role_account_id": None, "proxy_id": None,
    "private_key_path": None, "known_hosts_path": None, "username": "fixture",
    "connector": {"type": "direct"},
}
OK = {"success": True, "stage": "authenticated", "detail": "Fixture only", "duration_ms": 1}


class ManagementStoreIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.store = GatewayStore(sqlite_path=":memory:", secret_key=Fernet.generate_key())
        self.addCleanup(self.store.close)
        self.seen = []

        def tester(profile, **kwargs):
            self.seen.append(profile)
            return OK

        self.management = ManagementService(self.store, tester=tester)
        self.batches = BatchService(self.management)
        self.addCleanup(self.batches.shutdown)
        app = FastAPI()
        app.include_router(router)
        app.dependency_overrides[get_management_service] = lambda: self.management
        app.dependency_overrides[get_batch_service] = lambda: self.batches
        app.dependency_overrides[current_user] = lambda: AuthenticatedUser(
            subject="test-admin", tenant_id=None, name="Test Administrator", email=None,
            roles=frozenset({"Administrator"}), auth_mode="demo",
        )
        self.client = TestClient(app)
        self.addCleanup(self.client.close)

    def post(self, path, payload):
        response = self.client.post("/api/v1/" + path, json=payload)
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()

    def test_ui_null_paths_inline_password_preservation_and_clear(self):
        device = self.post("connections", {**DEVICE, "password": "fixture-secret"})
        self.assertTrue(device["password_configured"])
        self.assertNotIn("fixture-secret", str(device))
        device_id = device["id"]
        response = self.client.put("/api/v1/connections/" + device_id, json=DEVICE)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertTrue(response.json()["password_configured"])
        response = self.client.post(f"/api/v1/connections/{device_id}/test", json={})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.seen[-1]["password"], "fixture-secret")
        response = self.client.put("/api/v1/connections/" + device_id,
                                   json={**DEVICE, "password": ""})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()["password_configured"])

    def test_shared_role_proxy_latest_credentials_and_reference_safety(self):
        role = self.post("role-accounts", {
            "name": "shared login", "username": "fixture",
            "authentication_type": "password", "password": "old-fixture-secret",
        })
        proxy = self.post("proxies", {
            "name": "shared proxy", "type": "socks5", "host": "127.0.0.1", "port": 1080,
            "known_hosts_path": None, "role_account_id": role["id"],
        })
        device_body = {
            key: value for key, value in DEVICE.items()
            if key not in {"username", "private_key_path", "connector"}
        }
        device_body.update(role_account_id=role["id"], proxy_id=proxy["id"])
        device = self.post("connections", device_body)
        self.assertEqual(device["connector"]["type"], "socks5")
        for path, item in (("role-accounts", role), ("proxies", proxy)):
            self.assertEqual(self.client.delete(f"/api/v1/{path}/{item['id']}").status_code, 409)
        response = self.client.put(f"/api/v1/role-accounts/{role['id']}", json={
            "name": "shared login", "username": "fixture",
            "authentication_type": "password", "password": "new-fixture-secret",
        })
        self.assertEqual(response.status_code, 200)
        response = self.client.post(f"/api/v1/connections/{device['id']}/test", json={})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.seen[-1]["password"], "new-fixture-secret")
        self.assertEqual(self.seen[-1]["connector"]["password"], "new-fixture-secret")
        self.assertNotIn("fixture-secret", self.client.get("/api/v1/connections").text)

    def test_real_key_auth_switch_preserves_then_clears_secret(self):
        key_buffer = io.StringIO()
        paramiko.RSAKey.generate(2048).write_private_key(key_buffer)
        role_body = {"name": "key login", "username": "fixture", "authentication_type": "ssh_key"}
        role = self.post("role-accounts", {**role_body, "private_key": key_buffer.getvalue()})
        self.assertTrue(role["private_key_configured"])
        self.assertNotIn("PRIVATE KEY", str(role))
        response = self.client.put(f"/api/v1/role-accounts/{role['id']}", json=role_body)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["private_key_configured"])
        password_body = {**role_body, "authentication_type": "password"}
        response = self.client.put(f"/api/v1/role-accounts/{role['id']}", json=password_body)
        self.assertEqual(response.status_code, 400)
        self.assertTrue(self.store.get("role_accounts", role["id"])["private_key_configured"])
        response = self.client.put(f"/api/v1/role-accounts/{role['id']}",
                                   json={**password_body, "password": "replacement-fixture-secret"})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()["private_key_configured"])
        self.assertTrue(response.json()["password_configured"])
        response = self.client.put(f"/api/v1/role-accounts/{role['id']}",
                                   json={**role_body, "private_key": "INVALID-SECRET-KEY"})
        self.assertEqual(response.status_code, 400)
        self.assertNotIn("INVALID-SECRET-KEY", response.text)
        self.assertTrue(self.store.get("role_accounts", role["id"])["password_configured"])

    def test_switching_device_to_role_clears_obsolete_inline_credentials(self):
        device = self.post("connections", {**DEVICE, "password": "obsolete-fixture-secret"})
        role = self.post("role-accounts", {
            "name": "selected login", "username": "role-user",
            "authentication_type": "password", "password": "role-fixture-secret",
        })
        role_device = {
            key: value for key, value in DEVICE.items()
            if key not in {"username", "private_key_path"}
        }
        role_device["role_account_id"] = role["id"]
        response = self.client.put(f"/api/v1/connections/{device['id']}", json=role_device)
        self.assertEqual(response.status_code, 200, response.text)
        resolved = self.store.resolve_connection(device["id"])
        self.assertEqual(resolved["username"], "role-user")
        self.assertEqual(resolved["password"], "role-fixture-secret")
        response = self.client.put(f"/api/v1/connections/{device['id']}", json=DEVICE)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertFalse(response.json()["password_configured"])
        self.assertNotIn("password", self.store.resolve_connection(device["id"]))

    def test_real_job_snapshots_updates_progress_and_exports(self):
        first = self.post("connections", {**DEVICE, "password": "original-fixture-secret"})
        second = self.post("connections", {**DEVICE, "name": "=FORMULA", "password": "original-fixture-secret"})
        started, release = threading.Event(), threading.Event()
        seen = []

        def tester(profile, **kwargs):
            seen.append(profile)
            started.set()
            if not release.wait(3):
                raise RuntimeError("Fixture release timed out")
            return {**OK, "detail": "original-fixture-secret"}

        self.management.tester = tester
        self.addCleanup(release.set)
        response = self.client.post("/api/v1/connection-tests",
                                    json={"connection_ids": [first["id"], second["id"]]})
        self.assertEqual(response.status_code, 202, response.text)
        job_id = response.json()["id"]
        self.assertTrue(started.wait(3))
        self.store.save("connections", {**DEVICE, "password": "changed-fixture-secret"}, second["id"])
        self.assertEqual(self.client.get(f"/api/v1/connection-tests/{job_id}/export").status_code, 409)
        release.set()
        self.batches._future.result(timeout=3)
        self.assertEqual(seen[1]["password"], "original-fixture-secret")
        job = self.client.get(f"/api/v1/connection-tests/{job_id}").json()
        self.assertEqual(job["status"], "completed")
        self.assertEqual(job["completed"], 2)
        self.assertNotIn("fixture-secret", str(job))
        self.assertEqual(job["results"][1]["name"], "=FORMULA")
        for format in ("json", "csv"):
            exported = self.client.get(f"/api/v1/connection-tests/{job_id}/export?format={format}")
            self.assertEqual(exported.status_code, 200)
            self.assertNotIn("fixture-secret", exported.text)
            if format == "csv":
                self.assertIn("'=FORMULA", exported.text)

    def test_connector_capabilities_match_public_api_schema(self):
        response = self.client.get("/api/v1/capabilities")
        self.assertEqual(response.status_code, 200, response.text)
        connectors = {item["type"]: item["protocols"] for item in response.json()["connectors"]}
        self.assertEqual(set(connectors), {"direct", "ssh_tunnel", "ssh_shell", "socks5", "http_connect"})
        self.assertEqual(connectors["ssh_shell"], ["telnet"])
        self.assertEqual(sum(len(protocols) for protocols in connectors.values()), 13)

    def test_default_dependencies_pass_demo_policy_to_real_runner_without_network(self):
        device = self.post("connections", {
            **DEVICE, "host": "outside.invalid", "password": "fixture-secret",
        })
        app = FastAPI()
        app.include_router(router)
        app.state.demo_mode = True
        app.dependency_overrides[current_user] = lambda: AuthenticatedUser(
            subject="test-admin", tenant_id=None, name="Test Administrator", email=None,
            roles=frozenset({"Administrator"}), auth_mode="demo",
        )
        with TestClient(app) as client, \
                patch("app.dal.db.store.get_store", return_value=self.store), \
                patch("socket.getaddrinfo") as dns, \
                patch("socket.create_connection") as connect:
            response = client.post(f"/api/v1/connections/{device['id']}/test", json={})
            self.assertEqual(response.status_code, 200, response.text)
            self.assertFalse(response.json()["success"])
            self.assertEqual(response.json()["stage"], "demo_policy")
            self.assertIs(app.state.management_store, self.store)
            response = client.post("/api/v1/connection-tests",
                                   json={"connection_ids": [device["id"]]})
            self.assertEqual(response.status_code, 202, response.text)
            worker = app.state.management_batches
            self.addCleanup(worker.shutdown)
            worker._future.result(timeout=3)
            job = client.get("/api/v1/connection-tests/" + response.json()["id"]).json()
            self.assertEqual(job["status"], "completed")
            self.assertEqual(job["results"][0]["stage"], "demo_policy")
            dns.assert_not_called()
            connect.assert_not_called()


if __name__ == "__main__":
    unittest.main()
