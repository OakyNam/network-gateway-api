import copy
import threading
import unittest
from unittest.mock import Mock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.routes.management import (
    get_batch_service, get_management_service, router, shutdown_management,
)
from app.bl.services.batches import BatchService
from app.bl.services.management import ManagementService, safe_test
from app.common.identity import AuthenticatedUser, current_user


class FakeStoreError(Exception):
    def __init__(self, code):
        super().__init__("SECRET request body password=do-not-reflect")
        self.status_code = code


class FakeStore:
    def __init__(self):
        self.rows = {"connections": {}, "proxies": {}, "role_accounts": {}}
        self.jobs = {}

    def list(self, resource):
        return list(self.rows[resource].values())

    def get(self, resource, item_id):
        if item_id not in self.rows[resource]:
            raise FakeStoreError(404)
        return copy.deepcopy(self.rows[resource][item_id])

    def save(self, resource, payload, item_id=None):
        item_id = item_id or str(len(self.rows[resource]) + 1)
        previous = self.rows[resource].get(item_id, {})
        row = {**previous, **payload, "id": item_id}
        if "password" in payload:
            row["password_configured"] = bool(payload["password"])
        self.rows[resource][item_id] = row
        return copy.deepcopy(row)

    def delete(self, resource, item_id):
        self.get(resource, item_id)
        del self.rows[resource][item_id]

    def resolve_connection(self, item_id):
        return self.get("connections", item_id)

    def create_job(self, connection_ids):
        snapshots = [(item_id, self.resolve_connection(item_id)) for item_id in connection_ids]
        if any(job["status"] in {"queued", "running"} for job in self.jobs.values()):
            raise FakeStoreError(409)
        job_id = str(len(self.jobs) + 1)
        self.jobs[job_id] = {
            "id": job_id, "status": "queued", "total": len(snapshots),
            "completed": 0, "results": [], "_snapshots": snapshots,
        }
        return self.get_job(job_id)

    def get_job(self, job_id):
        if job_id not in self.jobs:
            raise FakeStoreError(404)
        return copy.deepcopy({k: v for k, v in self.jobs[job_id].items() if not k.startswith("_")})

    def get_job_connections(self, job_id):
        return copy.deepcopy(self.jobs[job_id]["_snapshots"])

    def record_job_result(self, job_id, result):
        self.jobs[job_id]["results"].append(copy.deepcopy(result))
        self.jobs[job_id]["completed"] += 1

    def set_job_status(self, job_id, status, error=None):
        self.jobs[job_id]["status"] = status
        if error:
            self.jobs[job_id]["error"] = error


DEVICE = {
    "name": "device", "protocol": "ssh", "host": "localhost", "port": 22,
    "timeout_seconds": 2, "connector": {"type": "direct"},
}
OK = {"success": True, "stage": "authenticated", "detail": "Ready", "duration_ms": 1}


class ManagementAPITests(unittest.TestCase):
    def setUp(self):
        self.store = FakeStore()
        self.tester = Mock(return_value=OK)
        self.service = ManagementService(self.store, tester=self.tester, demo_mode=True)
        self.batches = BatchService(self.service)
        self.app = FastAPI()
        self.app.include_router(router)
        self.app.dependency_overrides[get_management_service] = lambda: self.service
        self.app.dependency_overrides[get_batch_service] = lambda: self.batches
        self.app.dependency_overrides[current_user] = lambda: AuthenticatedUser(
            subject="test-admin", tenant_id=None, name="Test Administrator", email=None,
            roles=frozenset({"Administrator"}), auth_mode="demo",
        )
        self.client = TestClient(self.app)
        self.addCleanup(self.client.close)
        self.addCleanup(self.batches.shutdown)

    def test_device_crud_redacts_secrets_and_preserves_omitted_password(self):
        body = {**DEVICE, "password": "SECRET", "connector": {
            "type": "ssh_tunnel", "host": "localhost", "port": 22, "password": "BASTION",
        }}
        response = self.client.post("/api/v1/connections", json=body)
        self.assertEqual(response.status_code, 201)
        self.assertNotIn("SECRET", response.text)
        self.assertNotIn("BASTION", response.text)
        self.assertTrue(response.json()["password_configured"])
        response = self.client.put("/api/v1/connections/1", json=DEVICE)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.store.rows["connections"]["1"]["password"], "SECRET")
        response = self.client.get("/api/v1/connections")
        self.assertEqual(len(response.json()["items"]), 1)
        self.assertNotIn("SECRET", response.text)
        self.assertEqual(self.client.get("/api/v1/connections/1").status_code, 200)
        self.assertEqual(self.client.delete("/api/v1/connections/1").status_code, 204)
        self.assertEqual(self.client.get("/api/v1/connections/1").status_code, 404)

    def test_proxy_and_role_collections_are_public(self):
        role = {"name": "role", "username": "user", "authentication_type": "ssh_key",
                "private_key": "SECRET-KEY", "key_passphrase": "SECRET-PHRASE"}
        response = self.client.post("/api/v1/role-accounts", json=role)
        self.assertEqual(response.status_code, 201)
        self.assertNotIn("SECRET", response.text)
        proxy = {"name": "proxy", "type": "socks5", "host": "localhost", "port": 1080,
                 "password": "SECRET"}
        response = self.client.post("/api/v1/proxies", json=proxy)
        self.assertEqual(response.status_code, 201)
        self.assertNotIn("SECRET", response.text)
        for path in ("proxies", "role-accounts"):
            response = self.client.get(f"/api/v1/{path}")
            self.assertEqual(len(response.json()["items"]), 1)
            self.assertNotIn("SECRET", response.text)
            updated = dict(proxy if path == "proxies" else role)
            updated["name"] = "renamed"
            response = self.client.put(f"/api/v1/{path}/1", json=updated)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["name"], "renamed")
            self.assertNotIn("SECRET", response.text)
            self.assertEqual(self.client.delete(f"/api/v1/{path}/1").status_code, 204)

    def test_validation_never_reflects_values_fields_or_context(self):
        cases = [
            {**DEVICE, "port": "SECRET"},
            {**DEVICE, "password": {"key": "SECRET"}},
            {**DEVICE, "SECRET-FIELD": "SECRET"},
            {**DEVICE, "role_account_id": "role", "password": "SECRET"},
            {**DEVICE, "proxy_id": "proxy"},
            {**DEVICE, "timeout_seconds": True},
        ]
        for body in cases:
            with self.subTest(body=body):
                response = self.client.post("/api/v1/connections", json=body)
                self.assertEqual(response.status_code, 422)
                self.assertEqual(response.json(), {"detail": "Invalid request fields."})
        response = self.client.post("/api/v1/connections", content='{"SECRET":',
                                    headers={"Content-Type": "application/json"})
        self.assertEqual(response.status_code, 422)
        self.assertNotIn("SECRET", response.text)

    def test_exclusive_role_authentication(self):
        for auth, extra in [
            ("password", {"private_key": "SECRET"}),
            ("ssh_key", {"password": "SECRET"}),
            ("ssh_key", {"key_passphrase": "SECRET"}),
        ]:
            response = self.client.post("/api/v1/role-accounts", json={
                "name": "test", "username": "user", "authentication_type": auth, **extra,
            })
            self.assertEqual(response.status_code, 422)
            self.assertNotIn("SECRET", response.text)

    def test_single_test_is_bl_owned_and_missing_device_is_404(self):
        self.store.save("connections", DEVICE)
        response = self.client.post("/api/v1/connections/1/test", json={})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {**OK, "simulated": False})
        self.tester.assert_called_once()
        self.assertTrue(self.tester.call_args.kwargs["demo_mode"])
        self.assertEqual(self.client.post("/api/v1/connections/missing/test", json={}).status_code, 404)
        self.tester.assert_called_once()

    def test_single_test_optional_json_body_and_openapi_documentation(self):
        self.store.save("connections", DEVICE)
        operation = self.client.get("/openapi.json").json()["paths"]["/api/v1/connections/{item_id}/test"]["post"]
        body = operation["requestBody"]
        self.assertFalse(body.get("required", False))
        content = body["content"]["application/json"]
        self.assertEqual(content["schema"]["default"], {})
        self.assertEqual(content["examples"]["empty"]["value"], {})
        schemas = self.app.openapi()["components"]["schemas"]
        self.assertFalse(schemas["ConnectionTestWrite"]["additionalProperties"])
        self.assertEqual(schemas["ConnectionTestWrite"]["properties"], {})
        for kwargs in (
            {"json": {}},
            {"headers": {"Content-Type": "application/json"}},
        ):
            response = self.client.post("/api/v1/connections/1/test", **kwargs)
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.json(), {**OK, "simulated": False})
        response = self.client.post("/api/v1/connections/1/test", json={"password": "SECRET"})
        self.assertEqual(response.status_code, 422)
        self.assertNotIn("SECRET", response.text)
        self.assertEqual(self.client.post("/api/v1/connections/1/test").status_code, 415)
        self.assertEqual(self.tester.call_count, 2)

    def test_storage_errors_do_not_echo_driver_errors(self):
        for code in (400, 404, 409, 422, 500, 503):
            with patch.object(self.store, "list", side_effect=FakeStoreError(code)):
                response = self.client.get("/api/v1/connections")
                self.assertEqual(response.status_code, code)
                self.assertNotIn("SECRET", response.text)
                self.assertNotIn("password", response.text)

    def test_store_initialization_failure_logs_generic_error_and_returns_503(self):
        app = FastAPI()
        app.include_router(router)
        app.dependency_overrides[current_user] = lambda: AuthenticatedUser(
            subject="test-admin", tenant_id=None, name="Test Administrator", email=None,
            roles=frozenset({"Administrator"}), auth_mode="demo",
        )
        with TestClient(app) as client, \
                patch("app.dal.db.store.get_store", side_effect=RuntimeError("password=SECRET")), \
                self.assertLogs("app.api.routes.management", level="ERROR") as logs:
            response = client.get("/api/v1/connections")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json(), {"detail": "Management storage is unavailable."})
        self.assertIn("Management storage could not be initialized.", logs.output[0])
        self.assertNotIn("SECRET", str(logs.output))
        self.assertNotIn("SECRET", response.text)
        self.assertIsNone(logs.records[0].exc_info)

    def test_browser_cross_origin_mutations_are_rejected(self):
        for headers in [
            {"Origin": "https://evil.example"},
            {"Origin": "null"},
            {"Sec-Fetch-Site": "cross-site"},
            {"Sec-Fetch-Site": "same-site"},
            {"Origin": "http://testserver:9999"},
        ]:
            self.assertEqual(self.client.post("/api/v1/connections", json=DEVICE,
                                             headers=headers).status_code, 403)
            self.assertEqual(self.client.delete("/api/v1/connections/1", headers=headers).status_code, 403)
        self.assertEqual(self.client.post("/api/v1/connections", json=DEVICE,
                                         headers={"Origin": "http://testserver"}).status_code, 201)
        self.assertEqual(self.client.post("/api/v1/connections/1/test").status_code, 415)
        self.assertEqual(self.client.post("/api/v1/connections", data={"name": "device"}).status_code, 415)

    def test_capabilities_do_not_require_storage(self):
        expected = {"protocols": ["ssh", "netconf", "telnet"], "connectors": [{
            "type": "direct", "label": "Direct", "protocols": ["ssh", "netconf", "telnet"],
            "description": "Direct access",
        }]}
        with patch("app.api.routes.management.capabilities", return_value=expected):
            self.assertEqual(self.client.get("/api/v1/capabilities").json(), expected)

    def test_batch_routes_and_attachment_headers(self):
        self.store.save("connections", DEVICE)
        response = self.client.post("/api/v1/connection-tests", json={"connection_ids": ["1"]})
        self.assertEqual(response.status_code, 202)
        self.batches._future.result(timeout=3)
        job_id = response.json()["id"]
        self.assertEqual(self.client.get(f"/api/v1/connection-tests/{job_id}").json()["completed"], 1)
        for format in ("csv", "json"):
            response = self.client.get(f"/api/v1/connection-tests/{job_id}/export?format={format}")
            self.assertEqual(response.status_code, 200)
            self.assertIn("attachment;", response.headers["content-disposition"])
            self.assertEqual(response.headers["x-content-type-options"], "nosniff")
            self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertEqual(self.client.get(f"/api/v1/connection-tests/{job_id}/export?format=xml").status_code, 422)
        self.assertEqual(self.client.get("/api/v1/connection-tests/missing").status_code, 404)
        self.assertEqual(self.client.post("/api/v1/connection-tests",
                                         json={"connection_ids": ["missing"]}).status_code, 404)

    def test_invalid_batch_selection(self):
        for ids in ([], ["1", "1"], [""], ["a" * 129], [False]):
            self.assertEqual(self.client.post("/api/v1/connection-tests",
                                             json={"connection_ids": ids}).status_code, 422)

    def test_running_batch_does_not_block_api_and_reports_progress(self):
        started, release = threading.Event(), threading.Event()

        def tester(profile, **kwargs):
            started.set()
            if not release.wait(3):
                raise RuntimeError("Timed out waiting for test release")
            return OK

        self.service.tester = tester
        self.addCleanup(release.set)
        self.store.save("connections", DEVICE)
        response = self.client.post("/api/v1/connection-tests", json={"connection_ids": ["1"]})
        self.assertEqual(response.status_code, 202)
        self.assertTrue(started.wait(3))
        response = self.client.get("/api/v1/connection-tests/1")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "running")
        self.assertEqual(response.json()["completed"], 0)
        self.assertEqual(self.client.get("/api/v1/connections").status_code, 200)
        self.assertEqual(self.client.get("/api/v1/connection-tests/1/export").status_code, 409)
        self.assertEqual(self.client.post("/api/v1/connection-tests",
                                         json={"connection_ids": ["1"]}).status_code, 409)
        release.set()
        self.batches._future.result(timeout=3)

    def test_clear_password_and_same_auth_role_update_reach_store_unchanged(self):
        self.client.post("/api/v1/connections", json={**DEVICE, "password": "SECRET"})
        response = self.client.put("/api/v1/connections/1", json={**DEVICE, "password": ""})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()["password_configured"])
        role = {"name": "role", "username": "user", "authentication_type": "password"}
        self.client.post("/api/v1/role-accounts", json={**role, "password": "SECRET"})
        with patch.object(self.store, "save", wraps=self.store.save) as save:
            response = self.client.put("/api/v1/role-accounts/1", json=role)
            self.assertEqual(response.status_code, 200)
            self.assertNotIn("password", save.call_args.args[1])
        self.assertTrue(response.json()["password_configured"])

    def test_invalid_store_response_is_generic(self):
        with patch.object(self.store, "list", return_value=[{"password": "SECRET"}]):
            response = self.client.get("/api/v1/connections")
            self.assertEqual(response.status_code, 500)
            self.assertEqual(response.json(), {"detail": "Invalid management response."})

    def test_safe_result_handles_secret_exception_and_long_keys(self):
        key = "K" * 5000
        result = safe_test({"private_key": key}, lambda *a, **k: {**OK, "detail": key})
        self.assertEqual(result["detail"], "[redacted]")
        result = safe_test({"password": "SECRET"}, Mock(side_effect=RuntimeError("SECRET")))
        self.assertFalse(result["success"])
        self.assertNotIn("SECRET", str(result))
        result = safe_test({"password": "SECRET", "connector": {"password": "BASTION"}},
                           lambda *a, **k: {**OK, "detail": "SECRET BASTION", "duration_ms": float("nan")})
        self.assertEqual(result["detail"], "[redacted] [redacted]")
        self.assertGreaterEqual(result["duration_ms"], 0)
        result = safe_test({}, lambda *a, **k: {
            **OK, "detail": "Bad key: -----BEGIN OPENSSH PRIVATE KEY-----\npartial key",
        })
        self.assertEqual(result["detail"], "Bad key: [redacted]")

    def test_network_results_cannot_claim_to_be_simulated(self):
        self.store.save("connections", DEVICE)
        self.tester.return_value = {**OK, "simulated": True}
        response = self.client.post("/api/v1/connections/1/test", json={})
        self.assertEqual(response.status_code, 200)
        self.assertIs(response.json()["simulated"], False)


if __name__ == "__main__":
    unittest.main()
