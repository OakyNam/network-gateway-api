import unittest
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient

from app.common.identity import AuthenticatedUser, current_user
from app.main import app


def _admin_override():
    return AuthenticatedUser(
        subject="test-admin", tenant_id=None, name="Test Administrator", email=None,
        roles=frozenset({"Administrator"}), auth_mode="demo",
    )

def _viewer_override():
    return AuthenticatedUser(
        subject="test-viewer", tenant_id=None, name="Test Viewer", email=None,
        roles=frozenset({"Viewer"}), auth_mode="demo",
    )


class AppCompositionTests(unittest.TestCase):
    def test_ui_docs_capabilities_and_unconfigured_storage(self):
        from app.dal.db.store import StoreError

        app.dependency_overrides[current_user] = _admin_override
        self.addCleanup(app.dependency_overrides.pop, current_user, None)
        with patch("app.dal.db.store.get_store", side_effect=StoreError("Not configured", 503)):
            with TestClient(app) as client:
                self.assertEqual(client.get("/").url.path, "/ui")
                self.assertEqual(client.get("/ui").status_code, 200)
                self.assertEqual(client.get("/docs").status_code, 200)
                specification = client.get("/openapi.json").json()
                self.assertEqual(specification["info"]["title"], "Network Gateway API")
                for route in (
                    "/api/v1/connections", "/api/v1/proxies",
                    "/api/v1/role-accounts", "/api/v1/connection-tests",
                    "/api/v1/connections/{item_id}/test",
                    "/api/v1/connections/{connection_id}/inventory",
                    "/api/v1/connections/{connection_id}/static-routes",
                    "/api/v1/mappings/{name}",
                    "/devices/{device}/config",
                ):
                    self.assertIn(route, specification["paths"])
                capabilities = client.get("/api/v1/capabilities")
                self.assertEqual(capabilities.status_code, 200)
                self.assertEqual(set(capabilities.json()["protocols"]), {"ssh", "telnet", "netconf"})
                self.assertEqual(client.get("/api/v1/connections").status_code, 503)

    def test_legacy_routes_require_identity_and_disable_unaudited_mutations(self):
        path = "/protocols/router-1/protocols/bgp"
        with TestClient(app) as client:
            self.assertEqual(client.get(path).status_code, 401)
            self.assertEqual(client.put(path).status_code, 401)

            app.dependency_overrides[current_user] = _viewer_override
            self.assertEqual(client.get(path).status_code, 200)
            self.assertEqual(client.put(path).status_code, 403)

            app.dependency_overrides[current_user] = _admin_override
            response = client.put(path)
            self.assertEqual(response.status_code, 501)
            self.assertIn("audited service boundary", response.json()["detail"])
        app.dependency_overrides.pop(current_user, None)

    def test_shutdown_stops_worker_before_closing_store(self):
        order = []
        worker = Mock()
        worker.shutdown.side_effect = lambda: order.append("worker")
        store = Mock()
        store.close.side_effect = lambda: order.append("store")
        with TestClient(app):
            app.state.management_batches = worker
            app.state.management_store = store
        self.assertEqual(order, ["worker", "store"])
        self.assertIsNone(app.state.management_batches)
        self.assertIsNone(app.state.management_store)


if __name__ == "__main__":
    unittest.main()
