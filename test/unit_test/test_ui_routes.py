import unittest
from html.parser import HTMLParser

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.ui.routes import register_ui


class IDs(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = []

    def handle_starttag(self, tag, attrs):
        self.ids.extend(value for name, value in attrs if name == "id")


class UIRoutesTests(unittest.TestCase):
    def setUp(self):
        app = FastAPI()
        register_ui(app)
        self.client = TestClient(app)
        self.addCleanup(self.client.close)

    def test_index_has_unique_controls_and_separate_views(self):
        for url in ("/ui", "/ui/"):
            response = self.client.get(url)
            self.assertEqual(response.status_code, 200)
            self.assertIn("text/html", response.headers["content-type"])
            parser = IDs()
            parser.feed(response.text)
            self.assertEqual(len(parser.ids), len(set(parser.ids)))
            for control in (
                "connections", "test-all", "export-csv", "export-json",
                "device-editor", "view-devices", "view-proxies", "view-role-accounts",
                "api-docs-link",
                "device-details", "static-route-form", "detail-interface-rows",
                "detail-bgp-rows", "detail-lsp-rows",
                "view-transactions", "transaction-filters", "transaction-rows",
                "identity-summary", "identity-roles",
            ):
                self.assertIn(control, parser.ids)
            self.assertIn('data-page="device-editor"', response.text)

    def test_browser_module_mime_and_assets(self):
        for asset in (
            "connections.mjs", "model.mjs", "device-model.mjs", "device-details.mjs",
            "identity-model.mjs", "transactions.mjs",
        ):
            response = self.client.get(f"/ui/static/{asset}")
            self.assertEqual(response.status_code, 200)
            self.assertIn("javascript", response.headers["content-type"])
        self.assertEqual(self.client.get("/ui/static/styles.css").status_code, 200)
        self.assertEqual(self.client.get("/ui/static/missing.mjs").status_code, 404)
        self.assertEqual(self.client.get("/ui/static/ui_model.test.mjs").status_code, 404)

    def test_documentation_routes_remain_available(self):
        self.assertEqual(self.client.get("/docs").status_code, 200)
        specification = self.client.get("/openapi.json")
        self.assertEqual(specification.status_code, 200)
        self.assertIn("openapi", specification.json())


if __name__ == "__main__":
    unittest.main()
