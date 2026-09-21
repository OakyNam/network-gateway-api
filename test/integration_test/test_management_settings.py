"""Credential-free operational settings through the API and real SQLite."""

import unittest
from typing import get_args
from unittest.mock import patch

from cryptography.fernet import Fernet
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.routes.management import get_management_service, router
from app.api.schemas.management import ClientClass
from app.bl.services.management import ManagementService
from app.common.identity import AuthenticatedUser, current_user
from app.dal.db.store import CLIENT_CLASSES, GatewayStore


CONFIGURATIONS = {
    "device_lookup": {"table": "inventory", "search_column": "device_name"},
    "client_mapping": {
        "key_columns": ["vendor", "software"],
        "map": {"juniper:*": "app.dal.device.nccclient_juniper.JuniperNCCClient"},
    },
    "proxy_mapping": {
        "key_columns": ["owner", "region"],
        "map": {"operations:*": "bastion.local", "default": None},
    },
}


class ManagementSettingsIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.store = GatewayStore(sqlite_path=":memory:", secret_key=Fernet.generate_key())
        self.addCleanup(self.store.close)
        service = ManagementService(self.store)
        app = FastAPI()
        app.include_router(router)
        app.dependency_overrides[get_management_service] = lambda: service
        app.dependency_overrides[current_user] = lambda: AuthenticatedUser(
            subject="test-admin", tenant_id=None, name="Test Administrator", email=None,
            roles=frozenset({"Administrator"}), auth_mode="demo",
        )
        self.client = TestClient(app)
        self.addCleanup(self.client.close)

    def test_all_settings_missing_then_round_trip_and_update(self):
        for name, payload in CONFIGURATIONS.items():
            with self.subTest(name=name):
                path = "/api/v1/mappings/" + name
                self.assertEqual(self.client.get(path).status_code, 404)
                response = self.client.put(path, json=payload)
                self.assertEqual(response.status_code, 200, response.text)
                self.assertEqual(response.json(), payload)
                self.assertEqual(self.store.get_config(name), payload)
                self.assertEqual(self.client.get(path).json(), payload)
        updated = {"table": "routers", "search_column": "hostname"}
        self.assertEqual(self.client.put("/api/v1/mappings/device_lookup", json=updated).json(), updated)
        self.assertEqual(self.store.get_config("device_lookup"), updated)

    def test_unknown_setting_and_wrong_named_schema_are_explicit(self):
        path = "/api/v1/mappings/unknown"
        self.assertEqual(self.client.get(path).status_code, 422)
        self.assertEqual(self.client.put(path, json=CONFIGURATIONS["device_lookup"]).status_code, 422)
        for name, wrong_payload in (
            ("device_lookup", CONFIGURATIONS["proxy_mapping"]),
            ("client_mapping", CONFIGURATIONS["device_lookup"]),
            ("proxy_mapping", CONFIGURATIONS["device_lookup"]),
            ("client_mapping", {"key_columns": ["vendor"], "map": {"default": "bastion.local"}}),
            ("client_mapping", {"key_columns": ["vendor"], "map": {"default": None}}),
        ):
            with self.subTest(name=name, payload=wrong_payload):
                response = self.client.put("/api/v1/mappings/" + name, json=wrong_payload)
                self.assertEqual(response.status_code, 422, response.text)
                self.assertEqual(self.client.get("/api/v1/mappings/" + name).status_code, 404)

    def test_invalid_or_secret_bearing_payloads_are_not_saved_or_reflected(self):
        cases = [
            ("device_lookup", {"table": "inventory; SECRET", "search_column": "name"}),
            ("device_lookup", {"table": "none", "search_column": "name"}),
            ("device_lookup", {"table": "inventory", "search_column": "name", "password": "SECRET"}),
            ("device_lookup", {"table": "inventory"}),
            ("client_mapping", {"key_columns": ["vendor"], "map": {"default": "SECRET.execute"}}),
            ("client_mapping", {"key_columns": ["vendor"], "map": {}}),
            ("proxy_mapping", {"key_columns": ["owner"], "map": {"default": "http://user:SECRET@host"}}),
            ("proxy_mapping", {"key_columns": ["owner"], "map": {"default": {"password": "SECRET"}}}),
            ("proxy_mapping", {"key_columns": ["owner"], "map": {"default": "host"}, "private_key": "SECRET"}),
            ("proxy_mapping", {"key_columns": ["owner", "owner"], "map": {}}),
            ("proxy_mapping", {"key_columns": [], "map": {}}),
            ("proxy_mapping", {"key_columns": ["owner"], "map": {"UPPER": "host"}}),
            ("proxy_mapping", {"key_columns": ["owner"], "map": {"bad\nkey": "host"}}),
            ("proxy_mapping", {"key_columns": ["owner"], "map": {"default": ""}}),
            ("proxy_mapping", {"key_columns": ["owner"], "map": {"default": 123}}),
        ]
        for name, payload in cases:
            with self.subTest(name=name, payload=payload):
                response = self.client.put("/api/v1/mappings/" + name, json=payload)
                self.assertEqual(response.status_code, 422, response.text)
                self.assertNotIn("SECRET", response.text)
                self.assertEqual(self.client.get("/api/v1/mappings/" + name).status_code, 404)

    def test_invalid_update_preserves_previous_configuration(self):
        path = "/api/v1/mappings/client_mapping"
        payload = CONFIGURATIONS["client_mapping"]
        self.assertEqual(self.client.put(path, json=payload).status_code, 200)
        response = self.client.put(path, json={"key_columns": ["vendor"], "map": {"default": "SECRET.execute"}})
        self.assertEqual(response.status_code, 422)
        self.assertEqual(self.client.get(path).json(), payload)

    def test_empty_proxy_mapping_is_valid_explicit_direct_default(self):
        payload = {"key_columns": ["owner"], "map": {}}
        response = self.client.put("/api/v1/mappings/proxy_mapping", json=payload)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json(), payload)

    def test_same_origin_json_guard_applies_to_settings(self):
        path = "/api/v1/mappings/device_lookup"
        payload = CONFIGURATIONS["device_lookup"]
        self.assertEqual(self.client.put(path, json=payload, headers={"Origin": "https://evil.example"}).status_code, 403)
        self.assertEqual(self.client.put(path, data=payload).status_code, 415)
        self.assertEqual(self.client.get(path).status_code, 404)

    def test_unexpected_stored_secret_fields_are_not_exposed(self):
        for method in ("get_config", "save_config"):
            with self.subTest(method=method), patch.object(self.store, method, return_value={
                **CONFIGURATIONS["device_lookup"], "password": "SECRET",
            }):
                response = (
                    self.client.get("/api/v1/mappings/device_lookup")
                    if method == "get_config" else
                    self.client.put("/api/v1/mappings/device_lookup", json=CONFIGURATIONS["device_lookup"])
                )
                self.assertEqual(response.status_code, 500)
                self.assertEqual(response.json(), {"detail": "Invalid stored management configuration."})
                self.assertNotIn("SECRET", response.text)

    def test_client_class_allowlist_matches_store(self):
        self.assertEqual(set(get_args(ClientClass)), set(CLIENT_CLASSES))

    def test_mapping_paths_are_documented_without_settings_alias(self):
        paths = self.client.get("/openapi.json").json()["paths"]
        self.assertIn("/api/v1/mappings/{name}", paths)
        self.assertNotIn("/api/v1/settings/{name}", paths)
        self.assertEqual(self.client.get("/api/v1/settings/device_lookup").status_code, 404)


if __name__ == "__main__":
    unittest.main()
