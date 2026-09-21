import shutil
import unittest
import uuid
from pathlib import Path

from cryptography.fernet import Fernet
from sqlalchemy import insert, select

from app.dal.db.storage import gateway_transactions, static_routes
from app.dal.db.store import GatewayStore, StoreError


class TransactionsStoreTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(__file__).resolve().parents[2] / ".cache" / ("transactions-tests-" + uuid.uuid4().hex)
        self.directory.mkdir(parents=True)
        self.path = self.directory / "inventory.sqlite"
        self.key = Fernet.generate_key()
        self.store = GatewayStore(sqlite_path=self.path, secret_key=self.key)

    def tearDown(self):
        self.store.close()
        shutil.rmtree(self.directory)

    def reopen(self):
        self.store.close()
        self.store = GatewayStore(sqlite_path=self.path, secret_key=self.key)

    def fake_connection(self, **overrides):
        return self.store.save("connections", {
            "name": "Router", "protocol": "ssh", "host": "127.0.0.1", "port": 22,
            "username": "operator", "password": "device-unique-password",
            "client_type": "fake", **overrides,
        })

    def audit(self, **overrides):
        return {
            "correlation_id": str(uuid.uuid4()),
            "actor_subject": "user-123",
            "actor_tenant_id": str(uuid.uuid4()),
            "actor_name": "Ada Operator",
            "actor_email": "ada@example.com",
            "actor_roles": ["Operator"],
            "auth_mode": "entra",
            "action": "static_route.create",
            "request_method": "POST",
            "request_path": "/api/v1/connections/x/static-routes",
            **overrides,
        }

    def route_payload(self, **overrides):
        return {
            "destination": "10.0.0.0/24", "next_hop": "10.0.0.1", "interface": "eth0",
            "metric": 5, "description": "Test route", "enabled": True, **overrides,
        }

    def assert_error(self, status, operation):
        with self.assertRaises(StoreError) as error:
            operation()
        self.assertEqual(error.exception.status_code, status)
        return str(error.exception)

    # -- append_transaction: validation, immutability, normalization ----------------

    def test_append_transaction_normalizes_id_timestamp_and_roles(self):
        connection = self.fake_connection()
        record = self.store.append_transaction(self.audit(
            resource_type="static_route", resource_id="missing-route", connection_id=connection["id"],
            outcome="failed", detail="attempted mutation",
        ))
        self.assertTrue(uuid.UUID(record["id"]))
        self.assertTrue(uuid.UUID(record["correlation_id"]))
        self.assertTrue(record["timestamp_utc"].endswith("Z"))
        self.assertEqual(record["actor_roles"], ["Operator"])
        self.assertEqual(record["outcome"], "failed")
        self.assertEqual(record["connection_id"], connection["id"])

    def test_append_transaction_requires_valid_uuid_fields(self):
        self.assert_error(400, lambda: self.store.append_transaction(self.audit(
            correlation_id="not-a-uuid", resource_type="static_route", outcome="failed",
        )))
        self.assert_error(400, lambda: self.store.append_transaction(self.audit(
            connection_id="not-a-uuid", resource_type="static_route", outcome="failed",
        )))

    def test_append_transaction_rejects_unknown_roles_and_outcome(self):
        self.assert_error(400, lambda: self.store.append_transaction(self.audit(
            actor_roles=["SuperAdmin"], resource_type="static_route", outcome="failed",
        )))
        self.assert_error(400, lambda: self.store.append_transaction(self.audit(
            resource_type="static_route", outcome="unknown",
        )))

    def test_append_transaction_requires_actor_identity(self):
        self.assert_error(400, lambda: self.store.append_transaction(self.audit(
            actor_subject=None, resource_type="static_route", outcome="failed",
        )))

    def test_gateway_store_exposes_no_update_or_delete_transaction_api(self):
        self.assertFalse(hasattr(self.store, "update_transaction"))
        self.assertFalse(hasattr(self.store, "delete_transaction"))

    def test_transaction_rows_cannot_be_mutated_directly_without_bypassing_store(self):
        record = self.store.append_transaction(self.audit(resource_type="static_route", outcome="failed"))
        with self.store.engine.begin() as db:
            row = db.execute(select(gateway_transactions).where(
                gateway_transactions.c.id == record["id"],
            )).mappings().one()
        self.assertEqual(dict(row), record)

    # -- recursive secret redaction (defense-in-depth) ------------------------------

    def test_redacts_sensitive_keys_recursively_in_before_after_state(self):
        record = self.store.append_transaction(self.audit(
            resource_type="static_route", outcome="failed",
            before_state={"nested": {"password": "super-secret", "ok": "fine"}},
            after_state={"entries": [{"token": "abc123"}]},
        ))
        self.assertEqual(record["before_state"]["nested"]["password"], "[redacted]")
        self.assertEqual(record["before_state"]["nested"]["ok"], "fine")
        self.assertEqual(record["after_state"]["entries"][0]["token"], "[redacted]")

    def test_redacts_secret_value_patterns_in_free_text_detail(self):
        record = self.store.append_transaction(self.audit(
            resource_type="static_route", outcome="failed",
            detail="Authorization: Bearer abc.def123-XYZ failed unexpectedly",
        ))
        self.assertNotIn("abc.def123-XYZ", record["detail"])
        self.assertIn("[redacted]", record["detail"])

    def test_redacts_pem_private_key_in_detail(self):
        pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END RSA PRIVATE KEY-----"
        record = self.store.append_transaction(self.audit(
            resource_type="static_route", outcome="failed", detail=f"leaked key: {pem}",
        ))
        self.assertNotIn("MIIB", record["detail"])

    # -- list_transactions: filters, pagination --------------------------------------

    def test_list_transactions_filters_by_connection_action_actor_and_outcome(self):
        connection_a = self.fake_connection(name="A")
        connection_b = self.fake_connection(name="B")
        self.store.append_transaction(self.audit(
            resource_type="static_route", connection_id=connection_a["id"], outcome="succeeded",
            action="static_route.create", actor_subject="alice",
        ))
        self.store.append_transaction(self.audit(
            resource_type="static_route", connection_id=connection_b["id"], outcome="failed",
            action="static_route.delete", actor_subject="bob",
        ))

        by_connection = self.store.list_transactions({"connection_id": connection_a["id"]})
        self.assertEqual(len(by_connection["items"]), 1)
        self.assertEqual(by_connection["items"][0]["connection_id"], connection_a["id"])

        by_action = self.store.list_transactions({"action": "static_route.delete"})
        self.assertEqual(len(by_action["items"]), 1)
        self.assertEqual(by_action["items"][0]["actor_subject"], "bob")

        by_actor = self.store.list_transactions({"actor_subject": "alice"})
        self.assertEqual(len(by_actor["items"]), 1)

        by_outcome = self.store.list_transactions({"outcome": "failed"})
        self.assertEqual(len(by_outcome["items"]), 1)
        self.assertEqual(by_outcome["items"][0]["outcome"], "failed")

    def test_list_transactions_paginates_newest_first(self):
        for index in range(5):
            self.store.append_transaction(self.audit(
                resource_type="static_route", outcome="succeeded", action=f"static_route.action_{index}",
            ))
        page = self.store.list_transactions(limit=2, offset=0)
        self.assertEqual(page["total"], 5)
        self.assertEqual(len(page["items"]), 2)
        self.assertEqual(page["items"][0]["action"], "static_route.action_4")
        next_page = self.store.list_transactions(limit=2, offset=2)
        self.assertEqual(next_page["items"][0]["action"], "static_route.action_2")

    def test_list_transactions_rejects_invalid_pagination_and_filters(self):
        self.assert_error(400, lambda: self.store.list_transactions(limit=0))
        self.assert_error(400, lambda: self.store.list_transactions(limit=501))
        self.assert_error(400, lambda: self.store.list_transactions(offset=-1))
        self.assert_error(400, lambda: self.store.list_transactions({"outcome": "bogus"}))
        self.assert_error(400, lambda: self.store.list_transactions({"connection_id": "not-a-uuid"}))

    # -- atomic audited static-route mutation: commit together ----------------------

    def test_create_static_route_audited_commits_route_and_audit_together(self):
        connection = self.fake_connection()
        route = self.store.create_static_route_audited(
            connection["id"], self.route_payload(), self.audit(),
        )
        routes = self.store.list_static_routes(connection["id"])
        self.assertTrue(any(r["id"] == route["id"] for r in routes))

        transactions = self.store.list_transactions({"connection_id": connection["id"]})["items"]
        matches = [t for t in transactions if t["resource_id"] == route["id"]]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["outcome"], "succeeded")
        self.assertIsNone(matches[0]["before_state"])
        self.assertEqual(matches[0]["after_state"]["destination"], "10.0.0.0/24")

    def test_update_static_route_audited_records_before_and_after(self):
        connection = self.fake_connection()
        route = self.store.create_static_route_audited(connection["id"], self.route_payload(), self.audit())
        updated = self.store.update_static_route_audited(
            connection["id"], route["id"], self.route_payload(metric=42), self.audit(action="static_route.update"),
        )
        self.assertEqual(updated["metric"], 42)
        transactions = self.store.list_transactions({"action": "static_route.update"})["items"]
        self.assertEqual(len(transactions), 1)
        self.assertEqual(transactions[0]["before_state"]["metric"], 5)
        self.assertEqual(transactions[0]["after_state"]["metric"], 42)

    def test_delete_static_route_audited_records_before_state_only(self):
        connection = self.fake_connection()
        route = self.store.create_static_route_audited(connection["id"], self.route_payload(), self.audit())
        self.store.delete_static_route_audited(connection["id"], route["id"], self.audit(action="static_route.delete"))
        routes = self.store.list_static_routes(connection["id"])
        self.assertFalse(any(r["id"] == route["id"] for r in routes))
        transactions = self.store.list_transactions({"action": "static_route.delete"})["items"]
        self.assertEqual(len(transactions), 1)
        self.assertEqual(transactions[0]["before_state"]["destination"], "10.0.0.0/24")
        self.assertIsNone(transactions[0]["after_state"])

    # -- atomic rollback: audit failure must roll back the route change -------------

    def test_create_static_route_audited_rolls_back_route_when_audit_invalid(self):
        connection = self.fake_connection()
        self.assert_error(400, lambda: self.store.create_static_route_audited(
            connection["id"], self.route_payload(), self.audit(actor_subject=None),
        ))
        routes = self.store.list_static_routes(connection["id"])
        self.assertFalse(any(r["destination"] == "10.0.0.0/24" for r in routes))
        self.assertEqual(self.store.list_transactions({"connection_id": connection["id"]})["items"], [])

    def test_update_static_route_audited_rolls_back_route_when_audit_invalid(self):
        connection = self.fake_connection()
        route = self.store.create_static_route_audited(connection["id"], self.route_payload(), self.audit())
        self.assert_error(400, lambda: self.store.update_static_route_audited(
            connection["id"], route["id"], self.route_payload(metric=999),
            self.audit(actor_roles=["NotARole"]),
        ))
        current = next(r for r in self.store.list_static_routes(connection["id"]) if r["id"] == route["id"])
        self.assertEqual(current["metric"], 5)

    def test_delete_static_route_audited_rolls_back_delete_when_audit_invalid(self):
        connection = self.fake_connection()
        route = self.store.create_static_route_audited(connection["id"], self.route_payload(), self.audit())
        self.assert_error(400, lambda: self.store.delete_static_route_audited(
            connection["id"], route["id"], self.audit(actor_subject=None),
        ))
        self.assertTrue(any(r["id"] == route["id"] for r in self.store.list_static_routes(connection["id"])))

    def test_failed_static_route_attempt_can_be_audited_separately(self):
        connection = self.fake_connection()
        with self.assertRaises(StoreError):
            self.store.create_static_route_audited(connection["id"], self.route_payload(metric=-1), self.audit())
        # Nothing was written for the failed attempt automatically...
        self.assertEqual(self.store.list_transactions({"connection_id": connection["id"]})["items"], [])
        # ...but the caller can append a failed record independently.
        record = self.store.append_transaction(self.audit(
            resource_type="static_route", connection_id=connection["id"], outcome="failed",
            detail="invalid metric",
        ))
        self.assertEqual(record["outcome"], "failed")
        self.assertEqual(len(self.store.list_transactions({"connection_id": connection["id"]})["items"]), 1)

    # -- durability across reopen -----------------------------------------------------

    def test_transactions_and_route_state_survive_reopen(self):
        connection = self.fake_connection()
        route = self.store.create_static_route_audited(connection["id"], self.route_payload(), self.audit())
        self.reopen()
        routes = self.store.list_static_routes(connection["id"])
        self.assertTrue(any(r["id"] == route["id"] for r in routes))
        transactions = self.store.list_transactions({"connection_id": connection["id"]})["items"]
        self.assertEqual(len(transactions), 1)
        self.assertEqual(transactions[0]["resource_id"], route["id"])


if __name__ == "__main__":
    unittest.main()
