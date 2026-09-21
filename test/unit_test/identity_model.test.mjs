import assert from "node:assert/strict";
import test from "node:test";
import { normalizeSession, permissions, transactionQuery } from "../../app/ui/static/identity-model.mjs";

const session = (roles, auth_mode = "entra") => normalizeSession({ user: {
  subject: "user-id", tenant_id: "tenant-id", name: "Example User",
  email: "user@example.invalid", roles, auth_mode,
} });

test("viewer reads normalized data and transactions but cannot mutate or test", () => {
  assert.deepEqual(permissions(session(["Viewer"])), {
    viewer: true, operator: false, administrator: false, read: true, test: false,
    configureDevice: false, manageProfiles: false, manageAccess: false, viewTransactions: true,
  });
});
test("operator tests and configures devices but cannot manage profiles or credentials", () => {
  const value = permissions(session(["Operator"]));
  assert.equal(value.test, true);
  assert.equal(value.configureDevice, true);
  assert.equal(value.manageProfiles, false);
  assert.equal(value.manageAccess, false);
});
test("administrator receives every application permission", () => {
  assert.ok(Object.values(permissions(session(["Administrator"]))).every(Boolean));
});
test("roles are deduplicated and unsupported roles do not grant permissions", () => {
  assert.deepEqual(session(["Viewer", "Viewer", "Unknown"]).user.roles, ["Viewer"]);
  assert.throws(() => session(["Unknown"]));
});
test("session requires server-provided subject, name and supported roles", () => {
  for (const payload of [null, {}, { user: {} }, { user: { subject: "s", name: "n", roles: [] } }]) {
    assert.throws(() => normalizeSession(payload));
  }
});
test("demo and Entra modes stay distinguishable", () => {
  assert.equal(session(["Viewer"], "demo").user.auth_mode, "demo");
  assert.equal(session(["Viewer"], "entra").user.auth_mode, "entra");
});
test("transaction filters are encoded and bounded", () => {
  assert.equal(transactionQuery({ action: "static route/create", outcome: "failed", limit: 25, offset: 50 }),
    "action=static+route%2Fcreate&outcome=failed&limit=25&offset=50");
  for (const value of [{ limit: 0 }, { limit: 201 }, { limit: 1.5 }, { offset: -1 }]) {
    assert.throws(() => transactionQuery(value));
  }
});
