import assert from "node:assert/strict";
import test from "node:test";
import { buildProfile, buildProxy, buildRoleAccount, validationMessage } from "../../app/ui/static/model.mjs";

const capabilities = {
  connectors: [
    { type: "direct", protocols: ["ssh", "netconf", "telnet"] },
    { type: "ssh_shell", protocols: ["telnet"] },
    { type: "ssh_tunnel", protocols: ["ssh", "netconf", "telnet"] },
  ],
};
function values(extra = {}) {
  return new Map(Object.entries({
    name: "Example", protocol: "ssh", host: "127.0.0.1", port: "8822",
    username: "demo", timeout_seconds: "5", connector_type: "direct", ...extra,
  }));
}

test("blank password is omitted to preserve saved credentials", () => {
  const profile = buildProfile(values({ password: "" }), capabilities);
  assert.equal(Object.hasOwn(profile, "password"), false);
  assert.deepEqual(profile.connector, { type: "direct" });
});
test("explicit clear and replacement passwords remain distinct", () => {
  assert.equal(buildProfile(values({ clear_password: "on" }), capabilities).password, "");
  assert.equal(buildProfile(values({ password: " fake demo " }), capabilities).password, " fake demo ");
  assert.throws(() => buildProfile(values({ password: "fake", clear_password: "on" }), capabilities));
});
test("bastion and device credentials are separate", () => {
  const profile = buildProfile(values({
    password: "device-fake", connector_type: "ssh_tunnel",
    connector_host: "127.0.0.1", connector_port: "2222",
    connector_username: "bastion", connector_password: "bastion-fake",
  }), capabilities);
  assert.equal(profile.password, "device-fake");
  assert.equal(profile.connector.password, "bastion-fake");
  assert.equal(profile.connector.port, 2222);
});
test("unsupported connector/protocol combinations fail instead of falling back", () => {
  assert.throws(() => buildProfile(values({ connector_type: "ssh_shell" }), capabilities));
  assert.throws(() => buildProfile(values({ connector_type: "unknown" }), capabilities));
});
test("invalid ports, timeout and empty destinations fail explicitly", () => {
  for (const overrides of [
    { port: "0" }, { port: "65536" }, { port: "1.5" },
    { timeout_seconds: "0" }, { timeout_seconds: "31" }, { host: " " },
    { connector_type: "ssh_tunnel", connector_host: "" },
  ]) assert.throws(() => buildProfile(values(overrides), capabilities));
});
test("validation messages do not stringify secret-bearing input fields", () => {
  const message = validationMessage([
    { loc: ["body", "port"], msg: "invalid integer", input: { password: "do-not-display" } },
  ], 422);
  assert.equal(message, "body.port: invalid integer");
  assert.ok(!message.includes("do-not-display"));
});
test("role references exclude inline secrets for devices and bastions", () => {
  const profile = buildProfile(values({
    role_account_id: "device-role", username: "obsolete", password: "obsolete",
    private_key_path: "obsolete", connector_type: "ssh_tunnel",
    connector_host: "127.0.0.1", connector_port: "2222",
    connector_role_account_id: "bastion-role",
    connector_username: "obsolete", connector_password: "obsolete",
  }), capabilities);
  assert.equal(profile.role_account_id, "device-role");
  assert.equal(profile.connector.role_account_id, "bastion-role");
  for (const target of [profile, profile.connector]) {
    for (const name of ["username", "password", "private_key_path"]) {
      assert.equal(Object.hasOwn(target, name), false);
    }
  }
});
test("role account edits preserve passwords unless explicitly replaced", () => {
  const existing = { authentication_type: "password", password_configured: true };
  const account = buildRoleAccount(values({
    name: "Readers", username: "reader", authentication_type: "password",
  }), existing);
  assert.equal(account.name, "Readers");
  assert.equal(Object.hasOwn(account, "password"), false);
  assert.equal(buildRoleAccount(values({
    authentication_type: "password", password: "new-fake-password",
  }), existing).password, "new-fake-password");
  assert.throws(() => buildRoleAccount(values({ username: "" })));
});
test("saved proxy references are sent without duplicated connector credentials", () => {
  const profile = buildProfile(values({ proxy_id: "proxy-1", password: "device-only" }), capabilities,
    [{ id: "proxy-1", type: "ssh_tunnel" }]);
  assert.equal(profile.proxy_id, "proxy-1");
  assert.equal(Object.hasOwn(profile, "connector"), false);
  assert.equal(profile.password, "device-only");
});
test("unknown saved proxies and incompatible saved proxy protocols are rejected", () => {
  assert.throws(() => buildProfile(values({ proxy_id: "missing" }), capabilities, []));
  assert.throws(() => buildProfile(values({ proxy_id: "shell" }), capabilities,
    [{ id: "shell", type: "ssh_shell" }]));
});
test("direct devices explicitly clear their proxy reference", () => {
  const profile = buildProfile(values({ proxy_id: "" }), capabilities);
  assert.equal(profile.proxy_id, null);
  assert.deepEqual(profile.connector, { type: "direct" });
});
test("shared proxy role credentials are referenced, not copied", () => {
  const proxy = buildProxy(values({
    type: "ssh_tunnel", role_account_id: "bastion-role", password: "obsolete",
  }), capabilities);
  assert.equal(proxy.role_account_id, "bastion-role");
  assert.equal(Object.hasOwn(proxy, "password"), false);
  assert.equal(Object.hasOwn(proxy, "username"), false);
  assert.throws(() => buildProxy(values({ type: "direct" }), capabilities));
});
test("role authentication is exclusively password or private key", () => {
  assert.throws(() => buildRoleAccount(values({
    authentication_type: "password", password: "fake", private_key: "FAKE KEY",
  })));
  assert.throws(() => buildRoleAccount(values({
    authentication_type: "ssh_key", password: "fake", private_key: "FAKE KEY",
  })));
  const account = buildRoleAccount(values({
    authentication_type: "ssh_key", private_key: "FAKE KEY", key_passphrase: "fake-passphrase",
  }));
  assert.equal(account.private_key, "FAKE KEY");
  assert.equal(account.key_passphrase, "fake-passphrase");
  assert.equal(Object.hasOwn(account, "password"), false);
});
test("authentication changes require new credentials and preserve only unchanged methods", () => {
  const keyAccount = { authentication_type: "ssh_key", private_key_configured: true };
  const preserved = buildRoleAccount(values({ authentication_type: "ssh_key" }), keyAccount);
  assert.equal(Object.hasOwn(preserved, "private_key"), false);
  assert.equal(Object.hasOwn(preserved, "key_passphrase"), false);
  assert.throws(() => buildRoleAccount(values({ authentication_type: "password" }), keyAccount));
  assert.throws(() => buildRoleAccount(values({
    authentication_type: "ssh_key", key_passphrase: "changed-without-key",
  }), keyAccount));
});
