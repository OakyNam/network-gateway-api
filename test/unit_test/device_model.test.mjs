import assert from "node:assert/strict";
import test from "node:test";
import { buildStaticRoute, parseDetailsRoute } from "../../app/ui/static/device-model.mjs";
import { buildProfile } from "../../app/ui/static/model.mjs";

const routeValues = (extra = {}) => new Map(Object.entries({
  destination: "198.51.100.0/24", next_hop: "192.0.2.1",
  interface: "eth0", metric: "1", description: "Demo route", enabled: "on", ...extra,
}));

test("device details default to overview and unrelated views remain untouched", () => {
  assert.deepEqual(parseDetailsRoute("#devices/device-1/details"), { id: "device-1", section: "overview", subpage: null });
  assert.equal(parseDetailsRoute("#devices/device-1/edit"), null);
  assert.equal(parseDetailsRoute("#role-accounts"), null);
});
test("routing and MPLS retain explicit subnavigation", () => {
  assert.deepEqual(parseDetailsRoute("devices/d/details/routing"), { id: "d", section: "routing", subpage: "bgp" });
  assert.equal(parseDetailsRoute("devices/d/details/routing/static-routes").subpage, "static-routes");
  for (const subpage of ["interfaces", "ldp", "lsps"]) {
    assert.equal(parseDetailsRoute(`devices/d/details/mpls/${subpage}`).subpage, subpage);
  }
});
test("malformed or unsupported detail routes are explicit errors", () => {
  for (const hash of [
    "devices/%xx/details", "devices/d/details/unknown",
    "devices/d/details/interfaces/unexpected", "devices/d/details/routing/lsps",
    "devices/d/details/mpls/bgp",
  ]) assert.throws(() => parseDetailsRoute(hash));
});
test("encoded device identifiers are decoded once", () => {
  assert.equal(parseDetailsRoute("devices/name%20one/details/interfaces").id, "name one");
});
test("static route writes have exactly the intended public fields", () => {
  assert.deepEqual(buildStaticRoute(routeValues()), {
    destination: "198.51.100.0/24", next_hop: "192.0.2.1", interface: "eth0",
    metric: 1, description: "Demo route", enabled: true,
  });
});
test("zero metric, disabled routes and unspecified interfaces are supported", () => {
  const values = routeValues({ metric: "0", interface: "" });
  values.delete("enabled");
  const payload = buildStaticRoute(values);
  assert.equal(payload.metric, 0);
  assert.equal(payload.interface, null);
  assert.equal(payload.enabled, false);
});
test("IPv6 values are retained for authoritative API validation", () => {
  const route = buildStaticRoute(routeValues({ destination: "2001:db8:1::/64", next_hop: "2001:db8::1" }));
  assert.equal(route.destination, "2001:db8:1::/64");
  assert.equal(route.next_hop, "2001:db8::1");
});
test("invalid metric, missing prefix, long description and unknown interface fail", () => {
  for (const extra of [
    { metric: "" }, { metric: "-1" }, { metric: "65536" }, { metric: "1.5" },
    { destination: "" }, { destination: "198.51.100.1" }, { next_hop: "" },
    { description: "x".repeat(201) }, { interface: "invented-interface" },
  ]) assert.throws(() => buildStaticRoute(routeValues(extra)));
});
test("explicit fake client keeps stored role and proxy references", () => {
  const values = new Map(Object.entries({
    name: "Fake device", client_type: "fake", protocol: "ssh",
    host: "fake-device.invalid", port: "22", timeout_seconds: "5",
    role_account_id: "device-role", proxy_id: "proxy",
    password: "must-not-copy",
  }));
  const capabilities = { connectors: [{ type: "ssh_tunnel", protocols: ["ssh"] }] };
  const payload = buildProfile(values, capabilities, [{ id: "proxy", type: "ssh_tunnel" }]);
  assert.equal(payload.client_type, "fake");
  assert.equal(payload.role_account_id, "device-role");
  assert.equal(payload.proxy_id, "proxy");
  assert.equal(Object.hasOwn(payload, "password"), false);
  assert.equal(Object.hasOwn(payload, "connector"), false);
});
test("unknown client type does not silently become a network or fake client", () => {
  const values = new Map(Object.entries({
    name: "Device", protocol: "ssh", host: "127.0.0.1", port: "22",
    timeout_seconds: "5", connector_type: "direct", client_type: "unknown",
  }));
  const capabilities = { connectors: [{ type: "direct", protocols: ["ssh"] }] };
  assert.throws(() => buildProfile(values, capabilities));
  values.delete("client_type");
  assert.equal(buildProfile(values, capabilities).client_type, "network");
});
