export function parseDetailsRoute(hash) {
  const value = hash.replace(/^#/, "");
  if (!/^devices\/[^/]+\/details(?:\/|$)/.test(value)) return null;
  const match = /^devices\/([^/]+)\/details(?:\/(overview|interfaces|routing|mpls))?(?:\/([^/]+))?$/.exec(value);
  if (!match) throw new Error("Unknown device information page.");
  let id;
  try { id = decodeURIComponent(match[1]); }
  catch { throw new Error("Invalid device identifier in this address."); }
  const section = match[2] || "overview";
  const subpages = { routing: ["bgp", "static-routes"], mpls: ["interfaces", "ldp", "lsps"] };
  const subpage = match[3] || subpages[section]?.[0] || null;
  if (subpage && !subpages[section]?.includes(subpage)) {
    throw new Error("Unknown device information subpage.");
  }
  return { id, section, subpage };
}

export function buildStaticRoute(values) {
  const text = (name) => String(values.get(name) ?? "").trim();
  const destination = text("destination");
  const nextHop = text("next_hop");
  if (!destination || !destination.includes("/") || !nextHop) {
    throw new Error("Enter a destination CIDR prefix and a next-hop address.");
  }
  const metric = Number(text("metric"));
  if (!text("metric") || !Number.isInteger(metric) || metric < 0 || metric > 65535) {
    throw new Error("Route metric must be an integer from 0 to 65535.");
  }
  const description = text("description");
  if (description.length > 200) throw new Error("Route description must not exceed 200 characters.");
  const routeInterface = text("interface");
  if (routeInterface && !["eth0", "eth1", "lo"].includes(routeInterface)) {
    throw new Error("Choose a supported simulated interface.");
  }
  return {
    destination, next_hop: nextHop, interface: routeInterface || null,
    metric, description, enabled: values.has("enabled"),
  };
}
