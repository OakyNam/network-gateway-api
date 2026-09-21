export const APPLICATION_ROLES = Object.freeze(["Viewer", "Operator", "Administrator"]);

export function normalizeSession(payload) {
  if (!payload || typeof payload !== "object" || !payload.user || typeof payload.user !== "object") {
    throw new Error("The server returned an invalid identity session.");
  }
  const user = payload.user;
  const roles = [...new Set(Array.isArray(user.roles) ? user.roles : [])]
    .filter((role) => APPLICATION_ROLES.includes(role));
  if (!String(user.subject || "").trim() || !String(user.name || "").trim() || !roles.length) {
    throw new Error("The signed-in identity has no supported application role.");
  }
  return {
    authenticated: true,
    user: {
      subject: String(user.subject),
      tenant_id: user.tenant_id == null ? null : String(user.tenant_id),
      name: String(user.name),
      email: user.email == null ? null : String(user.email),
      roles,
      auth_mode: user.auth_mode === "demo" ? "demo" : "entra",
    },
  };
}

export function permissions(session) {
  const roles = new Set(session?.user?.roles || []);
  const administrator = roles.has("Administrator");
  const operator = administrator || roles.has("Operator");
  const viewer = operator || roles.has("Viewer");
  return Object.freeze({
    viewer, operator, administrator,
    read: viewer,
    test: operator,
    configureDevice: operator,
    manageProfiles: administrator,
    manageAccess: administrator,
    viewTransactions: viewer,
  });
}

export function transactionQuery(filters = {}) {
  const params = new URLSearchParams();
  for (const name of ["connection_id", "action", "actor_subject", "outcome", "from_time", "to_time"]) {
    const value = String(filters[name] ?? "").trim();
    if (value) params.set(name, value);
  }
  const limit = Number(filters.limit ?? 50);
  const offset = Number(filters.offset ?? 0);
  if (!Number.isInteger(limit) || limit < 1 || limit > 200) throw new Error("Transaction page size must be from 1 to 200.");
  if (!Number.isInteger(offset) || offset < 0) throw new Error("Transaction offset cannot be negative.");
  params.set("limit", String(limit));
  params.set("offset", String(offset));
  return params.toString();
}
