import {
  buildProfile, buildProxy, buildRoleAccount, connectorPorts, devicePorts, validationMessage,
} from "./model.mjs";
import { parseDetailsRoute } from "./device-model.mjs";
import { createDeviceDetails } from "./device-details.mjs";
import { normalizeSession, permissions } from "./identity-model.mjs";
import { createTransactionsView } from "./transactions.mjs";

const deviceForm = document.querySelector("#connection-form");
const accountForm = document.querySelector("#account-form");
const proxyForm = document.querySelector("#proxy-form");
const status = document.querySelector("#status");
const error = document.querySelector("#error");
const forms = [deviceForm, accountForm, proxyForm];
const state = {
  capabilities: null, session: null, permissions: permissions(null),
  ready: false, devices: [], accounts: [], proxies: [],
  device: null, account: null, proxy: null,
  dirty: new Set(), results: new Map(), busy: false,
  batch: null, batchIds: new Set(), pollTimer: null, polling: false,
  editorRoute: null, navigationHash: "",
};
const field = (form, name) => form.elements.namedItem(name);
const element = (id) => document.getElementById(id);
const batchActive = () => ["queued", "running"].includes(state.batch?.status);
const locked = () => state.busy || batchActive();
const deviceDetails = createDeviceDetails({
  request, onError: showError, clearError: () => { error.hidden = true; },
  accountName: (id) => state.accounts.find((item) => item.id === id)?.name || id || "None",
  proxyName: (id) => state.proxies.find((item) => item.id === id)?.name || id || "None",
  canConfigure: () => state.permissions.configureDevice,
});
const transactionsView = createTransactionsView({
  request, showError, canView: () => state.permissions.viewTransactions,
});

async function checkDocumentation() {
  const link = element("api-docs-link");
  const note = element("api-docs-status");
  link.hidden = true;
  note.hidden = false;
  try {
    const response = await fetch("/openapi.json", { cache: "no-store", signal: AbortSignal.timeout(5000) });
    if (!response.ok) {
      note.textContent = "API docs unavailable on this server. UI-only previews do not include backend documentation.";
      return;
    }
    const specification = await response.json();
    if (!specification.openapi || !specification.paths) {
      note.textContent = "This server did not provide a valid API specification.";
      return;
    }
    const docs = await fetch("/docs", { signal: AbortSignal.timeout(5000) });
    if (!docs.ok || !docs.headers.get("content-type")?.includes("text/html")) {
      note.textContent = "The API specification is available, but its documentation page is unavailable.";
      return;
    }
    link.href = "/docs";
    link.hidden = false;
    note.hidden = true;
  } catch {
    note.textContent = "API documentation could not be reached. Start the backend and refresh this page.";
  }
}
checkDocumentation();

async function request(path, method = "GET", body) {
  let response;
  try {
    response = await fetch(`/api/v1${path}`, {
      method, cache: "no-store",
      headers: body !== undefined || ["POST", "PUT", "PATCH"].includes(method)
        ? { "Content-Type": "application/json" } : {},
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(120000),
    });
  } catch {
    throw new Error("The API is unavailable or the request timed out. Refresh before retrying an action.");
  }
  if (response.status === 204) return null;
  let payload;
  try { payload = await response.json(); }
  catch { throw new Error(`Unreadable API response (HTTP ${response.status}).`); }
  if (!response.ok) {
    const failure = new Error(validationMessage(payload.detail, response.status));
    failure.status = response.status;
    throw failure;
  }
  return payload;
}

function showError(failure) {
  error.textContent = failure.message;
  error.hidden = false;
  if (failure.status === 401) {
    element("login-link").hidden = false;
    element("identity-summary").hidden = true;
    error.textContent = "Authentication is required. Sign in with Microsoft Entra ID to use the gateway.";
  }
  status.textContent = "Action failed. No success is assumed; review the error above.";
}

async function action(message, operation) {
  if (state.busy) return;
  state.busy = true;
  error.hidden = true;
  status.textContent = message;
  controls();
  try { await operation(); }
  catch (failure) { showError(failure); }
  finally { state.busy = false; controls(); }
}

function controls() {
  const disabled = locked() || !state.ready;
  for (const form of forms) {
    for (const input of form.elements) input.disabled = disabled || !state.permissions.manageProfiles;
  }
  for (const id of ["new", "new-account", "new-proxy"]) {
    element(id).disabled = disabled || !state.permissions.manageProfiles;
  }
  element("refresh").disabled = state.busy;
  element("delete").disabled = disabled || !state.permissions.manageProfiles || !state.device;
  element("delete-account").disabled = disabled || !state.permissions.manageAccess || !state.account;
  element("delete-proxy").disabled = disabled || !state.permissions.manageAccess || !state.proxy;
  element("test").disabled = disabled || !state.permissions.test || !state.device || state.dirty.has(deviceForm);
  element("test-all").disabled = disabled || !state.permissions.test || !state.devices.length;
  element("unsaved").hidden = !state.dirty.has(deviceForm) || !state.device;
  for (const button of document.querySelectorAll("#connections button, #accounts button, #proxies button")) {
    const operation = button.dataset.operation;
    button.disabled = disabled || button.dataset.requiresFake === "true" ||
      operation === "test" && !state.permissions.test ||
      operation === "manage" && !state.permissions.manageProfiles;
  }
  for (const [form, selector] of [[deviceForm, "[data-inline-device]"], [proxyForm, "[data-inline-proxy]"]]) {
    const usingRole = Boolean(field(form, "role_account_id").value);
    for (const label of document.querySelectorAll(selector)) {
      label.hidden = usingRole;
      for (const input of label.querySelectorAll("input")) {
        input.disabled = disabled || !state.permissions.manageProfiles || usingRole;
      }
    }
  }
  const keyMode = field(accountForm, "authentication_type").value === "ssh_key";
  for (const [selector, visible] of [["[data-account-password]", !keyMode], ["[data-account-key]", keyMode]]) {
    for (const label of document.querySelectorAll(selector)) {
      label.hidden = !visible;
      for (const input of label.querySelectorAll("input, textarea")) {
        input.disabled = disabled || !state.permissions.manageAccess || !visible;
      }
    }
  }
}

function navigate() {
  const name = location.hash.slice(1);
  let detail;
  try { detail = parseDetailsRoute(name); }
  catch (failure) { showError(failure); return; }
  if (!deviceDetails.canNavigate(detail)) {
    history.replaceState(null, "", `#${state.navigationHash}`);
    return;
  }
  state.navigationHash = name;
  const editMatch = /^devices\/([^/]+)\/edit$/.exec(name);
  const devicePage = name === "devices/new" || Boolean(editMatch);
  const view = detail ? "device-details" : devicePage ? "device-editor" :
    (["devices", "proxies", "role-accounts", "transactions"].includes(name) ? name : "devices");
  for (const page of document.querySelectorAll("[data-page]")) page.hidden = page.dataset.page !== view;
  for (const link of document.querySelectorAll("nav [data-view]")) {
    if (link.dataset.view === (devicePage || detail ? "devices" : view)) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  }
  if (detail && state.ready) deviceDetails.open(detail);
  else if (!detail) deviceDetails.leave();
  if (view === "transactions" && state.ready) transactionsView.refresh();
  if (devicePage && state.ready && state.editorRoute !== name) {
    let id;
    try { id = editMatch ? decodeURIComponent(editMatch[1]) : null; }
    catch { showError(new Error("Invalid device identifier in this address.")); return; }
    const device = id ? state.devices.find((item) => item.id === id) : null;
    if (id && !device) {
      showError(new Error("This device is not available. Return to the device list and refresh."));
      element("device-editor").hidden = true;
      return;
    }
    loadDevice(device);
    state.editorRoute = name;
  }
}
addEventListener("hashchange", navigate);
navigate();

function options(select, items, placeholder) {
  const current = select.value;
  select.replaceChildren(new Option(placeholder, ""));
  for (const item of items) select.add(new Option(item.name, item.id));
  if (current && !items.some((item) => item.id === current)) {
    select.add(new Option("Unavailable - choose another", current));
  }
  select.value = current;
}

function syncSelectors() {
  options(field(deviceForm, "role_account_id"), state.accounts, "Per-device credentials");
  options(field(proxyForm, "role_account_id"), state.accounts, "Per-proxy credentials");
  options(field(deviceForm, "proxy_id"), state.proxies, "Direct connection (no proxy)");
  describeConnector();
}

function describeConnector() {
  const proxyId = field(deviceForm, "proxy_id").value;
  const proxy = state.proxies.find((item) => item.id === proxyId);
  const type = proxyId ? proxy?.type : "direct";
  const capability = state.capabilities?.connectors.find((item) => item.type === type);
  element("connector-description").textContent = capability?.description || "Selected proxy unavailable. Refresh and choose a valid proxy.";
  for (const option of field(deviceForm, "protocol").options) {
    option.disabled = !capability?.protocols.includes(option.value);
  }
  element("proxy-description").textContent =
    state.capabilities?.connectors.find((item) => item.type === field(proxyForm, "type").value)?.description || "";
}

function textCell(row, text, className = "") {
  const cell = document.createElement("td");
  cell.textContent = text;
  cell.className = className;
  row.append(cell);
  return cell;
}
function rowButton(label, handler) {
  const button = document.createElement("button");
  button.type = "button";
  button.textContent = label;
  button.addEventListener("click", handler);
  return button;
}

function renderDevices() {
  const table = element("connections");
  table.replaceChildren();
  element("empty").hidden = state.devices.length !== 0;
  for (const device of state.devices) {
    const row = document.createElement("tr");
    const result = state.results.get(device.id);
    if (result) row.dataset.success = String(result.success);
    const proxy = state.proxies.find((item) => item.id === device.proxy_id);
    const account = state.accounts.find((item) => item.id === device.role_account_id);
    textCell(row, device.name);
    textCell(row, `${device.protocol.toUpperCase()}${device.client_type === "fake" ? " / FAKE" : ""} ${device.host}:${device.port}`);
    textCell(row, proxy?.name || device.connector?.type || "direct");
    textCell(row, account?.name || (device.role_account_id ? "Unavailable" : "Per-device"));
    textCell(row, result ? `${result.success ? "Passed" : "Failed"}${result.simulated ? " (simulated)" : ""}` :
      (batchActive() && state.batchIds.has(device.id) ? "Queued / testing" : "Not tested"), "result-status");
    textCell(row, result ? `${result.stage}: ${result.detail}` : "-");
    textCell(row, result ? `${result.duration_ms} ms` : "-");
    const actions = textCell(row, "");
    const buttons = document.createElement("div");
    buttons.className = "row-actions";
    const viewButton = rowButton("View", () => { location.hash = `devices/${encodeURIComponent(device.id)}/details`; });
    viewButton.dataset.requiresFake = String(device.client_type !== "fake");
    viewButton.title = device.client_type === "fake" ? "View simulated device data" : "Device inventory is currently implemented for fake clients only";
    const editButton = rowButton("Edit", () => {
      if (discard(deviceForm)) {
        state.editorRoute = null;
        location.hash = `devices/${encodeURIComponent(device.id)}/edit`;
        navigate();
      }
    });
    editButton.dataset.operation = "manage";
    const testButton = rowButton("Test", () => action(`Testing ${device.name}...`, () => testDevice(device)));
    testButton.dataset.operation = "test";
    buttons.append(
      viewButton, editButton, testButton,
    );
    actions.append(buttons);
    table.append(row);
  }
  controls();
}

function renderList(id, items, selected, form, load) {
  const list = element(id);
  list.replaceChildren();
  if (!items.length) {
    const empty = document.createElement("li");
    empty.textContent = "None configured.";
    list.append(empty);
  }
  for (const item of items) {
    const row = document.createElement("li");
    const button = rowButton(item.name, () => { if (discard(form)) load(item); });
    button.setAttribute("aria-pressed", String(item.id === selected?.id));
    const description = document.createElement("span");
    description.textContent = item.type ? `${item.type} ${item.host}:${item.port}` : item.username;
    button.append(description);
    row.append(button);
    list.append(row);
  }
}
function render() {
  syncSelectors();
  renderList("accounts", state.accounts, state.account, accountForm, loadAccount);
  renderList("proxies", state.proxies, state.proxy, proxyForm, loadProxy);
  renderDevices();
}
function discard(form) {
  return !state.dirty.has(form) || confirm("Discard unsaved changes in this editor?");
}
function fill(form, value, names) {
  form.reset();
  for (const name of names) field(form, name).value = value?.[name] ?? "";
  state.dirty.delete(form);
}
const secretLabel = (value) => value?.password_configured ? "Stored; leave blank to preserve." : "Not stored.";

function loadDevice(device = null) {
  state.device = device;
  fill(deviceForm, device ? { client_type: "network", ...device } : { protocol: "ssh", port: 22, timeout_seconds: 5, client_type: "network" }, [
    "name", "protocol", "client_type", "host", "port", "username", "private_key_path",
    "known_hosts_path", "timeout_seconds", "role_account_id", "proxy_id",
  ]);
  element("device-secret-state").textContent = secretLabel(device);
  element("editor-heading").textContent = device ? `Edit device: ${device.name}` : "New device";
  element("test-result").hidden = true;
  if (device?.connector?.type && device.connector.type !== "direct" && !device.proxy_id) {
    showError(new Error("This legacy profile has inline proxy settings. Create and select a saved proxy before saving it; it will not silently switch to direct."));
    field(deviceForm, "proxy_id").add(new Option("Legacy inline proxy - select a saved proxy", "legacy-inline"));
    field(deviceForm, "proxy_id").value = "legacy-inline";
  }
  describeConnector();
  controls();
}
function loadAccount(account = null) {
  state.account = account;
  fill(accountForm, account || { authentication_type: "password" }, ["name", "username", "authentication_type"]);
  element("account-heading").textContent = account ? `Edit account: ${account.name}` : "New role account";
  element("account-secret-state").textContent = secretLabel(account);
  element("account-key-state").textContent =
    account?.private_key_configured ? "Stored; leave blank to preserve the key and passphrase." : "Not stored.";
  render();
}
function loadProxy(proxy = null) {
  state.proxy = proxy;
  fill(proxyForm, proxy || { type: "ssh_tunnel", port: 22 }, [
    "name", "type", "host", "port", "username", "private_key_path", "known_hosts_path", "role_account_id",
  ]);
  element("proxy-heading").textContent = proxy ? `Edit proxy: ${proxy.name}` : "New proxy";
  element("proxy-secret-state").textContent = secretLabel(proxy);
  render();
}

async function refresh() {
  const [devices, accounts, proxies] = await Promise.all([
    request("/connections"), request("/role-accounts"), request("/proxies"),
  ]);
  state.devices = devices.items;
  state.accounts = accounts.items;
  state.proxies = proxies.items;
  render();
}

for (const form of forms) form.addEventListener("input", () => {
  state.dirty.add(form);
  controls();
});
field(deviceForm, "protocol").addEventListener("change", () => {
  field(deviceForm, "port").value = devicePorts[field(deviceForm, "protocol").value];
});
field(deviceForm, "proxy_id").addEventListener("change", () => {
  describeConnector();
  const option = field(deviceForm, "protocol").selectedOptions[0];
  if (option?.disabled) {
    field(deviceForm, "protocol").value = [...field(deviceForm, "protocol").options].find((item) => !item.disabled)?.value || "";
    field(deviceForm, "port").value = devicePorts[field(deviceForm, "protocol").value] || "";
  }
});
field(proxyForm, "type").addEventListener("change", () => {
  field(proxyForm, "port").value = connectorPorts[field(proxyForm, "type").value] || "";
  describeConnector();
});
field(accountForm, "authentication_type").addEventListener("change", () => {
  for (const name of ["password", "private_key", "key_passphrase"]) field(accountForm, name).value = "";
  controls();
});

function wireCrud(form, collection, selectedName, path, build, load, deleteId) {
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const values = new FormData(form);
    action("Saving configuration...", async () => {
      const selected = state[selectedName];
      const payload = build(values);
      const saved = await request(selected ? `${path}/${encodeURIComponent(selected.id)}` : path,
        selected ? "PUT" : "POST", payload);
      invalidateResults();
      state[collection] = state[collection].filter((item) => item.id !== saved.id);
      state[collection].push(saved);
      load(saved);
      if (form === deviceForm) {
        state.editorRoute = null;
        location.hash = "devices";
        navigate();
      }
      render();
      status.textContent = "Configuration saved. No device operation was performed.";
    });
  });
  element(deleteId).addEventListener("click", () => {
    const selected = state[selectedName];
    if (!selected || !confirm(`Delete "${selected.name}"? Records still in use cannot be deleted.`)) return;
    action("Deleting configuration...", async () => {
      await request(`${path}/${encodeURIComponent(selected.id)}`, "DELETE");
      invalidateResults();
      state[collection] = state[collection].filter((item) => item.id !== selected.id);
      load();
      if (form === deviceForm) {
        state.editorRoute = null;
        location.hash = "devices";
        navigate();
      }
      render();
      status.textContent = "Configuration deleted. No device operation was performed.";
    });
  });
}
wireCrud(deviceForm, "devices", "device", "/connections",
  (values) => buildProfile(values, state.capabilities, state.proxies), loadDevice, "delete");
wireCrud(accountForm, "accounts", "account", "/role-accounts",
  (values) => buildRoleAccount(values, state.account), loadAccount, "delete-account");
wireCrud(proxyForm, "proxies", "proxy", "/proxies",
  (values) => buildProxy(values, state.capabilities), loadProxy, "delete-proxy");
element("new").addEventListener("click", () => {
  if (discard(deviceForm)) {
    state.editorRoute = null;
    location.hash = "devices/new";
    navigate();
  }
});
element("new-account").addEventListener("click", () => { if (discard(accountForm)) loadAccount(); });
element("new-proxy").addEventListener("click", () => { if (discard(proxyForm)) loadProxy(); });
element("close-editor").addEventListener("click", () => {
  if (discard(deviceForm)) {
    loadDevice();
    state.editorRoute = null;
    location.hash = "devices";
    navigate();
  }
});
element("refresh").addEventListener("click", () => action("Refreshing saved configuration...", async () => {
  checkDocumentation();
  if (!state.ready) await initialize();
  else await refresh();
  if (batchActive()) await pollBatch();
  status.textContent = "Saved configuration refreshed. Unsaved editor values were preserved.";
}));

function invalidateResults() {
  deviceDetails.invalidate();
  state.results.clear();
  clearTimeout(state.pollTimer);
  state.batch = null;
  state.batchIds.clear();
  element("batch-progress").textContent = "Configuration changed. Run tests again; previous exports describe the earlier snapshot.";
  element("batch-meter").hidden = true;
  try { sessionStorage.removeItem("gateway-last-test"); }
  catch { status.textContent = "Configuration saved; browser test-history storage could not be cleared."; }
}

async function testDevice(device) {
  const result = await request(`/connections/${encodeURIComponent(device.id)}/test`, "POST");
  if (typeof result.success !== "boolean") throw new Error("Invalid connection-test response.");
  state.results.set(device.id, result);
  renderDevices();
  element("test-summary").textContent = `${result.simulated ? "Simulated connection" : "Connection"} test ${result.success ? "passed" : "failed"}.`;
  element("test-summary").dataset.success = String(result.success);
  element("test-details").replaceChildren();
  for (const [label, value] of [["Device", device.name], ["Stage", result.stage], ["Details", result.detail], ["Duration", `${result.duration_ms} ms`]]) {
    const term = document.createElement("dt");
    term.textContent = label;
    const detail = document.createElement("dd");
    detail.textContent = String(value);
    element("test-details").append(term, detail);
  }
  element("test-result").hidden = false;
  status.textContent = `${device.name}: ${result.success ? "passed" : "failed"}. ${result.detail}`;
}
element("test").addEventListener("click", () => action("Testing saved device...", () => testDevice(state.device)));

function renderBatch() {
  const batch = state.batch;
  if (!batch) return;
  const results = batch.results || [];
  for (const result of results) state.results.set(result.connection_id, result);
  const passed = results.filter((item) => item.success).length;
  const failed = results.filter((item) => item.success === false).length;
  const simulated = results.filter((item) => item.simulated === true).length;
  element("batch-progress").textContent =
    `${batch.status}: ${batch.completed}/${batch.total} completed. ${passed} passed, ${failed} failed.${simulated ? ` ${simulated} simulated.` : ""}${batch.error ? ` ${batch.error}` : ""}`;
  element("batch-meter").hidden = false;
  element("batch-meter").max = Math.max(1, batch.total);
  element("batch-meter").value = batch.completed;
  const terminal = ["completed", "failed"].includes(batch.status);
  element("batch-exports").hidden = !terminal;
  if (terminal) {
    if (!state.busy) status.textContent = `Bulk test ${batch.status}. Results are available for export.`;
    for (const format of ["csv", "json"]) {
      element(`export-${format}`).href =
        `/api/v1/connection-tests/${encodeURIComponent(batch.id)}/export?format=${format}`;
    }
  }
  renderDevices();
}
async function pollBatch() {
  clearTimeout(state.pollTimer);
  if (!state.batch?.id || state.polling) return;
  state.polling = true;
  try {
    state.batch = await request(`/connection-tests/${encodeURIComponent(state.batch.id)}`);
    renderBatch();
    if (batchActive()) state.pollTimer = setTimeout(pollBatch, 1000);
  } catch (failure) {
    if (failure.status === 404) {
      state.batch = null;
      state.batchIds.clear();
      element("batch-progress").textContent = "The previous test run is no longer available. Start a new run.";
      element("batch-exports").hidden = true;
      try { sessionStorage.removeItem("gateway-last-test"); }
      catch { status.textContent = "Previous run unavailable; browser test-history storage could not be cleared."; }
      controls();
      showError(new Error("The previous test run is no longer available. Start a new run to obtain current results."));
      return;
    }
    showError(new Error(`${failure.message} Bulk progress is unknown; use Refresh list to reconnect. The API may still be running the job.`));
  } finally {
    state.polling = false;
  }
}
element("test-all").addEventListener("click", () => action("Starting a bulk connection test...", async () => {
  const ids = state.devices.map((device) => device.id);
  const batch = await request("/connection-tests", "POST", { connection_ids: ids });
  state.batch = batch;
  state.batchIds = new Set(ids);
  for (const id of ids) state.results.delete(id);
  try { sessionStorage.setItem("gateway-last-test", batch.id); }
  catch { status.textContent = "Browser session storage unavailable; results remain available from the API."; }
  renderBatch();
  await pollBatch();
}));

async function initialize() {
  const sessionPayload = await request("/session");
  if (!sessionPayload?.user) {
    const failure = new Error("Authentication is required.");
    failure.status = 401;
    throw failure;
  }
  state.session = normalizeSession(sessionPayload);
  state.permissions = permissions(state.session);
  renderIdentity();
  state.capabilities = await request("/capabilities");
  field(deviceForm, "protocol").replaceChildren();
  field(proxyForm, "type").replaceChildren();
  for (const protocol of state.capabilities.protocols) {
    field(deviceForm, "protocol").add(new Option(protocol.toUpperCase(), protocol));
  }
  element("capabilities").replaceChildren();
  for (const connector of state.capabilities.connectors) {
    if (connector.type !== "direct") field(proxyForm, "type").add(new Option(connector.label, connector.type));
    const row = document.createElement("tr");
    for (const value of [connector.label, connector.protocols.join(", "), connector.description]) textCell(row, value);
    element("capabilities").append(row);
  }
  await refresh();
  loadDevice();
  loadProxy();
  loadAccount();
  state.ready = true;
  navigate();
}
function renderIdentity() {
  const user = state.session.user;
  element("identity-name").textContent = user.name;
  element("identity-email").textContent = user.email || user.subject;
  element("identity-roles").replaceChildren();
  for (const role of user.roles) {
    const badge = document.createElement("span");
    badge.textContent = role;
    element("identity-roles").append(badge);
  }
  element("identity-mode").textContent = user.auth_mode === "demo"
    ? "DEMO IDENTITY - not Entra authenticated"
    : "Authenticated by Microsoft Entra ID";
  element("identity-summary").hidden = false;
  element("login-link").hidden = true;
  element("environment-label").textContent = user.auth_mode === "demo"
    ? "Offline demo identity enabled."
    : "Enterprise identity enforced.";
}
element("refresh-transactions").addEventListener("click", () => transactionsView.refresh());
action("Loading configuration...", async () => {
  await initialize();
  status.textContent = "Ready. Devices are listed below; connections are only attempted when you run a test.";
  let previous;
  try { previous = sessionStorage.getItem("gateway-last-test"); }
  catch { status.textContent += " Browser session storage is unavailable."; }
  if (previous) {
    state.batch = { id: previous, status: "queued" };
    await pollBatch();
  }
});
