import { buildStaticRoute } from "./device-model.mjs";

export function createDeviceDetails({ request, onError, clearError, accountName, proxyName, canConfigure }) {
  const element = (id) => document.getElementById(id);
  const form = element("static-route-form");
  const state = { id: null, route: null, inventory: null, routes: [], selected: null, busy: false, dirty: false, active: false, sequence: 0 };
  const endpoint = (id = state.id) => `/connections/${encodeURIComponent(id)}`;

  function controls() {
    const disabled = state.busy || !state.inventory || !canConfigure();
    for (const input of form.elements) input.disabled = disabled;
    element("new-static-route").disabled = disabled;
    form.hidden = !canConfigure();
    element("details-refresh").disabled = state.busy;
    for (const button of element("detail-route-rows").querySelectorAll("button")) button.disabled = disabled;
  }

  function cell(row, value) {
    const td = document.createElement("td");
    td.textContent = Array.isArray(value) ? value.join(", ") :
      typeof value === "boolean" ? (value ? "Yes" : "No") : String(value ?? "-");
    row.append(td);
    return td;
  }

  function table(id, rows, columns) {
    const body = element(id);
    body.replaceChildren();
    for (const item of rows) {
      const row = document.createElement("tr");
      for (const column of columns) cell(row, item[column]);
      body.append(row);
    }
  }

  function navigation() {
    const { id, section, subpage } = state.route;
    const base = `#devices/${encodeURIComponent(id)}/details`;
    element("details-edit-device").href = `#devices/${encodeURIComponent(id)}/edit`;
    for (const link of document.querySelectorAll("[data-detail-tab]")) {
      link.href = `${base}/${link.dataset.detailTab}`;
      if (link.dataset.detailTab === section) link.setAttribute("aria-current", "page");
      else link.removeAttribute("aria-current");
    }
    for (const panel of document.querySelectorAll("[data-detail-panel]")) panel.hidden = panel.dataset.detailPanel !== section;
    for (const group of ["routing", "mpls"]) {
      for (const link of document.querySelectorAll(`[data-${group}-tab]`)) {
        const name = link.getAttribute(`data-${group}-tab`);
        link.href = `${base}/${group}/${name}`;
        if (section === group && name === subpage) link.setAttribute("aria-current", "page");
        else link.removeAttribute("aria-current");
      }
      for (const panel of document.querySelectorAll(`[data-${group}-panel]`)) {
        panel.hidden = panel.getAttribute(`data-${group}-panel`) !== subpage;
      }
    }
  }

  function loadRoute(route = null) {
    state.selected = route;
    form.reset();
    if (route) {
      for (const name of ["destination", "next_hop", "interface", "metric", "description"]) {
        form.elements.namedItem(name).value = route[name] ?? "";
      }
      form.elements.namedItem("enabled").checked = route.enabled;
    }
    state.dirty = false;
    element("static-route-editor-heading").textContent = route ? `Edit simulated route: ${route.destination}` : "Add simulated route";
    controls();
  }

  function discard() {
    return !state.dirty || confirm("Discard unsaved simulated route changes?");
  }

  function renderRoutes() {
    const body = element("detail-route-rows");
    body.replaceChildren();
    element("static-route-empty").hidden = state.routes.length !== 0;
    for (const route of state.routes) {
      const row = document.createElement("tr");
      for (const name of ["destination", "next_hop", "interface", "metric", "enabled", "description"]) cell(row, route[name]);
      const actions = cell(row, "");
      actions.className = "row-actions";
      const edit = document.createElement("button");
      edit.type = "button";
      edit.textContent = "Edit";
      edit.addEventListener("click", () => { if (discard()) loadRoute(route); });
      const remove = document.createElement("button");
      remove.type = "button";
      remove.textContent = "Delete";
      remove.className = "danger";
      remove.addEventListener("click", () => {
        if (confirm(`Delete simulated route ${route.destination}? No real device will be changed.`)) {
          mutate((id) => request(`${endpoint(id)}/static-routes/${encodeURIComponent(route.id)}`, "DELETE"));
        }
      });
      actions.append(edit, remove);
      body.append(row);
    }
    controls();
  }

  function renderInventory() {
    const data = state.inventory;
    element("device-details-heading").textContent = `${data.device.name} - simulated device information`;
    const entries = [
      ["Client", "Fake device (no network I/O)"],
      ["Saved device ID", data.device.id],
      ["Configured endpoint", `${data.device.protocol} ${data.device.host}:${data.device.port}`],
      ["Hostname", data.system.hostname], ["Model", data.system.model],
      ["Software", data.system.software_version], ["Serial", data.system.serial_number],
      ["Uptime (seconds)", data.system.uptime_seconds],
      ["Device role", accountName(data.access.role_account_id)],
      ["Saved proxy", proxyName(data.access.proxy_id)],
      ["Proxy role", accountName(data.access.proxy_role_account_id)],
      ["Connector", data.access.connector_type],
    ];
    element("detail-system").replaceChildren();
    for (const [label, value] of entries) {
      const term = document.createElement("dt");
      const description = document.createElement("dd");
      term.textContent = label;
      description.textContent = String(value ?? "-");
      element("detail-system").append(term, description);
    }
    table("detail-interface-rows", data.interfaces, ["name", "description", "admin_status", "oper_status", "mtu", "mac_address", "addresses", "rx_bytes", "tx_bytes"]);
    element("detail-bgp-summary").textContent = `Local ASN: ${data.bgp.local_asn}; router ID: ${data.bgp.router_id}. Simulated values.`;
    table("detail-bgp-rows", data.bgp.neighbors, ["address", "remote_asn", "state", "uptime_seconds", "prefixes_received", "prefixes_sent"]);
    table("detail-mpls-interface-rows", data.mpls.interfaces, ["name", "enabled"]);
    table("detail-ldp-rows", data.mpls.ldp_neighbors, ["router_id", "address", "state", "uptime_seconds"]);
    table("detail-lsp-rows", data.mpls.lsps, ["name", "source", "destination", "state", "label"]);
    renderRoutes();
  }

  function validateSimulation(data) {
    if (data.provider !== "fake" || data.simulated !== true) {
      throw new Error("The API did not identify this response as simulated device data.");
    }
  }

  async function reload() {
    clearError();
    const sequence = ++state.sequence;
    const id = state.id;
    state.busy = true;
    state.inventory = null;
    element("device-data-content").hidden = true;
    element("device-details-heading").textContent = "Device information";
    element("device-data-status").textContent = "Resolving saved device, role and proxy configuration...";
    controls();
    try {
      const [inventory, routes] = await Promise.all([
        request(`${endpoint(id)}/inventory`), request(`${endpoint(id)}/static-routes`),
      ]);
      if (sequence !== state.sequence) return;
      validateSimulation(inventory);
      validateSimulation(routes);
      if (!Array.isArray(routes.items)) throw new Error("Invalid static-route response.");
      state.inventory = inventory;
      state.routes = routes.items;
      loadRoute();
      renderInventory();
      element("device-data-content").hidden = false;
      element("device-data-status").textContent = "Simulated data loaded through stored device, role and proxy configuration. No network connection was opened.";
    } catch (failure) {
      if (sequence === state.sequence) {
        state.inventory = null;
        element("device-data-status").textContent = `Device data unavailable: ${failure.message}`;
        onError(failure);
      }
    } finally {
      if (sequence === state.sequence) { state.busy = false; controls(); }
    }
  }

  async function mutate(operation) {
    if (state.busy || !state.inventory) return;
    clearError();
    const sequence = state.sequence;
    const id = state.id;
    let saved = false;
    state.busy = true;
    element("device-data-status").textContent = "Saving simulated route state through the API...";
    controls();
    try {
      await operation(id);
      saved = true;
      const routes = await request(`${endpoint(id)}/static-routes`);
      if (sequence !== state.sequence) return;
      validateSimulation(routes);
      if (!Array.isArray(routes.items)) throw new Error("Invalid static-route response.");
      state.routes = routes.items;
      loadRoute();
      renderRoutes();
      element("device-data-status").textContent = "Simulated route state saved in the database. No network equipment was changed.";
    } catch (failure) {
      if (sequence === state.sequence) {
        element("device-data-status").textContent = saved
          ? "The change was saved but refreshing failed. Refresh device data before retrying."
          : `Simulated route change failed: ${failure.message}`;
        onError(failure);
      }
    } finally {
      if (sequence === state.sequence) { state.busy = false; controls(); }
    }
  }

  form.addEventListener("input", () => { state.dirty = true; });
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    let payload;
    try { payload = buildStaticRoute(new FormData(form)); }
    catch (failure) { onError(failure); return; }
    const selected = state.selected;
    mutate(async (id) => {
      const result = await request(`${endpoint(id)}/static-routes${selected ? `/${encodeURIComponent(selected.id)}` : ""}`,
        selected ? "PUT" : "POST", payload);
      validateSimulation(result);
    });
  });
  for (const id of ["new-static-route", "cancel-static-route"]) {
    element(id).addEventListener("click", () => { if (discard()) loadRoute(); });
  }
  element("details-refresh").addEventListener("click", () => { if (discard()) reload(); });
  controls();

  return {
    canNavigate(next) {
      if (state.active && state.dirty && (!next || next.id !== state.id)) {
        if (!discard()) return false;
        state.dirty = false;
      }
      return true;
    },
    open(route) {
      const load = !state.active || state.id !== route.id || !state.inventory && !state.busy;
      state.active = true;
      state.id = route.id;
      state.route = route;
      navigation();
      if (load) reload();
    },
    leave() { state.active = false; },
    invalidate() { state.inventory = null; state.sequence += 1; state.busy = false; },
  };
}
