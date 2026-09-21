import { transactionQuery } from "./identity-model.mjs";

export function createTransactionsView({ request, showError, canView }) {
  const element = (id) => document.getElementById(id);
  const form = element("transaction-filters");
  const state = { offset: 0, limit: 50, total: 0, busy: false };

  function cell(row, value) {
    const td = document.createElement("td");
    td.textContent = String(value ?? "-");
    row.append(td);
    return td;
  }

  function safeJson(value) {
    return value == null ? "None" : JSON.stringify(value, null, 2);
  }

  function render(payload) {
    if (!Array.isArray(payload.items)) throw new Error("Invalid transaction response.");
    state.total = Number(payload.total ?? payload.items.length);
    const body = element("transaction-rows");
    body.replaceChildren();
    for (const item of payload.items) {
      const row = document.createElement("tr");
      cell(row, item.timestamp_utc);
      cell(row, item.actor_name || item.actor_subject);
      cell(row, Array.isArray(item.actor_roles) ? item.actor_roles.join(", ") : "-");
      cell(row, item.action);
      cell(row, `${item.resource_type}${item.resource_id ? ` / ${item.resource_id}` : ""}`);
      cell(row, item.outcome);
      cell(row, item.correlation_id);
      cell(row, item.detail || "-");
      const details = cell(row, "");
      const disclosure = document.createElement("details");
      const summary = document.createElement("summary");
      summary.textContent = "Before / after";
      const before = document.createElement("pre");
      const after = document.createElement("pre");
      before.textContent = `Before\n${safeJson(item.before_state)}`;
      after.textContent = `After\n${safeJson(item.after_state)}`;
      disclosure.append(summary, before, after);
      details.append(disclosure);
      body.append(row);
    }
    element("transactions-empty").hidden = payload.items.length !== 0;
    element("transaction-page").textContent =
      `${state.total} immutable transaction${state.total === 1 ? "" : "s"}; showing ${state.offset + 1}-${Math.min(state.offset + payload.items.length, state.total)}.`;
    element("transactions-previous").disabled = state.busy || state.offset === 0;
    element("transactions-next").disabled = state.busy || state.offset + payload.items.length >= state.total;
  }

  async function load(reset = false) {
    if (!canView() || state.busy) return;
    if (reset) state.offset = 0;
    state.busy = true;
    element("transactions-status").textContent = "Loading immutable transaction records...";
    for (const input of form.elements) input.disabled = true;
    try {
      const filters = Object.fromEntries(new FormData(form));
      const payload = await request(`/transactions?${transactionQuery({ ...filters, limit: state.limit, offset: state.offset })}`);
      render(payload);
      element("transactions-status").textContent = "Transaction records loaded. These records cannot be changed or deleted through the API.";
    } catch (failure) {
      showError(failure);
      element("transactions-status").textContent = "Transaction records could not be loaded.";
    } finally {
      state.busy = false;
      for (const input of form.elements) input.disabled = false;
    }
  }

  form.addEventListener("submit", (event) => { event.preventDefault(); load(true); });
  element("transactions-previous").addEventListener("click", () => {
    state.offset = Math.max(0, state.offset - state.limit);
    load();
  });
  element("transactions-next").addEventListener("click", () => {
    state.offset += state.limit;
    load();
  });
  return { load, refresh: () => load(true) };
}
