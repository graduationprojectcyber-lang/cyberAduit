/* Audit log explorer: URL-synced filters, server-side sorting and pagination. */
(function () {
  "use strict";
  const CA = window.CA, $ = CA.$;
  const form = $("#filterForm"), rowsEl = $("#rows"), headRow = $("#headRow");
  const FIELDS = ["q", "actor", "ip", "action", "outcome", "severity", "origin", "start", "end"];
  const LABELS = { q: "Search", actor: "User", ip: "IP", action: "Action", outcome: "Outcome", severity: "Severity", origin: "Origin", start: "From", end: "To" };
  const COLS = [["id", "Event ID", true], ["ts", "Timestamp", true], ["actor", "User", true], ["action", "Action", true],
    ["resource", "Resource", true], ["source_ip", "Source IP", true], ["outcome", "Outcome", true], ["severity", "Severity", true],
    ["origin", "Origin", false], ["x", "", false]];
  const state = { sort: "ts", dir: "desc", page: 1, per_page: 25 };
  let controller = null;

  function readUrl() {
    const p = new URLSearchParams(location.search);
    FIELDS.forEach((f) => { if (form.elements[f]) form.elements[f].value = p.get(f) || ""; });
    if (p.get("sort")) state.sort = p.get("sort");
    if (p.get("dir")) state.dir = p.get("dir");
    if (p.get("page")) state.page = Math.max(1, parseInt(p.get("page"), 10) || 1);
    if (p.get("per_page")) state.per_page = parseInt(p.get("per_page"), 10) || 25;
    $("#perPage").value = String(state.per_page);
  }
  function formValues() {
    const v = {};
    FIELDS.forEach((f) => { const val = (form.elements[f].value || "").trim(); if (val) v[f] = val; });
    return v;
  }
  function apiParams(v) {
    const p = { ...v };
    if (p.start) p.start = CA.localDayIso(p.start, false);
    if (p.end) p.end = CA.localDayIso(p.end, true);
    return p;
  }

  function renderHead() {
    headRow.innerHTML = COLS.map(([key, label, sortable]) => {
      if (!sortable) return `<th scope="col">${label ? CA.esc(label) : '<span class="sr-only">Details</span>'}</th>`;
      const active = state.sort === key;
      return `<th scope="col" aria-sort="${active ? (state.dir === "asc" ? "ascending" : "descending") : "none"}">
        <button type="button" class="th-sort ${active ? "active" : ""}" data-sort="${key}">${CA.esc(label)}<span class="arrow" aria-hidden="true">${active ? (state.dir === "asc" ? "▲" : "▼") : "↕"}</span></button></th>`;
    }).join("");
  }
  headRow.addEventListener("click", (e) => {
    const b = e.target.closest("[data-sort]");
    if (!b) return;
    const key = b.dataset.sort;
    state.dir = state.sort === key && state.dir === "desc" ? "asc" : "desc";
    state.sort = key;
    state.page = 1;
    load();
  });

  function renderChips(v) {
    const chips = $("#chips");
    chips.innerHTML = Object.entries(v).map(([k, val]) => {
      const sel = form.elements[k];
      const shown = sel && sel.tagName === "SELECT" ? sel.options[sel.selectedIndex].text : val;
      return `<span class="chip">${CA.esc(LABELS[k])}: ${CA.esc(shown)}<button type="button" data-clear="${k}" aria-label="Remove ${CA.esc(LABELS[k])} filter">×</button></span>`;
    }).join("");
  }
  $("#chips").addEventListener("click", (e) => {
    const b = e.target.closest("[data-clear]");
    if (!b) return;
    form.elements[b.dataset.clear].value = "";
    state.page = 1;
    load({ announce: true });
  });

  function pagerHtml(page, pages) {
    const nums = new Set([1, pages, page - 1, page, page + 1].filter((n) => n >= 1 && n <= pages));
    const sorted = [...nums].sort((a, b) => a - b);
    let html = `<button type="button" data-page="${page - 1}" ${page <= 1 ? "disabled" : ""} aria-label="Previous page">‹</button>`;
    sorted.forEach((n, i) => {
      if (i && n - sorted[i - 1] > 1) html += '<span class="gap">…</span>';
      html += `<button type="button" data-page="${n}" ${n === page ? 'aria-current="page"' : ""}>${n}</button>`;
    });
    return html + `<button type="button" data-page="${page + 1}" ${page >= pages ? "disabled" : ""} aria-label="Next page">›</button>`;
  }
  $("#pager").addEventListener("click", (e) => {
    const b = e.target.closest("[data-page]");
    if (!b || b.disabled) return;
    state.page = Number(b.dataset.page);
    load();
    window.scrollTo({ top: form.offsetTop - 10, behavior: CA.reduceMotion ? "auto" : "smooth" });
  });
  $("#perPage").addEventListener("change", (e) => { state.per_page = Number(e.target.value); state.page = 1; load(); });

  function row(e) {
    return `<tr data-id="${e.id}" tabindex="0" style="cursor:pointer">
      <td class="mono">${CA.esc(e.uid)}</td>
      <td class="mono" title="${CA.esc(e.ts)} UTC">${CA.esc(CA.dateTime(e.ts))}</td>
      <td class="strong">${CA.esc(e.actor)}</td>
      <td>${CA.esc(e.action_label)}</td>
      <td class="mono" style="max-width:240px;overflow:hidden;text-overflow:ellipsis" title="${CA.esc(e.resource || "")}">${CA.esc(e.resource || "—")}</td>
      <td class="mono">${CA.esc(e.source_ip || "—")}</td>
      <td>${CA.pill(e.outcome)}</td><td>${CA.pill(e.severity)}</td><td>${CA.originPill(e.origin)}</td>
      <td class="right"><button class="btn btn-sm btn-ghost" type="button" data-open="${e.id}" aria-label="Inspect ${CA.esc(e.uid)}">Inspect</button></td></tr>`;
  }
  rowsEl.addEventListener("click", (e) => {
    const tr = e.target.closest("tr[data-id]");
    if (!tr) return;
    CA.$$("tr.selected", rowsEl).forEach((r) => r.classList.remove("selected"));
    tr.classList.add("selected");
    CA.openEvent(tr.dataset.id);
  });
  rowsEl.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && e.target.matches("tr[data-id]")) { e.preventDefault(); e.target.click(); }
  });

  async function load({ announce = false } = {}) {
    CA.$$(".field.invalid", form).forEach((f) => f.classList.remove("invalid"));
    const v = formValues();
    const params = { ...apiParams(v), sort: state.sort, dir: state.dir, page: state.page, per_page: state.per_page };
    history.replaceState(null, "", location.pathname + CA.query({ ...v, sort: state.sort !== "ts" ? state.sort : "", dir: state.dir !== "desc" ? state.dir : "", page: state.page > 1 ? state.page : "" }));
    renderHead();
    renderChips(v);
    const exp = $("#exportCsv");
    if (exp) exp.href = "/reports/export.csv" + CA.query(apiParams(v));
    rowsEl.innerHTML = Array.from({ length: 6 }, () => `<tr><td colspan="10"><div class="skeleton" style="height:18px"></div></td></tr>`).join("");
    if (controller) controller.abort();
    controller = new AbortController();
    try {
      const r = await CA.api("/api/events" + CA.query(params), { signal: controller.signal });
      state.page = r.page;
      rowsEl.innerHTML = r.items.length ? r.items.map(row).join("") :
        `<tr><td colspan="10"><div class="empty">${CA.icon("search")}<b>No events match these filters</b><span>Widen the date range or clear a filter.</span></div></td></tr>`;
      const from = r.total ? (r.page - 1) * r.per_page + 1 : 0;
      $("#pageInfo").textContent = `Showing ${CA.num(from)}–${CA.num(Math.min(r.page * r.per_page, r.total))} of ${CA.num(r.total)}`;
      $("#resultCount").innerHTML = `<b class="num" style="color:var(--text)">${CA.num(r.total)}</b> matching record${r.total === 1 ? "" : "s"}`;
      $("#pager").innerHTML = pagerHtml(r.page, r.pages);
      if (announce) CA.toast("info", "Filters applied", `${CA.num(r.total)} matching record${r.total === 1 ? "" : "s"}.`, 2200);
    } catch (err) {
      if (err.name === "AbortError") return;
      rowsEl.innerHTML = `<tr><td colspan="10"><div class="error-box">${CA.esc(err.message)}<button class="btn btn-sm" type="button" id="retry">Retry</button></div></td></tr>`;
      $("#retry")?.addEventListener("click", () => load());
      if (err.field && form.elements[err.field]) form.elements[err.field].closest(".field").classList.add("invalid");
      CA.toast("error", "Could not load events", err.message);
    }
  }

  form.addEventListener("submit", (e) => { e.preventDefault(); state.page = 1; load({ announce: true }); });
  form.addEventListener("change", (e) => { if (e.target.tagName === "SELECT" || e.target.type === "date") { state.page = 1; load(); } });
  $("#clearFilters").addEventListener("click", () => { form.reset(); state.page = 1; load({ announce: true }); });

  readUrl();
  load();
})();
