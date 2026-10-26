/* Alert center list with status, severity, rule, text and time filters. */
(function () {
  "use strict";
  const CA = window.CA, $ = CA.$;
  const form = $("#alertFilters"), rows = $("#alertRows");
  let status = new URLSearchParams(location.search).get("status") ?? "unresolved";

  function params() {
    const v = { status };
    ["q", "severity", "rule"].forEach((f) => { const x = form.elements[f].value.trim(); if (x) v[f] = x; });
    if (form.elements.start.value) v.start = CA.localDayIso(form.elements.start.value, false);
    if (form.elements.end.value) v.end = CA.localDayIso(form.elements.end.value, true);
    return v;
  }

  async function load(silent) {
    CA.$$("#statusSeg button").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.status === status)));
    if (silent !== true) rows.innerHTML = Array.from({ length: 5 }, () => '<tr><td colspan="9"><div class="skeleton" style="height:20px"></div></td></tr>').join("");
    try {
      const r = await CA.api("/api/alerts" + CA.query(params()));
      Object.entries(r.counts).forEach(([k, n]) => { const el = form.querySelector(`[data-count="${k}"]`); if (el) el.textContent = n; });
      $("#alertCount").textContent = `${r.items.length} alert${r.items.length === 1 ? "" : "s"} shown`;
      rows.innerHTML = r.items.length ? r.items.map((a) => `
        <tr data-uid="${CA.esc(a.uid)}" tabindex="0" style="cursor:pointer">
          <td><span style="display:inline-flex;align-items:center;gap:8px"><span class="sev-dot ${CA.esc(a.severity)}"></span><span class="mono">${CA.esc(a.uid)}</span></span></td>
          <td class="strong" style="min-width:240px">${CA.esc(a.title)}</td>
          <td><span class="mono dim">${CA.esc(a.rule_id)}</span></td>
          <td>${CA.pill(a.severity)}</td>
          <td>${CA.pill(a.status)}</td>
          <td class="mono">${CA.esc(a.actor || a.source_ip || a.group_key)}${a.actor && a.source_ip ? `<span class="dim"> · ${CA.esc(a.source_ip)}</span>` : ""}</td>
          <td class="mono" title="${CA.esc(a.created_at)} UTC">${CA.esc(CA.dateTime(a.created_at))}</td>
          <td class="right num">${a.event_count}</td>
          <td class="right"><a class="btn btn-sm btn-ghost" href="/alerts/${CA.esc(a.uid)}">Investigate ${CA.icon("arrow-right", "i-sm")}</a></td>
        </tr>`).join("")
        : `<tr><td colspan="9"><div class="empty">${CA.icon("shield-check")}<b>No alerts match</b><span>${status === "unresolved" ? "Nothing needs attention right now. Try the Event Simulator to trigger a rule." : "Change the filters to see more alerts."}</span></div></td></tr>`;
    } catch (err) {
      rows.innerHTML = `<tr><td colspan="9"><div class="error-box">${CA.esc(err.message)}</div></td></tr>`;
      CA.toast("error", "Could not load alerts", err.message);
    }
  }

  rows.addEventListener("click", (e) => {
    if (e.target.closest("a")) return;
    const tr = e.target.closest("tr[data-uid]");
    if (tr) location.href = `/alerts/${tr.dataset.uid}`;
  });
  rows.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && e.target.matches("tr[data-uid]")) location.href = `/alerts/${e.target.dataset.uid}`;
  });
  $("#statusSeg").addEventListener("click", (e) => {
    const b = e.target.closest("button");
    if (!b) return;
    status = b.dataset.status;
    load();
  });
  form.addEventListener("submit", (e) => { e.preventDefault(); load(); });
  form.addEventListener("change", load);
  form.elements.q.addEventListener("input", CA.debounce(load, 350));
  load();
  setInterval(() => { if (!document.hidden) load(true); }, 30000);
})();
