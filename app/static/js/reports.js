/* Report preview with the same filters used by the CSV and printable exports. */
(function () {
  "use strict";
  const CA = window.CA, $ = CA.$;
  const form = $("#reportForm"), preview = $("#reportPreview");
  let period = "7d";

  function params() {
    const p = { period };
    ["actor", "action", "outcome", "severity"].forEach((k) => { const v = form.elements[k].value.trim(); if (v) p[k] = v; });
    if (period === "custom") {
      if (form.elements.start.value) p.start = CA.localDayIso(form.elements.start.value, false);
      if (form.elements.end.value) p.end = CA.localDayIso(form.elements.end.value, true);
    }
    return p;
  }

  function bars(items, total, colorOf) {
    return items.map((it) => `<div style="display:grid;grid-template-columns:150px 1fr 56px;gap:10px;align-items:center;font-size:12.5px">
      <span class="muted">${CA.esc(it.label)}</span>
      <span style="height:8px;border-radius:4px;background:#111C30;overflow:hidden"><span style="display:block;height:100%;width:${total ? (it.count / total) * 100 : 0}%;background:${colorOf(it)};border-radius:4px;transition:width .6s"></span></span>
      <span class="num right">${CA.num(it.count)}</span></div>`).join("");
  }

  async function load(announce) {
    const p = params();
    const qs = CA.query(p);
    const csv = $("#csvBtn"), pr = $("#printBtn");
    if (csv) csv.href = "/reports/export.csv" + qs;
    if (pr) pr.href = "/reports/print" + qs;
    preview.innerHTML = '<div class="card"><div class="skeleton" style="height:90px"></div></div><div class="card"><div class="skeleton" style="height:240px"></div></div>';
    try {
      const r = await CA.api("/api/reports/summary" + qs);
      const s = r.summary;
      $("#reportMeta").textContent = `Generated ${CA.fullDateTime(r.generated_at)} · ${CA.num(s.total)} records match` + (r.rows_truncated ? " · preview shows the latest 200" : "");
      const sevOrder = ["critical", "high", "medium", "low", "info"];
      const sevColor = { critical: "#F0506E", high: "#F0506E", medium: "#F5B547", low: "#27D8FF", info: "#4A5A75" };
      preview.innerHTML = `
        <section class="metrics rise">
          ${[["Events", s.total, "cyan"], ["Successful", s.success, "green"], ["Failed", s.failed, "red"], ["Denied", s.denied, "amber"],
             ["Distinct users", s.actors, "blue"], ["Alerts raised", r.alerts.total, "red"]].map(([l, v, a]) => `
            <div class="metric accent-${a}"><div class="metric-top"><span class="metric-label">${l}</span></div><div class="metric-value" data-value="0">0</div>
            <div class="metric-trend">${l === "Alerts raised" ? `${r.alerts.open} open · ${r.alerts.acknowledged} ack · ${r.alerts.resolved} resolved` : ""}</div></div>`).join("")}
        </section>
        <section class="row rise rise-2">
          <div class="card grow-1"><div class="card-head"><h3>Event distribution</h3></div>
            ${r.distribution.length ? bars(r.distribution, s.total, (it) => CA.DIST_COLORS[it.key] || "#4A5A75") : '<div class="note-text">No events.</div>'}</div>
          <div class="card grow-1"><div class="card-head"><h3>Severity</h3></div>
            ${bars(sevOrder.filter((k) => r.severity[k]).map((k) => ({ label: CA.cap(k), count: r.severity[k], key: k })), s.total, (it) => sevColor[it.key])}</div>
          <div class="card grow-1"><div class="card-head"><h3>Alert summary</h3></div>
            ${r.alerts.by_rule.length ? r.alerts.by_rule.map((b) => `<a class="entity" href="/alerts?rule=${CA.esc(b.rule_id)}"><span class="mono">${CA.esc(b.rule_id)}</span><span>${CA.esc(b.name)}</span><span class="meta">${b.n}</span></a>`).join("")
              : '<div class="note-text">No alerts were raised in this period.</div>'}
            <div class="note-text">${r.alerts.high} high-severity alert(s) in the period.</div></div>
        </section>
        <section class="card rise rise-3" style="padding:0;gap:0;overflow:hidden">
          <div class="card-head" style="padding:16px 18px"><h3>Detailed events</h3><span class="dim" style="font-size:12px">latest ${r.rows.length} of ${CA.num(s.total)}</span></div>
          <div class="table-wrap" style="border:0;border-radius:0;max-height:520px;overflow:auto">
            <table class="table" style="min-width:900px"><thead><tr><th>Event</th><th>Time</th><th>User</th><th>Action</th><th>Resource</th><th>Source IP</th><th>Outcome</th><th>Severity</th></tr></thead>
            <tbody>${r.rows.length ? r.rows.map((e) => `<tr data-id="${e.id}" style="cursor:pointer"><td class="mono">${CA.esc(e.uid)}</td><td class="mono">${CA.esc(CA.dateTime(e.ts))}</td>
              <td class="strong">${CA.esc(e.actor)}</td><td>${CA.esc(e.action_label)}</td><td class="mono">${CA.esc(e.resource || "—")}</td><td class="mono">${CA.esc(e.source_ip || "—")}</td>
              <td>${CA.pill(e.outcome)}</td><td>${CA.pill(e.severity)}</td></tr>`).join("") : `<tr><td colspan="8"><div class="empty"><b>No events match this report</b></div></td></tr>`}</tbody></table>
          </div>
        </section>`;
      CA.$$(".metric .metric-value", preview).forEach((el, i) => CA.countUp(el, [s.total, s.success, s.failed, s.denied, s.actors, r.alerts.total][i], 700));
      CA.$$("tr[data-id]", preview).forEach((tr) => tr.addEventListener("click", () => CA.openEvent(tr.dataset.id)));
      if (announce) CA.toast("info", "Report preview updated", `${CA.num(s.total)} records in the selected period.`, 2400);
    } catch (err) {
      preview.innerHTML = `<div class="error-box">${CA.esc(err.message)}</div>`;
      CA.toast("error", "Report could not be generated", err.message);
    }
  }

  $("#periodSeg").addEventListener("click", (e) => {
    const b = e.target.closest("button");
    if (!b) return;
    period = b.dataset.period;
    CA.$$("#periodSeg button").forEach((x) => x.setAttribute("aria-pressed", String(x === b)));
    form.elements.start.disabled = form.elements.end.disabled = period !== "custom";
    if (period === "custom" && !form.elements.start.value) {
      const d = new Date(); const pad = (n) => String(n).padStart(2, "0");
      form.elements.end.value = `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
      d.setDate(d.getDate() - 7);
      form.elements.start.value = `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
    }
    load(false);
  });
  form.addEventListener("submit", (e) => { e.preventDefault(); load(true); });
  form.addEventListener("change", (e) => { if (e.target.tagName === "SELECT" || e.target.type === "date") load(false); });
  ["#csvBtn", "#printBtn"].forEach((s) => $(s)?.addEventListener("click", () => {
    CA.toast("success", s === "#csvBtn" ? "CSV export started" : "Printable report opened",
      "Generated from a live database query; the export itself is recorded as a report.export audit event.", 3500);
  }));
  load(false);
})();
