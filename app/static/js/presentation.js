/* Presentation mode: large metrics, highlighted alert, live stream and the guided demo sequence. */
(function () {
  "use strict";
  const CA = window.CA, $ = CA.$;
  let latestAlert = null, latestId = 0;

  const STEPS = [
    { t: "System introduction", talk: "Start the app: each start-up step completes only when the backend answers — nothing is faked.", href: () => "/?intro=1", go: "Play intro" },
    { t: "Dashboard overview", talk: "Every number is a database query. Point out the health panel (real checks) and the Demo data label.", href: () => "/", go: "Open dashboard" },
    { t: "Trigger a failed login", talk: "Press “Failed login”. One failure is stored and R-01 counts it, but no alert yet — show the live stream.", href: () => "/simulator", go: "Open simulator" },
    { t: "Trigger repeated failed logins", talk: "Press “Repeated failed logins” or run the guided scenario: five failures in ten minutes meet R-01.", href: () => "/simulator", go: "Open guided scenario" },
    { t: "Show the generated alert", talk: "The alert explains the rule, threshold and window. Wording stays “requires investigation” — not proof of an attack.", href: () => "/alerts", go: "Open alert center" },
    { t: "Open the investigation workspace", talk: "Walk the timeline: context, evidence, the trigger event, then acknowledge and add a note — both are audited.", href: () => latestAlert ? `/alerts/${latestAlert.uid}` : "/alerts", go: "Open investigation" },
    { t: "Filter the audit logs", talk: "Filter Action = Login and Outcome = Failed, open an event, copy its ID; secrets are never logged.", href: () => "/logs?action=login&outcome=failed", go: "Open audit logs" },
    { t: "Generate a report", talk: "Preview the period, export CSV (formula-escaped) and the printable report. Exports are themselves audited.", href: () => "/reports", go: "Open reports" },
  ];
  let step = 0;
  try { step = Math.min(STEPS.length - 1, Math.max(0, Number(localStorage.getItem("ca_present_step") || 0))); } catch (_) { /* storage blocked */ }

  function renderSeq() {
    $("#stepN").textContent = step + 1;
    $("#stepTitle").textContent = STEPS[step].t;
    $("#progress").innerHTML = STEPS.map((_, i) => `<span class="${i < step ? "done" : i === step ? "cur" : ""}"></span>`).join("");
    $("#seq").innerHTML = STEPS.map((s, i) => `<li><button type="button" class="seq-step ${i < step ? "done" : ""}" data-i="${i}" ${i === step ? 'aria-current="step"' : ""}>
      <span class="no">${i < step ? CA.icon("check", "i-sm") : i + 1}</span>
      <span style="flex:1"><span class="tt" style="display:block">${CA.esc(s.t)}</span>${i === step ? `<span class="talk" style="display:block">${CA.esc(s.talk)}</span>` : ""}</span></button></li>`).join("");
    const go = $("#goBtn");
    go.href = STEPS[step].href();
    go.textContent = `${STEPS[step].go} →`;
    try { localStorage.setItem("ca_present_step", String(step)); } catch (_) { /* ignore */ }
  }
  const move = (d) => { step = Math.min(STEPS.length - 1, Math.max(0, step + d)); renderSeq(); };
  $("#seq").addEventListener("click", (e) => { const b = e.target.closest("[data-i]"); if (b) { step = Number(b.dataset.i); renderSeq(); } });
  $("#prevBtn").addEventListener("click", () => move(-1));
  $("#nextBtn").addEventListener("click", () => move(1));
  document.addEventListener("keydown", (e) => {
    if (/^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName) || document.querySelector(".scrim")) return;
    if (e.key === "ArrowRight" || e.key === "PageDown") { e.preventDefault(); move(1); }
    if (e.key === "ArrowLeft" || e.key === "PageUp") { e.preventDefault(); move(-1); }
  });

  async function loadStats() {
    try {
      const s = await CA.api(`/api/stats?range=24h&tz=${new Date().getTimezoneOffset()}`);
      CA.$$("[data-m]").forEach((el) => CA.countUp(el, s.cards[el.dataset.m]));
      const notes = {
        total: `${CA.num(s.last_24h.total)} in the last 24 h · stored in SQLite`,
        failed: `${CA.num(s.last_24h.failed)} in the last 24 h`,
        open_alerts: `${s.trends.open_alerts >= 0 ? "+" : ""}${s.trends.open_alerts} new vs previous 24 h`,
        high_alerts: "unresolved",
      };
      CA.$$("[data-n]").forEach((el) => (el.textContent = notes[el.dataset.n]));
    } catch (err) {
      CA.$$("[data-n]").forEach((el) => (el.textContent = "unavailable"));
    }
  }

  async function loadAlert() {
    try {
      const r = await CA.api("/api/alerts?status=unresolved");
      const items = r.items.slice().sort((a, b) => (b.created_at > a.created_at ? 1 : -1));
      latestAlert = items.find((a) => a.severity === "high" || a.severity === "critical") || items[0] || null;
      const host = $("#heroAlert");
      if (!latestAlert) {
        host.className = "card"; host.style.background = "rgba(10,18,34,.85)";
        host.innerHTML = `<div class="empty">${CA.icon("shield-check")}<b>No unresolved alerts</b><span>Launch “Repeated failed logins” to see the detection engine respond.</span></div>`;
      } else {
        const a = latestAlert;
        host.className = "hero-alert";
        host.removeAttribute("style");
        host.innerHTML = `<div class="stack" style="flex:1 1 380px;gap:10px">
            <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap"><span class="mono" style="font-size:15px;color:var(--red-text)">${CA.esc(a.uid)}</span>${CA.pill(a.severity)}${CA.pill(a.status)}<span class="mono dim">${CA.esc(a.rule_id)} · ${CA.esc(CA.ago(a.created_at))}</span></div>
            <h2>${CA.esc(a.title)}</h2><p>${CA.esc(a.explanation)}</p></div>
          <a class="btn btn-primary btn-lg" href="/alerts/${CA.esc(a.uid)}" style="height:54px;font-size:16px">Open investigation ${CA.icon("arrow-right", "i-sm")}</a>`;
      }
      renderSeq();
    } catch (err) {
      $("#heroAlert").innerHTML = `<div class="error-box">${CA.esc(err.message)}</div>`;
    }
  }

  function feedRow(e, fresh) {
    return `<li class="${fresh ? "is-new" : ""}" data-id="${e.id}" style="cursor:pointer">
      <span class="mono dim" style="font-size:14px;width:80px">${CA.esc(CA.time(e.ts))}</span>
      <span style="font-weight:600;width:120px">${CA.esc(e.actor)}</span>
      <span style="flex:1 1 220px;color:#C9D4E5">${CA.esc(e.action_label)}${e.resource && e.resource.length < 36 ? ` <span class="dim" style="font-size:14px">${CA.esc(e.resource)}</span>` : ""}</span>
      <span class="mono dim" style="font-size:14px">${CA.esc(e.source_ip || "—")}</span>
      <span class="pill ${CA.esc(e.outcome)}" style="height:28px;font-size:13.5px">${CA.esc(e.outcome)}</span>${CA.originPill(e.origin)}</li>`;
  }
  async function initFeed() {
    const r = await CA.api("/api/events?per_page=6&sort=ts&dir=desc");
    latestId = r.latest_id;
    $("#feed").innerHTML = r.items.map((e) => feedRow(e, false)).join("") || '<li class="note-text">No events yet.</li>';
    $("#liveTag .txt").textContent = `Polling every ${Math.round(CA.poll / 1000)} s`;
  }
  async function poll() {
    if (document.hidden) return;
    const tag = $("#liveTag");
    try {
      const r = await CA.api(`/api/events?since_id=${latestId}&per_page=50&sort=ts&dir=asc`);
      tag.className = "live-tag"; tag.querySelector(".txt").textContent = `Polling every ${Math.round(CA.poll / 1000)} s`;
      if (!r.items.length) return;
      latestId = Math.max(latestId, ...r.items.map((e) => e.id));
      $("#feed").insertAdjacentHTML("afterbegin", r.items.slice().sort((a, b) => b.id - a.id).map((e) => feedRow(e, true)).join(""));
      while ($("#feed").children.length > 6) $("#feed").lastElementChild.remove();
      loadStats(); loadAlert();
    } catch (err) {
      tag.className = "live-tag error"; tag.querySelector(".txt").textContent = "Disconnected · retrying";
    }
  }
  $("#feed").addEventListener("click", (e) => { const li = e.target.closest("[data-id]"); if (li) CA.openEvent(li.dataset.id); });

  CA.$$("[data-preset]").forEach((btn) => btn.addEventListener("click", async () => {
    CA.busy(btn, true, "Writing…");
    try {
      const r = await CA.api("/api/simulate", { method: "POST", body: { preset: btn.dataset.preset } });
      const ev = r.evaluations.find((x) => x.rule_id === "R-01");
      const created = r.alerts.filter((a) => a.new);
      $("#launchResult").innerHTML = `<span style="color:var(--green-text)">201 Created</span> · ${r.events.length} event(s) stored (${CA.esc(r.events[0].uid)}${r.events.length > 1 ? "…" + CA.esc(r.events[r.events.length - 1].uid) : ""})` +
        (ev ? ` · R-01: ${ev.count} of ${ev.threshold} failures in ${ev.window_minutes} min` : "") +
        (r.alerts.length ? ` · <a href="/alerts/${CA.esc(r.alerts[0].uid)}">${CA.esc(r.alerts[0].uid)} ${created.length ? "opened" : "updated"} →</a>` : " · no alert");
      CA.toast(created.length ? "warn" : "success", created.length ? "Detection rule matched" : "Simulation recorded",
        created.length ? `${created[0].uid}: ${created[0].title}` : `${r.events.length} event(s) stored in the audit log.`);
      await poll();
      loadStats(); loadAlert();
      if (created.length && step < 4) { step = 4; renderSeq(); }
    } catch (err) {
      CA.toast("error", "Scenario rejected", err.message);
    } finally {
      CA.busy(btn, false);
    }
  }));

  renderSeq();
  loadStats();
  loadAlert();
  initFeed().catch((err) => { $("#feed").innerHTML = `<li class="error-box">${CA.esc(err.message)}</li>`; });
  setInterval(poll, CA.poll);
  setInterval(() => { if (!document.hidden) loadStats(); }, 20000);
})();
