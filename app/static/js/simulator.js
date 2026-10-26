/* Event simulator: presets, custom events and the guided playback — all through the real API. */
(function () {
  "use strict";
  const CA = window.CA, $ = CA.$;
  const form = $("#simForm");
  let opts = null, presetKey = null, filling = false, playing = false;

  /* ---------- form ---------- */
  function fillSelect(sel, items, value) {
    sel.innerHTML = items.map(([v, l]) => `<option value="${CA.esc(v)}">${CA.esc(l)}</option>`).join("");
    if (value !== undefined && items.some(([v]) => v === value)) sel.value = value;
  }
  function syncAction(outcome, resource) {
    const action = opts.actions.find((a) => a.key === form.elements.action.value) || opts.actions[0];
    fillSelect(form.elements.outcome, action.outcomes.map((o) => [o, CA.cap(o)]), outcome);
    fillSelect(form.elements.resource, (opts.resources[action.key] || []).map((r) => [r, r]), resource);
  }
  function setMode() {
    const p = opts.presets.find((x) => x.key === presetKey);
    $("#modeTag").textContent = p ? `Preset · ${p.label}` : "Custom event";
    $("#expect").textContent = p ? p.expect : "A custom event is written with these values; matching rules are evaluated right after the write.";
    CA.$$(".preset").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.key === presetKey)));
  }
  function applyPreset(key) {
    const p = opts.presets.find((x) => x.key === key);
    if (!p) return;
    filling = true;
    presetKey = key;
    const prm = p.params;
    form.elements.user.value = (prm.users && prm.users[0]) || prm.user;
    form.elements.action.value = prm.action;
    syncAction(prm.outcome, prm.resource);
    form.elements.ip.value = prm.ip;
    form.elements.count.value = prm.count;
    if (prm.users) $("#expect").textContent = p.expect;
    filling = false;
    setMode();
  }
  form.addEventListener("change", (e) => {
    if (filling) return;
    if (e.target.name === "action") syncAction();
    presetKey = null;
    setMode();
  });
  form.addEventListener("input", (e) => { if (!filling && (e.target.name === "ip" || e.target.name === "count")) { presetKey = null; setMode(); } });

  function showFieldError(field, message) {
    CA.$$(".field-error", form).forEach((el) => el.classList.add("hidden"));
    CA.$$(".field.invalid", form).forEach((el) => el.classList.remove("invalid"));
    if (!field) return;
    const el = form.querySelector(`[data-err="${field}"]`);
    if (el) { el.textContent = message; el.classList.remove("hidden"); el.closest(".field").classList.add("invalid"); }
    else if (form.elements[field]) form.elements[field].closest(".field").classList.add("invalid");
  }

  /* ---------- result + history ---------- */
  function renderResult(r) {
    const n = r.events.length;
    const ids = n > 1 ? `${r.events[0].uid} … ${r.events[n - 1].uid}` : r.events[0].uid;
    const evals = r.evaluations.length ? r.evaluations.map((ev) => {
      const txt = !ev.enabled ? "Rule disabled — not evaluated" :
        ev.rule_id === "R-05" ? "Sensitive change recorded" :
        `${ev.count} of ${ev.threshold} ${ev.unit} within ${ev.window_minutes} min`;
      return `<div class="eval ${ev.matched ? "hit" : ""}"><span class="rid">${CA.esc(ev.rule_id)}</span><span class="txt">${CA.esc(txt)}</span>
        ${ev.matched ? CA.pill("high", "Matched") : CA.pill("", ev.enabled ? "Below threshold" : "Disabled")}</div>`;
    }).join("") : '<div class="eval"><span class="rid">—</span><span class="txt">No detection rule applies to this action and outcome.</span></div>';
    const alerts = r.alerts.map((a) => `<a class="entity" href="/alerts/${CA.esc(a.uid)}" style="border-color:rgba(240,80,110,.3);background:rgba(240,80,110,.06)">
      <span class="mono" style="color:var(--red-text)">${CA.esc(a.uid)}</span><span>${CA.esc(a.title)}</span>
      <span class="meta">${a.new ? "new alert" : "evidence attached"} →</span></a>`).join("");
    $("#result").innerHTML = `<div class="stack rise" style="gap:12px">
      <div class="callout ok" style="display:flex;gap:10px;align-items:center;flex-wrap:wrap"><span class="mono" style="color:var(--green-text);font-weight:600">201 Created</span>
        <span>${n} event${n === 1 ? "" : "s"} persisted to <span class="mono">audit_events</span></span></div>
      <button type="button" class="link-btn mono" style="align-self:flex-start;padding:0" data-open="${r.events[n - 1].id}">${CA.esc(ids)}</button>
      <div class="section-label">Rule evaluation</div>${evals}${alerts}</div>`;
    $("#result [data-open]").addEventListener("click", (e) => CA.openEvent(e.currentTarget.dataset.open));
  }

  async function loadHistory() {
    try {
      const r = await CA.api("/api/simulator/history");
      $("#history").innerHTML = r.items.length ? r.items.slice(0, 8).map((e) => `<li style="cursor:pointer" data-open="${e.id}" tabindex="0">
        <span class="mono dim" style="font-size:11.5px">${CA.esc(CA.time(e.ts))}</span>
        <span class="hl">${CA.esc(e.action_label)} · ${CA.esc(e.actor)}</span>${CA.pill(e.outcome)}</li>`).join("")
        : '<li><span class="note-text">No simulated events yet.</span></li>';
    } catch (err) {
      $("#history").innerHTML = `<li><span class="error-box">${CA.esc(err.message)}</span></li>`;
    }
  }
  $("#history").addEventListener("click", (e) => { const li = e.target.closest("[data-open]"); if (li) CA.openEvent(li.dataset.open); });
  $("#history").addEventListener("keydown", (e) => { if (e.key === "Enter" && e.target.dataset.open) CA.openEvent(e.target.dataset.open); });

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    showFieldError(null);
    const count = Number(form.elements.count.value);
    if (!Number.isInteger(count) || count < 1 || count > 20) { showFieldError("count", "Enter a whole number from 1 to 20."); return; }
    if (!form.elements.ip.value.trim()) { showFieldError("ip", "Enter a private or documentation-range IP."); return; }
    const payload = presetKey ? { preset: presetKey } : {
      user: form.elements.user.value, action: form.elements.action.value, outcome: form.elements.outcome.value,
      resource: form.elements.resource.value, ip: form.elements.ip.value.trim(), count,
    };
    const btn = $("#execBtn");
    CA.busy(btn, true, "Writing to the audit log…");
    try {
      const r = await CA.api("/api/simulate", { method: "POST", body: payload });
      renderResult(r);
      const created = r.alerts.filter((a) => a.new);
      CA.toast("success", "Simulation recorded", `${r.events.length} event(s) stored${created.length ? ` · ${created.map((a) => a.uid).join(", ")} opened` : ""}.`);
      if (created.length) CA.toast("warn", "Detection rule matched", `${created[0].uid}: ${created[0].title}`, 7000);
      loadHistory();
      CA.refreshHealth();
      CA.refreshNotifications();
    } catch (err) {
      showFieldError(err.field, err.message);
      CA.toast("error", "Simulation rejected by the server", err.message);
    } finally {
      CA.busy(btn, false);
    }
  });

  /* ---------- guided playback ---------- */
  const STEPS = [
    "Generate failed authentication events",
    "Persist the events in the audit database",
    "Evaluate the detection rule",
    "Create an alert if the threshold is met",
    "Update the alert count and recent events",
    "Open the alert investigation panel",
    "Show the evidence and recommended steps",
  ];
  const stepsEl = $("#playSteps");
  function resetPlay() {
    stepsEl.innerHTML = STEPS.map((t, i) => `<li class="play-step" data-i="${i}"><span class="h"><span class="num">${i + 1}</span>STEP ${i + 1}</span>
      <span class="ttl">${CA.esc(t)}</span><span class="res">pending</span></li>`).join("");
    $("#playOutcome").innerHTML = "";
  }
  function setStep(i, state, text) {
    const li = stepsEl.children[i];
    li.className = `play-step ${state}`;
    li.querySelector(".h .num, .h .spinner, .h .ok-icon, .h .bad-icon")?.remove();
    const marker = state === "running" ? '<span class="spinner" style="width:18px;height:18px"></span>'
      : state === "done" ? `<span class="ok-icon">${CA.icon("check")}</span>` : state === "fail" ? `<span class="bad-icon">${CA.icon("x")}</span>` : `<span class="num">${i + 1}</span>`;
    li.querySelector(".h").insertAdjacentHTML("afterbegin", marker);
    li.querySelector(".res").textContent = text;
  }
  const pause = (ms) => new Promise((r) => setTimeout(r, CA.reduceMotion ? 0 : ms));

  async function runPlayback() {
    if (playing) return;
    playing = true;
    resetPlay();
    const btn = $("#playRun");
    CA.busy(btn, true, "Running…");
    const user = $("#playUser").value;
    let step = 0;
    try {
      // 1 — generate five failures through the real endpoint
      setStep(0, "running", "POST /api/simulate …");
      const results = [];
      for (let k = 0; k < 5; k++) {
        const r = await CA.api("/api/simulate", { method: "POST", body: { preset: "failed_login", user } });
        results.push(r);
        stepsEl.children[0].querySelector(".res").textContent = `${k + 1}/5 · ${r.events[0].uid} → 201`;
        await pause(260);
      }
      const ids = results.map((r) => r.events[0].id);
      setStep(0, "done", `5 × POST /api/simulate → 201 (${user})`);
      await pause(350);

      // 2 — confirm the rows exist in the database
      step = 1; setStep(1, "running", "querying audit_events …");
      const check = await CA.api("/api/events" + CA.query({ actor: user, action: "login", outcome: "failed", origin: "simulated", since_id: ids[0] - 1, per_page: 50 }));
      const found = ids.filter((id) => check.items.some((e) => e.id === id)).length;
      if (found !== 5) throw new Error(`only ${found} of 5 events found`);
      setStep(1, "done", `${found} of 5 rows found · ${results[0].events[0].uid}…${results[4].events[0].uid}`);
      await pause(350);

      // 3 — rule evaluation returned by the backend for the last write
      step = 2; setStep(2, "running", "reading R-01 evaluation …");
      const ev = results[4].evaluations.find((x) => x.rule_id === "R-01");
      if (!ev) throw new Error("R-01 did not evaluate this event");
      if (!ev.enabled) throw new Error("R-01 is disabled on the Detection rules page");
      setStep(2, ev.matched ? "done" : "fail", `R-01 · ${ev.count} of ${ev.threshold} failures in ${ev.window_minutes} min → ${ev.matched ? "threshold met" : "below threshold"}`);
      if (!ev.matched) throw Object.assign(new Error("threshold not met — no alert is created"), { handled: true });
      await pause(350);

      // 4 — alert creation
      step = 3; setStep(3, "running", "checking alert …");
      const alertUid = ev.alert_uid;
      const createdNow = results.some((r) => r.evaluations.some((x) => x.rule_id === "R-01" && x.alert_new && x.alert_uid === alertUid));
      setStep(3, "done", createdNow ? `INSERT alerts → ${alertUid} (new)` : `evidence attached to already-open ${alertUid}`);
      await pause(350);

      // 5 — dashboard numbers
      step = 4; setStep(4, "running", "GET /api/stats …");
      const stats = await CA.api(`/api/stats?range=24h&tz=${new Date().getTimezoneOffset()}`);
      CA.refreshHealth(); CA.refreshNotifications(); loadHistory();
      setStep(4, "done", `open alerts ${stats.cards.open_alerts} · events ${CA.num(stats.cards.total)}`);
      await pause(350);

      // 6 — load the investigation data
      step = 5; setStep(5, "running", `GET /api/alerts/${alertUid} …`);
      const detail = await CA.api(`/api/alerts/${alertUid}`);
      setStep(5, "done", `200 · ${detail.alert.title}`);
      await pause(350);

      // 7 — evidence summary
      step = 6;
      setStep(6, "done", `${detail.evidence.length} supporting events · ${detail.recommended.length} recommended steps`);
      $("#playOutcome").innerHTML = `<div class="callout danger rise" style="display:flex;flex-wrap:wrap;gap:12px;align-items:center">
        <span class="mono" style="color:var(--red-text)">${CA.esc(alertUid)} · ${CA.esc(CA.cap(detail.alert.severity))}</span>
        <span style="flex:1 1 260px">${CA.esc(detail.alert.explanation)}</span>
        <a class="btn btn-primary" href="/alerts/${CA.esc(alertUid)}">Open investigation ${CA.icon("arrow-right", "i-sm")}</a></div>`;
      CA.toast("success", "Guided scenario complete", `${alertUid} is ready for investigation.`);
    } catch (err) {
      if (!err.handled) setStep(step, "fail", err.message);
      for (let i = step + 1; i < STEPS.length; i++) setStep(i, "", "not run");
      $("#playOutcome").innerHTML = `<div class="error-box">Playback stopped at step ${step + 1}: ${CA.esc(err.message)}</div>`;
      CA.toast("error", "Guided scenario stopped", err.message);
    } finally {
      playing = false;
      CA.busy(btn, false);
    }
  }
  $("#playRun").addEventListener("click", runPlayback);
  $("#playReset").addEventListener("click", () => { if (!playing) resetPlay(); });

  /* ---------- init ---------- */
  (async function init() {
    resetPlay();
    try {
      opts = await CA.api("/api/simulator/options");
      fillSelect(form.elements.user, opts.users.map((u) => [u.username, `${u.username} · ${u.role}`]));
      fillSelect($("#playUser"), opts.users.filter((u) => u.username !== "admin").map((u) => [u.username, u.username]), "m.ali");
      fillSelect(form.elements.action, opts.actions.map((a) => [a.key, a.label]));
      $("#presets").innerHTML = opts.presets.map((p, i) => `<button type="button" class="preset" data-key="${CA.esc(p.key)}" aria-pressed="false">
        <span class="top"><span class="n">${String(i + 1).padStart(2, "0")}</span><span class="d ${CA.esc(p.color)}"></span></span>
        <span class="name">${CA.esc(p.label)}</span><span class="exp">${CA.esc(p.expect)}</span></button>`).join("");
      CA.$$(".preset").forEach((b) => b.addEventListener("click", () => applyPreset(b.dataset.key)));
      applyPreset("failed_login");
    } catch (err) {
      $("#presets").innerHTML = `<div class="error-box">${CA.esc(err.message)}</div>`;
    }
    loadHistory();
  })();
})();
