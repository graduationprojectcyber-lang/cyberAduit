/* Incident investigation workspace for one alert. */
(function () {
  "use strict";
  const CA = window.CA, $ = CA.$;
  const uid = $("#workspace").dataset.uid;
  const stepKey = `ca_steps_${uid}`;
  let data = null;

  function loadSteps() { try { return JSON.parse(localStorage.getItem(stepKey) || "{}"); } catch (_) { return {}; } }
  function saveSteps(v) { try { localStorage.setItem(stepKey, JSON.stringify(v)); } catch (_) { /* storage blocked */ } }

  function renderSummary() {
    const a = data.alert;
    const stage = a.status === "open" ? 0 : a.status === "acknowledged" ? 1 : 2;
    const stages = [
      ["Open", `${CA.dateTime(a.created_at)} · detection engine`],
      ["Acknowledged", a.acknowledged_at ? `${CA.dateTime(a.acknowledged_at)} · ${a.acknowledged_by}` : "pending"],
      ["Resolved", a.resolved_at ? `${CA.dateTime(a.resolved_at)} · ${a.resolved_by}` : "pending"],
    ];
    const actions = data.can_act ? `
      ${a.status === "open" ? `<button class="btn" type="button" id="ackBtn">${CA.icon("check", "i-sm")}Acknowledge</button>` : ""}
      <button class="btn" type="button" id="noteJump">${CA.icon("plus", "i-sm")}Add note</button>
      ${a.status !== "resolved" ? `<button class="btn btn-primary" type="button" id="resolveBtn">Resolve…</button>` : ""}`
      : `<span class="note-text">Your role can view this alert but not change it.</span>`;
    $("#summary").innerHTML = `
      <div class="row" style="align-items:flex-start;gap:16px">
        <div class="stack" style="flex:1 1 360px;gap:8px">
          <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
            <span class="mono muted">${CA.esc(a.uid)}</span>${CA.pill(a.severity)}${CA.pill(a.status)}
          </div>
          <h2 style="font-size:22px;line-height:1.25">${CA.esc(a.title)}</h2>
          <div class="muted" style="font-size:13px">Triggered <span class="mono" style="color:var(--text)">${CA.esc(CA.fullDateTime(a.created_at))}</span> <span class="dim">(${CA.esc(a.created_at)} UTC)</span>
            by rule <b style="color:var(--text);font-weight:500">${CA.esc(data.rule.id)} · ${CA.esc(data.rule.name)}</b></div>
        </div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">${actions}</div>
      </div>
      <ol class="stepper" aria-label="Investigation status">${stages.map((s, i) => `
        <li class="${i <= stage ? "done" : ""} ${i === 2 ? "final" : ""}"><span class="bar"></span><span class="lbl">${s[0]}</span><span class="meta">${CA.esc(s[1])}</span></li>`).join("")}
      </ol>
      ${a.resolution ? `<div class="callout ok"><b>Resolution:</b> ${CA.esc(a.resolution)}</div>` : ""}`;
    $("#ackBtn")?.addEventListener("click", acknowledge);
    $("#resolveBtn")?.addEventListener("click", resolve);
    $("#noteJump")?.addEventListener("click", () => { const t = $("#noteText"); if (t) { t.scrollIntoView({ behavior: CA.reduceMotion ? "auto" : "smooth", block: "center" }); t.focus(); } });
  }

  function renderWhy() {
    const a = data.alert, r = data.rule, ev = data.evidence;
    const trigger = ev.find((e) => e.is_trigger) || ev[ev.length - 1];
    let ticks = "", labels = "";
    if (ev.length && trigger) {
      const tTrig = new Date(trigger.ts).getTime();
      const start = Math.min(new Date(ev[0].ts).getTime(), tTrig - a.window_minutes * 60000);
      const end = Math.max(new Date(ev[ev.length - 1].ts).getTime(), tTrig) + 1;
      const frac = (t) => Math.min(1, Math.max(0, (t - start) / (end - start)));
      ticks = ev.map((e) => `<span class="tick ${e.is_trigger ? "trigger" : ""}" style="left:calc(14px + (100% - 28px) * ${frac(new Date(e.ts).getTime()).toFixed(4)})" title="${CA.esc(e.uid)} · ${CA.esc(CA.time(e.ts))}"></span>`).join("");
      labels = `<span class="lbl" style="left:14px">${CA.esc(CA.time(new Date(start).toISOString()))}</span><span class="lbl" style="right:14px">${CA.esc(CA.time(new Date(end).toISOString()))}</span>`;
    }
    $("#why").innerHTML = `
      <div class="card-head"><div><h3>Why this alert triggered</h3><div class="sub">${CA.esc(r.description)}</div></div></div>
      <p class="callout" style="margin:0">${CA.esc(a.explanation)}</p>
      <dl class="facts">
        <div><dt>Rule</dt><dd>${CA.esc(r.id)}</dd></div>
        <div><dt>Threshold</dt><dd>${r.id === "R-05" ? "any change" : `≥ ${a.threshold} ${CA.esc(r.id === "R-02" ? "accounts" : "events")}`}</dd></div>
        <div><dt>Time window</dt><dd>${a.window_minutes} min</dd></div>
        <div><dt>Supporting events</dt><dd>${ev.length}</dd></div>
      </dl>
      <div class="window-track" role="img" aria-label="${ev.length} supporting events placed on the detection window; the red mark is the event that met the threshold"><span class="axis"></span>${ticks}${labels}</div>
      ${data.findings.map((f) => `<div class="callout ${f.ok ? "ok" : "warn"}">${CA.icon(f.ok ? "check" : "alert", "i-sm")} ${CA.esc(f.text)}</div>`).join("")}
      <p class="note-text" style="margin:0">A matched pattern indicates potential unauthorized activity; it does not by itself prove an attack.</p>`;
  }

  function renderTimeline() {
    const list = $("#timeline");
    if (!data.timeline.length) { list.innerHTML = '<li><div class="empty" style="grid-column:1/-1">No events linked.</div></li>'; return; }
    let lastDay = "";
    list.innerHTML = data.timeline.map((e) => {
      const day = CA.date(e.ts);
      const dayRow = day !== lastDay ? `<li><span></span><span class="rail"></span><span class="section-label" style="padding:10px 0 2px">${CA.esc(day)}</span></li>` : "";
      lastDay = day;
      const kind = e.is_trigger ? "trigger" : e.phase === "lifecycle" ? "lifecycle" : e.outcome;
      const box = e.is_trigger ? "trigger" : e.is_evidence ? "evidence" : e.phase === "lifecycle" ? "" : "context";
      const flag = e.is_trigger ? '<span class="flag trigger">Trigger event</span>' : e.is_evidence ? '<span class="flag evidence">Evidence</span>'
        : e.phase === "lifecycle" ? "" : `<span class="flag context">${e.phase === "before" ? "Before" : "After"}</span>`;
      return `${dayRow}<li><span class="t">${CA.esc(CA.time(e.ts))}</span><span class="rail"><span class="dot ${kind}"></span></span>
        <button type="button" class="box ${box}" data-ev="${e.id}" style="background-color:transparent;text-align:left;color:inherit;cursor:pointer;width:100%;border-style:solid">
          <span class="head"><span class="msg">${CA.esc(e.message)}</span>${flag}</span>
          <span class="meta" style="display:block">${CA.esc(e.uid)} · ${CA.esc(e.actor)} · ${CA.esc(e.source_ip || "—")} · ${CA.esc(e.outcome)}</span>
        </button></li>`;
    }).join("");
  }

  function renderEntities() {
    const ent = data.entities;
    const group = (label, items, link) => items.length ? `<div class="stack" style="gap:6px"><div class="section-label">${label}</div>
      ${items.map((i) => `<a class="entity" href="${link(i)}"><span class="mono">${CA.esc(i.name)}</span><span class="meta">${i.failed !== undefined ? `${i.failed} failed · ${i.events} total` : `${i.events} events`}</span></a>`).join("")}</div>` : "";
    $("#entities").innerHTML = `<div class="card-head"><h3>Related entities</h3></div>
      ${group("Source IPs (simulated labels)", ent.ips, (i) => `/logs?ip=${encodeURIComponent(i.name)}`)}
      ${group("Affected accounts", ent.accounts, (i) => `/logs?actor=${encodeURIComponent(i.name)}`)}
      ${group("Action types", ent.actions, () => "/logs")}`;
  }

  function renderSteps() {
    const done = loadSteps();
    $("#steps").innerHTML = `<div class="card-head"><h3>Recommended investigation steps</h3></div>
      ${data.recommended.map((s, i) => `<label class="check"><input type="checkbox" data-step="${i}" ${done[i] ? "checked" : ""}><span>${CA.esc(s)}</span></label>`).join("")}
      <div class="note-text">Checklist progress is kept in this browser only.</div>`;
    CA.$$("[data-step]", $("#steps")).forEach((c) => c.addEventListener("change", () => {
      const v = loadSteps(); v[c.dataset.step] = c.checked; saveSteps(v);
    }));
  }

  function renderNotes() {
    const notes = data.notes;
    $("#notes").innerHTML = `<div class="card-head"><h3>Analyst notes</h3><span class="dim" style="font-size:12px">${notes.length}</span></div>
      ${notes.length ? notes.map((n) => `<div class="note-card"><span class="by"><b>${CA.esc(n.author)}</b> · <span class="mono">${CA.esc(CA.dateTime(n.created_at))}</span></span><span class="body">${CA.esc(n.body)}</span></div>`).join("")
        : '<div class="note-text">No notes yet.</div>'}
      ${data.can_act ? `<label class="field" id="noteField">Add a note
        <textarea class="textarea" id="noteText" rows="3" maxlength="2000" placeholder="What did you check? What did you find?"></textarea></label>
        <button class="btn" type="button" id="saveNote" style="align-self:flex-end">Save note</button>` : ""}`;
    $("#saveNote")?.addEventListener("click", saveNote);
  }

  async function load() {
    try {
      data = await CA.api(`/api/alerts/${encodeURIComponent(uid)}`);
      renderSummary(); renderWhy(); renderTimeline(); renderEntities(); renderSteps(); renderNotes();
    } catch (err) {
      $("#summary").innerHTML = `<div class="error-box">${CA.esc(err.message)} <a class="btn btn-sm" href="/alerts">Back to alerts</a></div>`;
      ["#why", "#entities", "#steps", "#notes", "#timelineCard"].forEach((s) => $(s).classList.add("hidden"));
    }
  }

  async function acknowledge(e) {
    const btn = e.currentTarget;
    CA.busy(btn, true, "Acknowledging…");
    try {
      const r = await CA.api(`/api/alerts/${uid}/acknowledge`, { method: "POST", body: {} });
      CA.toast("success", `${uid} acknowledged`, `State change recorded in the audit trail as ${r.event_uid}.`);
      await load();
      CA.refreshHealth();
    } catch (err) {
      CA.busy(btn, false);
      CA.toast("error", "Could not acknowledge", err.message);
    }
  }

  function resolve() {
    const layer = CA.openLayer("dialog", `
      <h2>Resolve ${CA.esc(uid)}</h2>
      <p class="muted" style="margin:0;line-height:1.6">Summarise what you found and what was done. The summary is stored with the alert and the resolution is written to the audit trail.</p>
      <label class="field" id="resField">Resolution summary (required)
        <textarea class="textarea" id="resText" rows="4" maxlength="1000" autofocus></textarea>
        <span class="field-error hidden" id="resErr"></span></label>
      <div class="actions"><button class="btn btn-ghost" type="button" data-close>Cancel</button>
        <button class="btn btn-success" type="button" id="resOk">Confirm resolution</button></div>`, { label: `Resolve ${uid}` });
    const ok = layer.panel.querySelector("#resOk");
    ok.addEventListener("click", async () => {
      const text = layer.panel.querySelector("#resText").value.trim();
      const errEl = layer.panel.querySelector("#resErr");
      if (text.length < 5) {
        errEl.textContent = "Write at least 5 characters."; errEl.classList.remove("hidden");
        layer.panel.querySelector("#resField").classList.add("invalid");
        return;
      }
      CA.busy(ok, true, "Resolving…");
      try {
        const r = await CA.api(`/api/alerts/${uid}/resolve`, { method: "POST", body: { resolution: text } });
        layer.close();
        CA.toast("success", `${uid} resolved`, `Resolution saved and recorded as ${r.event_uid}.`);
        await load();
        CA.refreshHealth();
      } catch (err) {
        CA.busy(ok, false);
        errEl.textContent = err.message; errEl.classList.remove("hidden");
      }
    });
  }

  async function saveNote(e) {
    const text = $("#noteText").value.trim();
    if (!text) { $("#noteField").classList.add("invalid"); CA.toast("warn", "Note is empty", "Write something before saving."); return; }
    const btn = e.currentTarget;
    CA.busy(btn, true, "Saving…");
    try {
      const r = await CA.api(`/api/alerts/${uid}/notes`, { method: "POST", body: { body: text } });
      CA.toast("success", "Note saved", `Recorded in the audit trail as ${r.event_uid}.`);
      await load();
    } catch (err) {
      CA.busy(btn, false);
      CA.toast("error", "Could not save the note", err.message);
    }
  }

  $("#timeline").addEventListener("click", (e) => {
    const b = e.target.closest("[data-ev]");
    if (b) CA.openEvent(b.dataset.ev);
  });
  $("#rawBtn").addEventListener("click", () => {
    if (!data) return;
    const t = data.evidence.find((e) => e.is_trigger) || data.evidence[data.evidence.length - 1];
    if (!t) return;
    const raw = { event_id: t.uid, timestamp_utc: t.ts, actor: t.actor, actor_role: t.actor_role, action: t.action, resource: t.resource,
      source_ip: t.source_ip, http_method: t.http_method, route: t.route, outcome: t.outcome, severity: t.severity, origin: t.origin,
      message: t.message, metadata: t.metadata, hash: t.hash, prev_hash: t.prev_hash };
    CA.openLayer("dialog", `<h2>Raw trigger event · ${CA.esc(t.uid)}</h2>
      <pre class="code" style="max-height:60vh;overflow:auto">${CA.esc(JSON.stringify(raw, null, 2))}</pre>
      <div class="note-text">Rendered as escaped text. Secrets are never stored in audit records.</div>
      <div class="actions"><button class="btn" type="button" data-copyraw>${CA.icon("copy", "i-sm")}Copy JSON</button><button class="btn btn-primary" type="button" data-close>Close</button></div>`,
      { label: "Raw event" }).panel.querySelector("[data-copyraw]").addEventListener("click", (ev) => CA.copy(JSON.stringify(raw, null, 2), ev.currentTarget));
  });

  load();
})();
