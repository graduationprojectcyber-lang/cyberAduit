/* Dashboard: metrics, charts, network, health and the live event stream — all from the API. */
(function () {
  "use strict";
  const CA = window.CA, $ = CA.$;
  const tz = new Date().getTimezoneOffset();
  const chart = CA.lineChart($("#volumeChart"));
  const donut = CA.donut($("#donut"), $("#distList"));
  const net = CA.network($("#netCanvas"), $("#netDetail"), $("#netChips"));
  const RANGE_LABEL = { "24h": "last 24 hours, hourly", "7d": "last 7 days, daily", "30d": "last 30 days, daily" };
  let range = "24h", stats = null, lastDist = "";

  /* ---------- stats ---------- */
  function renderStats() {
    CA.$$("[data-card]").forEach((card) => {
      const key = card.dataset.card;
      CA.countUp(card.querySelector(".metric-value"), stats.cards[key]);
      const delta = stats.trends[key];
      const trend = card.querySelector(".trend");
      const goodWhenUp = card.dataset.polarity === "up-good";
      trend.textContent = delta > 0 ? `+${CA.num(delta)}` : delta < 0 ? `−${CA.num(-delta)}` : "±0";
      trend.className = "trend " + (delta === 0 ? "trend-flat" : (delta > 0) === goodWhenUp ? "trend-up-good" : "trend-up-bad");
      card.querySelector(".trend-note").textContent = key.endsWith("alerts") ? "new vs previous 24 h" : "last 24 h vs previous 24 h";
    });
    const sum = (k) => stats.series.buckets.reduce((a, b) => a + b[k], 0);
    $("#legSuccess").textContent = CA.num(sum("success"));
    $("#legFailed").textContent = CA.num(sum("failed"));
    $("#legDenied").textContent = CA.num(sum("denied"));
    $("#rangeLabel").textContent = `Recorded operations by outcome · ${RANGE_LABEL[stats.series.range]}`;
    chart.update(stats.series.buckets, stats.series.unit);
    $("#volumeAxis").innerHTML = chart.axisLabels(stats.series.range === "7d" ? 4 : 5).map((l) => `<span>${CA.esc(l)}</span>`).join("");
    const dist = JSON.stringify(stats.distribution);
    if (dist !== lastDist) { donut.update(stats.distribution); lastDist = dist; }
  }

  async function loadStats({ toast = false } = {}) {
    try {
      stats = await CA.api(`/api/stats?range=${range}&tz=${tz}`);
      return true;
    } catch (err) {
      if (toast) CA.toast("error", "Could not load statistics", err.message);
      return false;
    }
  }

  CA.$$("#rangeSeg button").forEach((btn) => btn.addEventListener("click", async () => {
    if (btn.dataset.range === range) return;
    range = btn.dataset.range;
    CA.$$("#rangeSeg button").forEach((b) => b.setAttribute("aria-pressed", String(b === btn)));
    if (await loadStats({ toast: true })) renderStats();
  }));

  /* ---------- health ---------- */
  let lastOk = null;
  CA.onHealth((h) => {
    const list = $("#healthList");
    if (!list) return;
    const row = (cls, label, value) => `<li><span class="hd ${cls}"></span><span class="hl">${CA.esc(label)}</span><span class="hv">${CA.esc(value)}</span></li>`;
    if (h.error) {
      list.innerHTML = row("bad", "Backend API", "Unavailable") + row("bad", "Database connection", "Unknown") +
        row("warn", "Last successful refresh", lastOk ? `${CA.time(lastOk)} · ${CA.ago(lastOk)}` : "never") +
        `<li><span class="note-text" style="color:var(--red-text)">${CA.esc(h.error)}</span></li>`;
      return;
    }
    lastOk = new Date().toISOString();
    const last = h.last_event;
    list.innerHTML =
      row(h.database.ok ? "ok" : "bad", "Database connection", h.database.ok ? `Connected · ${h.database.latency_ms} ms` : "Unavailable") +
      row("ok", "Application", `Running · v${h.application.version}`) +
      row(h.detection.rules_enabled ? "ok" : "warn", "Detection engine", `${h.detection.rules_enabled} of ${h.detection.rules_total} rules enabled`) +
      row("info", "Last data refresh", `${CA.time(lastOk)} · just now`) +
      row("info", "Most recent audit event", last ? `${last.uid} · ${CA.ago(last.ts)}` : "none yet") +
      row(h.unresolved_alerts.total ? "warn" : "ok", "Unresolved alerts", `${h.unresolved_alerts.total} (${h.unresolved_alerts.high} high)`);
  });

  /* ---------- live feed ---------- */
  const feed = $("#feedBody"), liveTag = $("#liveTag"), pauseBtn = $("#pauseBtn");
  let latestId = 0, paused = false, waiting = [], polling = false;

  function rowHtml(e, fresh) {
    return `<tr class="${fresh ? "is-new" : ""}" data-id="${e.id}">
      <td class="mono">${CA.esc(CA.time(e.ts))}</td>
      <td class="mono">${CA.esc(e.uid)}</td>
      <td class="strong">${CA.esc(e.actor)}</td>
      <td>${CA.esc(e.action_label)} <span class="dim">${CA.esc(e.resource && e.resource.length < 40 ? e.resource : "")}</span></td>
      <td class="mono">${CA.esc(e.source_ip || "—")}</td>
      <td>${CA.pill(e.outcome)}</td><td>${CA.pill(e.severity)}</td><td>${CA.originPill(e.origin)}</td>
      <td class="right"><button class="link-btn" type="button" data-open="${e.id}">Details</button></td></tr>`;
  }
  function setLive(state, text) {
    liveTag.className = "live-tag" + (state === "paused" ? " paused" : state === "error" ? " error" : "");
    liveTag.querySelector(".txt").textContent = text;
  }
  function prepend(items) {
    if (!items.length) return;
    feed.querySelector(".empty-row")?.remove();
    const html = items.slice().sort((a, b) => b.id - a.id).map((e) => rowHtml(e, true)).join("");
    feed.insertAdjacentHTML("afterbegin", html);
    while (feed.children.length > 12) feed.lastElementChild.remove();
  }
  feed.addEventListener("click", (e) => {
    const b = e.target.closest("[data-open]");
    if (b) CA.openEvent(b.dataset.open);
  });

  async function initFeed() {
    try {
      const r = await CA.api("/api/events?per_page=10&sort=ts&dir=desc");
      latestId = r.latest_id;
      feed.innerHTML = r.items.length ? r.items.map((e) => rowHtml(e, false)).join("")
        : `<tr class="empty-row"><td colspan="9"><div class="empty">${CA.icon("activity")}<b>No events recorded yet</b><span>Sign-ins and simulator runs will appear here.</span></div></td></tr>`;
      setLive("live", `Live · polling every ${Math.round(CA.poll / 1000)} s`);
    } catch (err) {
      feed.innerHTML = `<tr><td colspan="9"><div class="error-box">Event stream unavailable: ${CA.esc(err.message)}</div></td></tr>`;
      setLive("error", "Disconnected");
    }
  }

  const refreshAfterNew = CA.debounce(async () => {
    if (await loadStats()) renderStats();
    net.refresh();
    CA.refreshHealth();
    CA.refreshNotifications();
  }, 600);

  async function pollFeed() {
    if (polling || document.hidden) return;
    polling = true;
    try {
      const r = await CA.api(`/api/events?since_id=${latestId}&per_page=50&sort=ts&dir=asc`);
      if (r.items.length) {
        latestId = Math.max(latestId, ...r.items.map((e) => e.id));
        if (paused) waiting = waiting.concat(r.items);
        else prepend(r.items);
        refreshAfterNew();
      }
      setLive(paused ? "paused" : "live", paused ? `Paused · ${waiting.length} new event${waiting.length === 1 ? "" : "s"} waiting`
        : `Live · polling every ${Math.round(CA.poll / 1000)} s`);
    } catch (err) {
      setLive("error", "Disconnected · retrying");
    } finally {
      polling = false;
    }
  }

  pauseBtn.addEventListener("click", () => {
    paused = !paused;
    pauseBtn.setAttribute("aria-pressed", String(paused));
    pauseBtn.innerHTML = paused ? `${CA.icon("play", "i-sm")}<span>Resume updates</span>` : `${CA.icon("pause", "i-sm")}<span>Pause updates</span>`;
    if (!paused) {
      prepend(waiting);
      if (waiting.length) CA.toast("info", "Live updates resumed", `${waiting.length} queued event(s) added to the stream.`, 2600);
      waiting = [];
      setLive("live", `Live · polling every ${Math.round(CA.poll / 1000)} s`);
    } else {
      setLive("paused", "Paused · 0 new events waiting");
    }
  });

  /* ---------- start ---------- */
  (async function start() {
    const ok = await Promise.all([loadStats({ toast: true }), initFeed(), net.refresh()]);
    if (CA.markDashboardReady) CA.markDashboardReady();
    await CA.introGate;
    if (ok[0]) renderStats();
    setInterval(pollFeed, CA.poll);
    setInterval(async () => { if (!document.hidden && await loadStats()) renderStats(); }, 30000);
  })();
})();
