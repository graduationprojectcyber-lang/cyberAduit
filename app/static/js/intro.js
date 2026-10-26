/* Cinematic start-up sequence. Each step waits for a real backend response;
   nothing is marked complete before the server has answered. */
(function () {
  "use strict";
  const CA = window.CA;
  let resolveGate;
  CA.introGate = new Promise((r) => (resolveGate = r));
  CA.dashboardReady = CA.dashboardReady || new Promise((r) => (CA.markDashboardReady = r));

  const root = document.getElementById("intro");
  const dash = document.getElementById("dash");
  if (!root || (dash && dash.dataset.intro !== "1")) {
    resolveGate();
    return;
  }

  const stepsEl = document.getElementById("introSteps");
  const bar = document.getElementById("introBar");
  const cta = document.getElementById("introCta");
  const wait = (ms) => new Promise((r) => setTimeout(r, CA.reduceMotion ? 0 : ms));
  const started = performance.now();
  let health = null, finished = false;

  const steps = [
    { label: "Initializing application", run: async () => {
      health = await CA.api("/api/health");
      return `v${health.application.version} · session verified`;
    } },
    { label: "Connecting to audit database", run: async () => {
      if (!health.database || !health.database.ok) throw new Error("database check failed");
      return `SQLite · ${CA.num(health.database.events)} records · ${health.database.latency_ms} ms`;
    } },
    { label: "Loading monitoring rules", run: async () => {
      const r = await CA.api("/api/rules");
      return `${r.items.filter((x) => x.enabled).length} of ${r.items.length} rules enabled`;
    } },
    { label: "Preparing security event stream", run: async () => {
      const e = await CA.api("/api/events?per_page=1");
      return e.items.length ? `latest ${e.items[0].uid}` : "stream ready · no events yet";
    } },
    { label: "Loading dashboard", run: async () => {
      await CA.dashboardReady;
      return `ready in ${((performance.now() - started) / 1000).toFixed(1)} s`;
    } },
  ];

  stepsEl.innerHTML = steps.map((s, i) => `<li data-i="${i}"><span class="st"><span class="idle"></span></span>
    <span class="lbl">${CA.esc(s.label)}</span><span class="det">waiting</span></li>`).join("");

  function close() {
    if (finished) return;
    finished = true;
    try { sessionStorage.setItem("ca_intro_seen", "1"); } catch (_) { /* storage blocked */ }
    root.classList.add("leaving");
    if (dash) dash.classList.remove("dash-hold");
    resolveGate();
    setTimeout(() => root.remove(), 750);
    const main = document.getElementById("main");
    if (main) main.focus({ preventScroll: true });
  }
  document.getElementById("introSkip").addEventListener("click", close);
  document.addEventListener("keydown", function onKey(e) {
    if (e.key === "Escape" && !finished) { close(); document.removeEventListener("keydown", onKey); }
  });

  (async function run() {
    await wait(2300); // let the emblem and title reveal finish
    let failed = false;
    for (let i = 0; i < steps.length && !finished; i++) {
      const li = stepsEl.children[i];
      li.className = "active";
      li.querySelector(".st").innerHTML = '<span class="spinner" style="width:16px;height:16px"></span>';
      li.querySelector(".det").textContent = "checking…";
      try {
        const [detail] = await Promise.all([steps[i].run(), wait(380)]);
        li.className = "done";
        li.querySelector(".st").innerHTML = `<span class="ok-icon">${CA.icon("check")}</span>`;
        li.querySelector(".det").textContent = detail;
      } catch (err) {
        failed = true;
        li.className = "fail";
        li.querySelector(".st").innerHTML = `<span class="bad-icon">${CA.icon("x")}</span>`;
        li.querySelector(".det").textContent = err.message || "failed";
        break;
      }
      bar.style.width = `${((i + 1) / steps.length) * 100}%`;
    }
    if (finished) return;
    if (failed) {
      bar.style.background = "var(--red)";
      cta.innerHTML = `<div class="error-box">The backend did not confirm every step. The dashboard will show what is actually available.</div>
        <button class="btn btn-lg" type="button" id="introContinue">Continue to dashboard</button>`;
      document.getElementById("introContinue").addEventListener("click", close);
      return;
    }
    cta.innerHTML = `<div class="tagline">Observe · Investigate · Understand</div>
      <button class="btn btn-primary btn-lg" type="button" id="introEnter">Enter monitoring center ${CA.icon("arrow-right", "i-sm")}</button>`;
    const enter = document.getElementById("introEnter");
    enter.addEventListener("click", close);
    enter.focus();
    await wait(2200);
    close();
  })();
})();
