/* Lightweight SVG charts (no external library, works offline). */
(function () {
  "use strict";
  const CA = window.CA;
  const NS = "http://www.w3.org/2000/svg";
  const W = 720, H = 230, TOP = 14, BOTTOM = 218;
  const SERIES = [
    { key: "success", label: "Successful", color: "#27D8FF", width: 2 },
    { key: "failed", label: "Failed", color: "#F0506E", width: 2 },
    { key: "denied", label: "Denied", color: "#F5B547", width: 1.7, dash: "4 4" },
  ];
  CA.DIST_COLORS = {
    login: "#27D8FF", logout: "#1A93BF", file_modify: "#5B94FF", file_create: "#9B8CFF",
    file_delete: "#F0506E", user_management: "#F5B547", permission: "#FF9F6B", alert: "#6FD3B5", other: "#4A5A75",
  };

  function el(name, attrs) {
    const node = document.createElementNS(NS, name);
    Object.entries(attrs || {}).forEach(([k, v]) => node.setAttribute(k, v));
    return node;
  }
  function resample(values, n) {
    if (!values || !values.length) return new Array(n).fill(0);
    if (values.length === n) return values.slice();
    return Array.from({ length: n }, (_, i) => {
      const pos = (i / Math.max(1, n - 1)) * (values.length - 1);
      const a = Math.floor(pos), b = Math.min(values.length - 1, a + 1);
      return values[a] + (values[b] - values[a]) * (pos - a);
    });
  }

  CA.lineChart = function (container) {
    container.classList.add("chart");
    container.innerHTML = "";
    const svg = el("svg", { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: "none", role: "img", style: `height:${H}px` });
    const defs = el("defs");
    const grad = el("linearGradient", { id: "caArea", x1: 0, y1: 0, x2: 0, y2: 1 });
    grad.append(el("stop", { offset: 0, "stop-color": "#27D8FF", "stop-opacity": .22 }), el("stop", { offset: 1, "stop-color": "#27D8FF", "stop-opacity": 0 }));
    defs.append(grad);
    svg.append(defs);
    for (let i = 0; i < 5; i++) {
      const y = TOP + ((BOTTOM - TOP) / 4) * i;
      svg.append(el("line", { x1: 0, x2: W, y1: y, y2: y, stroke: i === 4 ? "#1C2A42" : "#142037", "vector-effect": "non-scaling-stroke" }));
    }
    const area = el("path", { fill: "url(#caArea)" });
    svg.append(area);
    const paths = SERIES.map((s) => {
      const p = el("path", { fill: "none", stroke: s.color, "stroke-width": s.width, "stroke-linejoin": "round", "vector-effect": "non-scaling-stroke" });
      if (s.dash) p.setAttribute("stroke-dasharray", s.dash);
      svg.append(p);
      return p;
    });
    const cursor = el("line", { y1: TOP, y2: BOTTOM, stroke: "#3A5276", "stroke-width": 1, "vector-effect": "non-scaling-stroke", opacity: 0 });
    svg.append(cursor);
    container.append(svg);
    const dots = SERIES.map((s) => {
      const dot = document.createElement("span");
      dot.style.cssText = `position:absolute;width:9px;height:9px;border-radius:50%;background:${s.color};box-shadow:0 0 0 3px #0A1222;transform:translate(-50%,-50%);pointer-events:none;opacity:0;transition:opacity .15s`;
      container.append(dot);
      return dot;
    });
    const tip = document.createElement("div");
    tip.className = "tip hidden";
    container.append(tip);
    const empty = document.createElement("div");
    empty.className = "empty hidden";
    empty.style.cssText = "position:absolute;inset:0;";
    empty.innerHTML = "<b>No events in this period</b><span>Run a scenario in the Event Simulator to generate activity.</span>";
    container.append(empty);
    container.tabIndex = 0;

    let state = { buckets: [], unit: "hour", values: { success: [], failed: [], denied: [] }, max: 1 };
    let shown = { success: [], failed: [], denied: [] };
    let raf = null, hover = -1;

    const xAt = (i, n) => (n <= 1 ? W / 2 : (i * W) / (n - 1));
    const yAt = (v, max) => BOTTOM - (v / max) * (BOTTOM - TOP);
    const pathFor = (vals, max) => vals.map((v, i) => `${i ? "L" : "M"}${xAt(i, vals.length).toFixed(1)},${yAt(v, max).toFixed(1)}`).join(" ");

    function draw(vals, max) {
      SERIES.forEach((s, i) => paths[i].setAttribute("d", pathFor(vals[s.key], max)));
      const s = vals.success;
      area.setAttribute("d", s.length ? `${pathFor(s, max)} L${W},${BOTTOM} L0,${BOTTOM} Z` : "");
    }
    function label(i) {
      const b = state.buckets[i];
      if (!b) return "";
      const start = new Date(b.start);
      if (state.unit === "hour") {
        const end = new Date(start.getTime() + 3600000);
        const f = (d) => d.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" });
        return `${start.toLocaleDateString("en-GB", { day: "2-digit", month: "short" })} ${f(start)}–${f(end)}`;
      }
      return start.toLocaleDateString("en-GB", { weekday: "short", day: "2-digit", month: "short" });
    }
    function showHover(i) {
      const n = state.buckets.length;
      if (i < 0 || i >= n) { hover = -1; tip.classList.add("hidden"); cursor.setAttribute("opacity", 0); dots.forEach((d) => (d.style.opacity = 0)); return; }
      hover = i;
      const x = xAt(i, n);
      cursor.setAttribute("x1", x); cursor.setAttribute("x2", x); cursor.setAttribute("opacity", 1);
      const rect = svg.getBoundingClientRect();
      const px = (x / W) * rect.width;
      SERIES.forEach((s, k) => {
        dots[k].style.left = px + "px";
        dots[k].style.top = (yAt(state.values[s.key][i], state.max) / H) * rect.height + "px";
        dots[k].style.opacity = 1;
      });
      const b = state.buckets[i];
      tip.innerHTML = `<div class="when">${CA.esc(label(i))}</div>` + SERIES.map((s) =>
        `<div><span style="color:${s.color}">●</span> ${s.label} <b class="num">${CA.num(b[s.key])}</b></div>`).join("");
      tip.classList.remove("hidden");
      tip.style.left = Math.min(rect.width - 90, Math.max(90, px)) + "px";
    }
    svg.addEventListener("mousemove", (e) => {
      const rect = svg.getBoundingClientRect();
      const n = state.buckets.length;
      if (!n) return;
      showHover(Math.round(((e.clientX - rect.left) / rect.width) * (n - 1)));
    });
    svg.addEventListener("mouseleave", () => showHover(-1));
    container.addEventListener("keydown", (e) => {
      const n = state.buckets.length;
      if (!n) return;
      if (e.key === "ArrowRight") { e.preventDefault(); showHover(Math.min(n - 1, hover + 1)); }
      if (e.key === "ArrowLeft") { e.preventDefault(); showHover(Math.max(0, hover < 0 ? n - 1 : hover - 1)); }
      if (e.key === "Escape") showHover(-1);
    });
    container.addEventListener("blur", () => showHover(-1));

    return {
      update(buckets, unit) {
        const n = buckets.length;
        const target = {};
        SERIES.forEach((s) => (target[s.key] = buckets.map((b) => b[s.key])));
        const max = Math.max(4, ...SERIES.flatMap((s) => target[s.key])) * 1.12;
        const from = {};
        SERIES.forEach((s) => (from[s.key] = resample(shown[s.key].length ? shown[s.key] : new Array(n).fill(0), n)));
        const fromMax = state.max || max;
        state = { buckets, unit, values: target, max };
        const total = buckets.reduce((a, b) => a + b.success + b.failed + b.denied, 0);
        empty.classList.toggle("hidden", total > 0);
        svg.setAttribute("aria-label", `Event volume, ${n} ${unit === "hour" ? "hourly" : "daily"} buckets: ` +
          SERIES.map((s) => `${s.label.toLowerCase()} ${target[s.key].reduce((a, b) => a + b, 0)}`).join(", "));
        showHover(-1);
        cancelAnimationFrame(raf);
        if (CA.reduceMotion) { shown = target; draw(target, max); return; }
        const t0 = performance.now(), dur = 650;
        const step = (now) => {
          const p = Math.min(1, (now - t0) / dur), e = 1 - Math.pow(1 - p, 3);
          const cur = {};
          SERIES.forEach((s) => (cur[s.key] = target[s.key].map((v, i) => from[s.key][i] + (v - from[s.key][i]) * e)));
          shown = cur;
          draw(cur, fromMax + (max - fromMax) * e);
          if (p < 1) raf = requestAnimationFrame(step);
        };
        raf = requestAnimationFrame(step);
      },
      axisLabels(count = 5) {
        const n = state.buckets.length;
        if (!n) return [];
        return Array.from({ length: count }, (_, k) => {
          const i = Math.round((k / (count - 1)) * (n - 1));
          const d = new Date(state.buckets[i].start);
          if (k === count - 1) return "Now";
          return state.unit === "hour" ? d.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" })
            : d.toLocaleDateString("en-GB", { day: "2-digit", month: "short" });
        });
      },
    };
  };

  CA.donut = function (container, listEl) {
    const R = 70, C = 2 * Math.PI * R;
    container.innerHTML = `<svg width="168" height="168" viewBox="0 0 180 180" role="img" aria-label="Event distribution">
      <circle cx="90" cy="90" r="${R}" fill="none" stroke="#111C30" stroke-width="16"></circle><g class="segs" transform="rotate(-90 90 90)"></g></svg>
      <div class="center"><b class="num">0</b><span>events</span></div>`;
    const g = container.querySelector(".segs");
    const centerN = container.querySelector(".center b"), centerL = container.querySelector(".center span");
    let items = [], total = 0;
    function highlight(key) {
      CA.$$("circle.seg", g).forEach((c) => (c.style.opacity = !key || c.dataset.key === key ? 1 : .28));
      CA.$$("li", listEl).forEach((li) => li.classList.toggle("hl", li.dataset.key === key));
      const it = items.find((i) => i.key === key);
      centerN.textContent = CA.num(it ? it.count : total);
      centerL.textContent = it ? it.label : "events";
    }
    return {
      update(data) {
        items = data.filter((d) => d.count > 0);
        total = items.reduce((a, b) => a + b.count, 0);
        g.innerHTML = "";
        let acc = 0;
        const segs = items.map((it) => {
          const c = el("circle", { class: "seg", cx: 90, cy: 90, r: R, fill: "none", stroke: CA.DIST_COLORS[it.key] || "#4A5A75", "stroke-width": 16,
            "stroke-dasharray": `0 ${C}`, "stroke-dashoffset": 0 });
          c.dataset.key = it.key;
          const len = total ? (it.count / total) * C : 0;
          c.dataset.len = Math.max(0, len - (items.length > 1 ? 2.5 : 0));
          c.dataset.off = -acc;
          acc += len;
          c.addEventListener("mouseenter", () => highlight(it.key));
          c.addEventListener("mouseleave", () => highlight(null));
          g.append(c);
          return c;
        });
        requestAnimationFrame(() => requestAnimationFrame(() => segs.forEach((c) => {
          c.setAttribute("stroke-dasharray", `${c.dataset.len} ${C}`);
          c.setAttribute("stroke-dashoffset", c.dataset.off);
        })));
        centerN.dataset.value = centerN.dataset.value || 0;
        CA.countUp(centerN, total);
        centerL.textContent = "events";
        listEl.innerHTML = data.map((it) => `<li data-key="${CA.esc(it.key)}" tabindex="0">
          <span class="sw" style="background:${CA.DIST_COLORS[it.key] || "#4A5A75"}"></span>
          <span class="lbl">${CA.esc(it.label)}</span><span class="n">${CA.num(it.count)}</span>
          <span class="p">${total ? ((it.count / total) * 100).toFixed(1) : "0.0"}%</span></li>`).join("");
        CA.$$("li", listEl).forEach((li) => {
          li.addEventListener("mouseenter", () => highlight(li.dataset.key));
          li.addEventListener("mouseleave", () => highlight(null));
          li.addEventListener("focus", () => highlight(li.dataset.key));
          li.addEventListener("blur", () => highlight(null));
        });
      },
    };
  };
})();
