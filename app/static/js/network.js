/* Interactive SVG relationship graph: source IP → protected app → account.
   Built only from /api/network, which aggregates real audit records. */
(function () {
  "use strict";
  const CA = window.CA;

  CA.network = function (canvas, detail, chips) {
    let data = null, selected = null, lastSeenId = 0;

    const nodeKey = (kind, id) => `${kind}:${id}`;

    function layout() {
      const ips = data.ips, accounts = data.accounts;
      const rows = Math.max(ips.length, accounts.length, 3);
      const H = Math.max(300, 70 + rows * 64);
      const place = (list, x) => list.map((n, i) => ({ ...n, x, y: 60 + ((H - 90) / Math.max(1, list.length)) * (i + .5) }));
      return { H, ips: place(ips, 92), accounts: place(accounts, 560), app: { ...data.app, x: 330, y: 30 + (H - 30) / 2 } };
    }

    function edgesFor(L) {
      const edges = [];
      L.ips.forEach((ip) => edges.push({ id: `e-ip-${ip.id}`, from: nodeKey("ip", ip.id), to: "app",
        d: `M${ip.x + 15},${ip.y} C${ip.x + 120},${ip.y} ${L.app.x - 110},${L.app.y} ${L.app.x - 34},${L.app.y}`, suspicious: ip.suspicious }));
      L.accounts.forEach((a) => edges.push({ id: `e-acc-${a.id}`, from: "app", to: nodeKey("account", a.id),
        d: `M${L.app.x + 34},${L.app.y} C${L.app.x + 110},${L.app.y} ${a.x - 100},${a.y} ${a.x - 13},${a.y}`, suspicious: a.suspicious }));
      return edges;
    }

    function activeEdges(L) {
      if (!selected) return new Set();
      if (selected === "app") return new Set(edgesFor(L).map((e) => e.id));
      const [kind, id] = [selected.slice(0, selected.indexOf(":")), selected.slice(selected.indexOf(":") + 1)];
      const set = new Set();
      if (kind === "ip") {
        set.add(`e-ip-${id}`);
        const ip = L.ips.find((n) => n.id === id);
        (ip ? ip.accounts : []).forEach((a) => set.add(`e-acc-${a}`));
      } else {
        set.add(`e-acc-${id}`);
        const acc = L.accounts.find((n) => n.id === id);
        (acc ? acc.ips : []).forEach((ip) => set.add(`e-ip-${ip}`));
      }
      return set;
    }

    function selectedNode(L) {
      if (selected === "app") return { kind: "app", ...L.app };
      const [kind, id] = [selected.slice(0, selected.indexOf(":")), selected.slice(selected.indexOf(":") + 1)];
      return (kind === "ip" ? L.ips : L.accounts).find((n) => n.id === id);
    }

    function render(flash) {
      if (!data) return;
      if (!data.ips.length) {
        canvas.innerHTML = `<div class="empty" style="min-height:300px">${CA.icon("network")}<b>No network activity in the last ${data.hours} hours</b><span>Run a scenario in the Event Simulator to populate the graph.</span></div>`;
        detail.innerHTML = '<div class="note-text">Nothing to inspect yet.</div>';
        chips.innerHTML = "";
        return;
      }
      const L = layout();
      if (!selected || (selected !== "app" && !selectedNode(L))) {
        const sus = L.ips.find((n) => n.suspicious);
        selected = sus ? nodeKey("ip", sus.id) : "app";
      }
      const active = activeEdges(L);
      const selNode = selectedNode(L);
      const redPath = selNode && selNode.suspicious;
      const edges = edgesFor(L);
      let svg = `<svg viewBox="0 0 660 ${L.H}" role="img" aria-label="Network graph of ${L.ips.length} source IPs and ${L.accounts.length} accounts connected through the protected application">
        <text x="92" y="24" text-anchor="middle" fill="#8494AE" font-size="10" letter-spacing="1.4" font-family="Segoe UI, sans-serif">SOURCE IP</text>
        <text x="330" y="24" text-anchor="middle" fill="#8494AE" font-size="10" letter-spacing="1.4" font-family="Segoe UI, sans-serif">PROTECTED APPLICATION</text>
        <text x="575" y="24" text-anchor="middle" fill="#8494AE" font-size="10" letter-spacing="1.4" font-family="Segoe UI, sans-serif">ACCOUNTS</text>`;
      edges.forEach((e) => { svg += `<path class="net-edge" d="${e.d}"></path>`; });
      edges.forEach((e) => {
        const on = active.has(e.id);
        const color = on && (redPath || e.suspicious) && selected !== "app" ? "#F0506E" : e.suspicious && selected === "app" ? "#F0506E" : "#27D8FF";
        svg += `<path class="net-flow ${on ? "on" : ""}" d="${e.d}" stroke="${color}"></path>`;
      });
      const isSel = (k) => k === selected;
      L.ips.forEach((n) => {
        const k = nodeKey("ip", n.id), c = n.suspicious ? "#F0506E" : "#6F8BB5";
        const fresh = flash && n.last_id > flash;
        svg += `<g class="net-node" tabindex="0" role="button" data-key="${CA.esc(k)}" aria-label="Source IP ${CA.esc(n.id)}, ${n.events} events${n.suspicious ? ", under investigation" : ""}">
          ${n.suspicious ? `<circle class="net-pulse" cx="${n.x}" cy="${n.y}" r="14" fill="none" stroke="#F0506E" stroke-width="1.5"></circle>` : ""}
          ${fresh ? `<circle class="net-burst" cx="${n.x}" cy="${n.y}" r="14" fill="none" stroke="#27D8FF" stroke-width="2"></circle>` : ""}
          <circle class="ring" cx="${n.x}" cy="${n.y}" r="14" fill="${n.suspicious ? "#1C0F1C" : "#0C1729"}" stroke="${isSel(k) ? "#27D8FF" : c}" stroke-width="${isSel(k) ? 2.6 : 1.5}"></circle>
          <circle cx="${n.x}" cy="${n.y}" r="4" fill="${c}"></circle>
          <text x="${n.x}" y="${n.y + 31}" text-anchor="middle" ${n.suspicious ? 'style="fill:#FF9DB0"' : ""}>${CA.esc(n.id)}</text></g>`;
      });
      const app = L.app, appSel = isSel("app");
      svg += `<g class="net-node" tabindex="0" role="button" data-key="app" aria-label="Protected application, ${app.events} events">
        <circle cx="${app.x}" cy="${app.y}" r="46" fill="none" stroke="#27D8FF" stroke-opacity=".12"></circle>
        <circle class="ring" cx="${app.x}" cy="${app.y}" r="32" fill="#0B1C2E" stroke="#27D8FF" stroke-width="${appSel ? 2.6 : 1.5}"></circle>
        <path d="M${app.x} ${app.y - 16} ${app.x + 11} ${app.y - 12}v7.5c0 6.5-4.6 11-11 13.2-6.4-2.2-11-6.7-11-13.2V${app.y - 12}z" fill="none" stroke="#27D8FF" stroke-width="1.6" stroke-linejoin="round"></path>
        <text x="${app.x}" y="${app.y + 52}" text-anchor="middle" style="fill:#E8EEF7;font-family:Segoe UI,sans-serif;font-weight:600;font-size:12px">CyberAudit app</text>
        <text x="${app.x}" y="${app.y + 67}" text-anchor="middle" style="fill:#8494AE;font-size:10.5px">${CA.num(app.events)} events / ${data.hours} h</text></g>`;
      L.accounts.forEach((n) => {
        const k = nodeKey("account", n.id), c = n.suspicious ? "#F0506E" : "#4B6489";
        const fresh = flash && n.last_id > flash;
        svg += `<g class="net-node" tabindex="0" role="button" data-key="${CA.esc(k)}" aria-label="Account ${CA.esc(n.id)}, ${n.events} events${n.suspicious ? ", under investigation" : ""}">
          ${fresh ? `<rect class="net-burst" x="${n.x - 11}" y="${n.y - 11}" width="22" height="22" rx="6" fill="none" stroke="#27D8FF" stroke-width="2"></rect>` : ""}
          <rect class="ring" x="${n.x - 11}" y="${n.y - 11}" width="22" height="22" rx="6" fill="#0C1729" stroke="${isSel(k) ? "#27D8FF" : c}" stroke-width="${isSel(k) ? 2.6 : 1.5}"></rect>
          <text x="${n.x + 20}" y="${n.y + 4}">${CA.esc(n.id)}</text></g>`;
      });
      svg += "</svg>";
      canvas.innerHTML = svg;
      CA.$$(".net-node", canvas).forEach((g) => {
        const pick = () => { selected = g.dataset.key; render(); const again = CA.$(`.net-node[data-key="${CSS.escape(selected)}"]`, canvas); if (again) again.focus(); };
        g.addEventListener("click", pick);
        g.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); pick(); } });
      });

      const n = selNode;
      const kindLabel = selected === "app" ? "Protected system" : selected.startsWith("ip:") ? "Source IP · simulated label" : "Account";
      const rows = selected === "app"
        ? [["Events (24 h)", CA.num(app.events)], ["Source IPs shown", L.ips.length], ["Accounts shown", L.accounts.length], ["Open alerts", data.open_alerts]]
        : [["Events (24 h)", CA.num(n.events)], ["Successful", CA.num(n.success)], ["Failed", CA.num(n.failed)], ["Denied", CA.num(n.denied)],
           [selected.startsWith("ip:") ? "Accounts" : "Source IPs", (selected.startsWith("ip:") ? n.accounts : n.ips).join(", ") || "—"],
           ["Last activity", CA.ago(n.last_ts)]];
      const filter = selected === "app" ? "" : selected.startsWith("ip:") ? `?ip=${encodeURIComponent(n.id)}` : `?actor=${encodeURIComponent(n.id)}`;
      const note = selected === "app"
        ? "Every audited request terminates at the application. Each edge is derived from recorded events in the last 24 hours."
        : n.suspicious ? "Linked to an unresolved alert or a high failure ratio. Suspicious activity requires investigation."
        : "No unresolved alert is linked to this node.";
      detail.innerHTML = `
        <div style="display:flex;align-items:center;justify-content:space-between;gap:8px">
          <span class="section-label">${kindLabel}</span>
          ${n && n.suspicious ? '<span class="pill high">Needs investigation</span>' : ""}
        </div>
        <div class="mono" style="font-size:17px;font-weight:500;color:var(--text-strong);overflow-wrap:anywhere">${CA.esc(selected === "app" ? "CyberAudit app" : n.id)}</div>
        <dl class="kv" style="grid-template-columns:auto 1fr">${rows.map(([k, v]) => `<dt>${CA.esc(k)}</dt><dd class="num" style="text-align:right">${CA.esc(v)}</dd>`).join("")}</dl>
        <p class="note-text" style="margin:0;color:var(--text-3)">${CA.esc(note)}</p>
        <a href="/logs${filter}" style="margin-top:auto;font-size:12.5px;font-weight:500">View matching audit events →</a>`;

      const all = [{ key: "app", label: "CyberAudit app", sus: false }]
        .concat(L.ips.map((i) => ({ key: nodeKey("ip", i.id), label: i.id, sus: i.suspicious })))
        .concat(L.accounts.map((a) => ({ key: nodeKey("account", a.id), label: a.id, sus: a.suspicious })));
      chips.innerHTML = all.map((c) => `<button type="button" data-key="${CA.esc(c.key)}" aria-pressed="${c.key === selected}" class="${c.sus ? "sus" : ""}">${CA.esc(c.label)}</button>`).join("");
      CA.$$("button", chips).forEach((b) => b.addEventListener("click", () => { selected = b.dataset.key; render(); }));
    }

    return {
      async refresh() {
        try {
          const fresh = await CA.api("/api/network?hours=24");
          const previous = lastSeenId;
          data = fresh;
          const newest = Math.max(0, ...fresh.ips.map((i) => i.last_id));
          render(previous && newest > previous ? previous : 0);
          lastSeenId = Math.max(lastSeenId, newest);
        } catch (err) {
          canvas.innerHTML = `<div class="error-box" style="margin:16px">Network data unavailable: ${CA.esc(err.message)}</div>`;
        }
      },
    };
  };
})();
