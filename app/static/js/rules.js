/* Detection rule overview and administrator-only settings. */
(function () {
  "use strict";
  const CA = window.CA, $ = CA.$;
  const rows = $("#ruleRows");
  let canEdit = false;

  function row(r) {
    const dis = canEdit ? "" : "disabled";
    return `<tr data-rule="${CA.esc(r.id)}">
      <td style="min-width:280px"><div style="display:flex;gap:8px;align-items:baseline"><span class="mono dim">${CA.esc(r.id)}</span><b style="font-weight:600">${CA.esc(r.name)}</b></div>
        <div class="muted" style="font-size:11.5px;margin-top:3px;line-height:1.45">${CA.esc(r.description)}</div></td>
      <td><button type="button" class="switch" role="switch" aria-checked="${r.enabled}" aria-label="Enable ${CA.esc(r.name)}" data-field="enabled" ${dis}></button></td>
      <td><input class="input num" style="width:84px" type="number" min="1" max="100" value="${r.threshold}" data-field="threshold" aria-label="${CA.esc(r.id)} threshold" ${dis || (r.id === "R-05" ? "disabled title='R-05 always alerts on a single change'" : "")}>
        <div class="dim" style="font-size:11px;margin-top:3px">${CA.esc(r.unit)}</div></td>
      <td><input class="input num" style="width:92px" type="number" min="1" max="1440" value="${r.window_minutes}" data-field="window_minutes" aria-label="${CA.esc(r.id)} window in minutes" ${dis}></td>
      <td class="right num">${CA.num(r.matches_24h)}</td>
      <td class="right num">${r.alerts_total} <span class="dim">(${r.alerts_unresolved})</span></td>
      <td class="mono">${r.last_triggered ? `${CA.esc(CA.dateTime(r.last_triggered))}<div class="dim" style="font-size:11px">${CA.esc(CA.ago(r.last_triggered))}</div>` : '<span class="dim">never</span>'}</td>
      <td class="right">${canEdit ? `<button class="btn btn-sm" type="button" data-save>Save</button>` : `<a class="link-btn" href="/alerts?rule=${CA.esc(r.id)}">Alerts →</a>`}</td></tr>`;
  }

  async function load() {
    try {
      const r = await CA.api("/api/rules");
      canEdit = r.can_edit;
      $("#ruleSub").textContent = `${r.items.filter((x) => x.enabled).length} of ${r.items.length} enabled` + (canEdit ? " · you can change settings" : " · read-only for your role");
      rows.innerHTML = r.items.map(row).join("");
    } catch (err) {
      rows.innerHTML = `<tr><td colspan="8"><div class="error-box">${CA.esc(err.message)}</div></td></tr>`;
    }
  }

  rows.addEventListener("click", async (e) => {
    const sw = e.target.closest(".switch");
    if (sw && !sw.disabled) sw.setAttribute("aria-checked", String(sw.getAttribute("aria-checked") !== "true"));
    const save = e.target.closest("[data-save]");
    if (!save) return;
    const tr = save.closest("tr");
    const id = tr.dataset.rule;
    const body = { enabled: tr.querySelector("[data-field=enabled]").getAttribute("aria-checked") === "true" };
    const th = tr.querySelector("[data-field=threshold]");
    if (!th.disabled) body.threshold = Number(th.value);
    body.window_minutes = Number(tr.querySelector("[data-field=window_minutes]").value);
    CA.$$(".input", tr).forEach((i) => i.style.borderColor = "");
    CA.busy(save, true, "Saving…");
    try {
      await CA.api(`/api/rules/${id}`, { method: "PUT", body });
      CA.toast("success", `${id} updated`, "The change was validated by the server and recorded as a rule.update audit event.");
      await load();
      CA.refreshHealth();
    } catch (err) {
      CA.busy(save, false);
      const bad = err.field && tr.querySelector(`[data-field=${err.field}]`);
      if (bad) bad.style.borderColor = "var(--red)";
      CA.toast("error", "Rule not saved", err.message);
    }
  });
  load();
})();
