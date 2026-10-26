/* Administrator user management. */
(function () {
  "use strict";
  const CA = window.CA, $ = CA.$;
  const rows = $("#userRows");
  let users = [], roles = {}, me = 0;

  function row(u) {
    const self = u.id === me;
    const roleSelect = `<select class="select" data-role="${u.id}" style="width:auto;height:32px" aria-label="Role for ${CA.esc(u.username)}" ${self ? "disabled title='You cannot change your own role'" : ""}>
      ${Object.entries(roles).map(([k, l]) => `<option value="${k}" ${k === u.role ? "selected" : ""}>${CA.esc(l)}</option>`).join("")}</select>`;
    return `<tr>
      <td><div style="display:flex;align-items:center;gap:10px"><span class="avatar" style="width:32px;height:32px">${CA.esc(u.username.slice(0, 2))}</span>
        <div><div class="strong" style="display:flex;align-items:center;gap:8px">${CA.esc(u.username)}${self ? ' <span class="dim">(you)</span>' : ""}<span class="role-badge ${u.role}">${CA.esc(u.role_label)}</span></div>
        <div class="dim" style="font-size:12px">${CA.esc(u.full_name)}</div></div></div></td>
      <td>${roleSelect}</td>
      <td>${u.is_active ? CA.pill("success", "Active") : CA.pill("", "Deactivated")}</td>
      <td class="mono">${CA.esc(CA.date(u.created_at))}</td>
      <td class="mono">${u.last_login_at ? CA.esc(CA.dateTime(u.last_login_at)) : '<span class="dim">never</span>'}</td>
      <td class="right"><div style="display:inline-flex;gap:6px">
        <button class="btn btn-sm btn-ghost" type="button" data-reset="${u.id}" ${self ? "disabled" : ""}>${CA.icon("key", "i-sm")}Reset password</button>
        <button class="btn btn-sm ${u.is_active ? "btn-danger" : ""}" type="button" data-toggle="${u.id}" ${self ? "disabled" : ""}>${u.is_active ? "Deactivate" : "Activate"}</button>
      </div></td></tr>`;
  }

  async function load() {
    try {
      const r = await CA.api("/api/users" + CA.query({ q: $("#userSearch").value.trim() }));
      users = r.items; roles = r.roles; me = r.current_user_id;
      rows.innerHTML = users.length ? users.map(row).join("") : `<tr><td colspan="6"><div class="empty">${CA.icon("users")}<b>No users match</b></div></td></tr>`;
    } catch (err) {
      rows.innerHTML = `<tr><td colspan="6"><div class="error-box">${CA.esc(err.message)}</div></td></tr>`;
    }
  }

  rows.addEventListener("change", async (e) => {
    const sel = e.target.closest("[data-role]");
    if (!sel) return;
    const u = users.find((x) => x.id === Number(sel.dataset.role));
    const ok = await CA.confirm({ title: "Change role?", message: `Change ${u.username} from ${roles[u.role]} to ${roles[sel.value]}? Role changes are sensitive: detection rule R-05 will raise an alert for review.`, confirmLabel: "Change role" });
    if (!ok) { sel.value = u.role; return; }
    try {
      await CA.api(`/api/users/${u.id}`, { method: "PATCH", body: { role: sel.value } });
      CA.toast("success", "Role updated", `${u.username} is now ${roles[sel.value]}. Recorded as user.role_change.`);
      load(); CA.refreshNotifications(); CA.refreshHealth();
    } catch (err) {
      sel.value = u.role;
      CA.toast("error", "Role not changed", err.message);
    }
  });

  rows.addEventListener("click", async (e) => {
    const t = e.target.closest("[data-toggle]");
    const rs = e.target.closest("[data-reset]");
    if (t) {
      const u = users.find((x) => x.id === Number(t.dataset.toggle));
      const activate = !u.is_active;
      const ok = await CA.confirm({ title: activate ? "Activate account?" : "Deactivate account?",
        message: activate ? `${u.username} will be able to sign in again.` : `${u.username} will be signed out and unable to sign in. Their audit history is kept.`,
        confirmLabel: activate ? "Activate" : "Deactivate", danger: !activate });
      if (!ok) return;
      try {
        await CA.api(`/api/users/${u.id}`, { method: "PATCH", body: { is_active: activate } });
        CA.toast("success", activate ? "Account activated" : "Account deactivated", `${u.username} · recorded in the audit trail.`);
        load();
      } catch (err) { CA.toast("error", "Change rejected", err.message); }
    }
    if (rs) {
      const u = users.find((x) => x.id === Number(rs.dataset.reset));
      const ok = await CA.confirm({ title: "Reset password?", message: `Generate a new temporary password for ${u.username}? The old password stops working immediately.`, confirmLabel: "Reset password", danger: true });
      if (!ok) return;
      try {
        const r = await CA.api(`/api/users/${u.id}/reset-password`, { method: "POST", body: {} });
        const layer = CA.openLayer("dialog", `<h2>Temporary password for ${CA.esc(u.username)}</h2>
          <p class="muted" style="margin:0;line-height:1.6">Shown once. It is stored only as a salted hash and is not written to the audit log.</p>
          <pre class="code" style="font-size:16px;text-align:center">${CA.esc(r.temporary_password)}</pre>
          <div class="actions"><button class="btn" type="button" data-copy>${CA.icon("copy", "i-sm")}Copy</button><button class="btn btn-primary" type="button" data-close>Done</button></div>`, { label: "Temporary password" });
        layer.panel.querySelector("[data-copy]").addEventListener("click", (ev) => CA.copy(r.temporary_password, ev.currentTarget));
        load();
      } catch (err) { CA.toast("error", "Password not reset", err.message); }
    }
  });

  $("#newUser").addEventListener("click", () => {
    const layer = CA.openLayer("dialog", `<h2>New user</h2>
      <form id="createForm" class="stack" style="gap:12px" novalidate>
        <label class="field">Username<input class="input" name="username" maxlength="32" autocomplete="off" autofocus placeholder="e.g. h.kadhim"></label>
        <label class="field">Full name<input class="input" name="full_name" maxlength="80" autocomplete="off"></label>
        <label class="field">Role<select class="select" name="role">${Object.entries(roles).map(([k, l]) => `<option value="${k}" ${k === "viewer" ? "selected" : ""}>${CA.esc(l)}</option>`).join("")}</select></label>
        <label class="field">Initial password (10+ characters, letters and digits)
          <span style="display:flex;gap:8px"><input class="input mono" name="password" maxlength="128" autocomplete="new-password"><button class="btn" type="button" data-gen>Generate</button></span></label>
        <div class="field-error hidden" id="createErr"></div>
        <div class="actions"><button class="btn btn-ghost" type="button" data-close>Cancel</button><button class="btn btn-primary" type="submit">Create user</button></div>
      </form>`, { label: "New user" });
    const f = layer.panel.querySelector("#createForm");
    f.querySelector("[data-gen]").addEventListener("click", () => {
      const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789";
      const arr = new Uint32Array(12); crypto.getRandomValues(arr);
      f.elements.password.value = Array.from(arr, (n) => chars[n % chars.length]).join("") + "7a";
    });
    f.addEventListener("submit", async (e) => {
      e.preventDefault();
      CA.$$(".field.invalid", f).forEach((x) => x.classList.remove("invalid"));
      const err = f.querySelector("#createErr");
      err.classList.add("hidden");
      const body = Object.fromEntries(["username", "full_name", "role", "password"].map((k) => [k, f.elements[k].value.trim()]));
      const btn = f.querySelector("[type=submit]");
      CA.busy(btn, true, "Creating…");
      try {
        const u = await CA.api("/api/users", { method: "POST", body });
        layer.close();
        CA.toast("success", "User created", `${u.username} (${u.role_label}) · recorded as user.create.`);
        load();
      } catch (ex) {
        CA.busy(btn, false);
        err.textContent = ex.message; err.classList.remove("hidden");
        if (ex.field && f.elements[ex.field]) f.elements[ex.field].closest(".field").classList.add("invalid");
      }
    });
  });

  $("#userSearch").addEventListener("input", CA.debounce(load, 300));
  load();
})();
