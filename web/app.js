"use strict";

// ---------- helpers ----------

const $ = (sel, root = document) => root.querySelector(sel);
let csrf = "";
let me = null;

// h builds DOM nodes; text always goes through textContent, never innerHTML.
function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.className = v;
    else if (k === "style") el.style.cssText = v; // CSSOM, allowed by the CSP

    else if (k === "dataset") Object.assign(el.dataset, v);
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (v === true) el.setAttribute(k, "");
    else el.setAttribute(k, v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

class ApiError extends Error {
  constructor(msg, status, output) { super(msg); this.status = status; this.output = output; }
}

async function api(method, path, body) {
  const opts = { method, headers: {}, credentials: "same-origin" };
  if (method !== "GET") opts.headers["X-CSRF-Token"] = csrf;
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  let data = null;
  try { data = await res.json(); } catch { /* empty body */ }
  if (res.status === 401 && path !== "/api/login") {
    showLogin();
    throw new ApiError("session expired", 401);
  }
  if (!res.ok) {
    const out = data?.output?.length ? "\n" + data.output.join("\n") : "";
    throw new ApiError((data?.error || res.statusText) + out, res.status, data?.output);
  }
  return data;
}

function toast(msg, isError = false) {
  const t = h("div", { class: "toast" + (isError ? " error" : "") }, msg);
  $("#toasts").append(t);
  setTimeout(() => t.remove(), isError ? 9000 : 4500);
}

function outputToast(res, fallback = "Done") {
  const lines = res?.output?.filter(Boolean) || [];
  toast(lines.length ? lines.join("\n") : fallback);
}

async function guard(fn) {
  try { return await fn(); }
  catch (e) { if (e.status !== 401) toast(e.message, true); }
}

function bytes(n) {
  if (!n && n !== 0) return "—";
  const u = ["B", "KiB", "MiB", "GiB", "TiB"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i ? n.toFixed(1) : n) + " " + u[i];
}

function when(s) {
  if (!s) return "—";
  const d = new Date(s);
  if (isNaN(d)) return s;
  return d.toLocaleString(undefined, { dateStyle: "short", timeStyle: "short" });
}

function ago(s) {
  if (!s) return "—";
  const sec = (Date.now() - new Date(s)) / 1000;
  if (isNaN(sec)) return s;
  if (sec < 90) return Math.round(sec) + " s ago";
  if (sec < 5400) return Math.round(sec / 60) + " min ago";
  if (sec < 172800) return Math.round(sec / 3600) + " h ago";
  return Math.round(sec / 86400) + " days ago";
}

function badge(text, kind = "") { return h("span", { class: "badge " + kind }, text); }

function card(label, value, sub) {
  return h("div", { class: "card" }, h("div", { class: "label" }, label), h("div", { class: "value" }, value), sub ? h("div", { class: "sub" }, sub) : null);
}

// ---------- modal forms ----------

const modal = $("#modal");

// openForm shows a dialog built from field specs and calls onSubmit with the
// values; the dialog stays open (showing the error) if onSubmit throws.
function openForm({ title, fields = [], ok = "Save", danger = false, intro, onSubmit }) {
  $("#modal-title").textContent = title;
  const body = $("#modal-body");
  body.replaceChildren();
  if (intro) body.append(h("p", { class: "muted", style: "margin:0" }, intro));
  const inputs = {};
  for (const f of fields) body.append(fieldEl(f, inputs));
  const okBtn = $("#modal-ok");
  okBtn.textContent = ok;
  okBtn.className = "btn " + (danger ? "danger" : "primary");
  const err = $("#modal-error");
  err.hidden = true;

  const form = $("#modal-form");
  const submit = async (ev) => {
    if (ev.submitter?.value === "cancel") return;
    ev.preventDefault();
    if (!form.reportValidity()) return;
    const values = {};
    for (const [name, el] of Object.entries(inputs)) {
      if (el.type === "checkbox") values[name] = el.checked;
      else if (el.type === "number") values[name] = el.value === "" ? null : Number(el.value);
      else values[name] = el.value;
    }
    okBtn.disabled = true;
    try {
      await onSubmit(values);
      modal.close();
    } catch (e) {
      err.textContent = e.message;
      err.hidden = false;
    } finally {
      okBtn.disabled = false;
    }
  };
  form.onsubmit = submit;
  modal.showModal();
  const first = body.querySelector("input:not([type=checkbox]), textarea, select");
  if (first) first.focus();
}

function fieldEl(f, inputs) {
  let input;
  if (f.type === "select") {
    input = h("select", { name: f.name }, f.options.map(o => {
      const [v, l] = Array.isArray(o) ? o : [o, o];
      return h("option", { value: v, selected: String(v) === String(f.value) }, l);
    }));
  } else if (f.type === "textarea") {
    input = h("textarea", { name: f.name, rows: f.rows || 4, placeholder: f.placeholder, class: f.mono ? "code" : null, style: f.mono ? "min-height:0" : null });
    input.value = f.value ?? "";
  } else {
    input = h("input", {
      name: f.name, type: f.type || "text", placeholder: f.placeholder, required: f.required,
      min: f.min, autocomplete: f.type === "password" ? "new-password" : "off", pattern: f.pattern,
    });
    if (f.type === "checkbox") input.checked = !!f.value;
    else input.value = f.value ?? "";
  }
  inputs[f.name] = input;
  if (f.type === "checkbox") return h("label", { class: "check" }, input, f.label);
  return h("label", {}, f.label, input, f.hint ? h("span", { class: "hint" }, f.hint) : null);
}

function confirmAction(title, text, ok, fn) {
  openForm({ title, intro: text, ok, danger: true, onSubmit: fn });
}

// ---------- jobs ----------

async function runJob(promise, onDone) {
  let job;
  try { job = await promise; } catch (e) { if (e.status !== 401) toast(e.message, true); return; }
  const dlg = $("#job-modal");
  $("#job-title").textContent = job.kind;
  const log = $("#job-log");
  const status = $("#job-status");
  log.textContent = "";
  dlg.showModal();
  for (;;) {
    let j;
    try { j = await api("GET", "/api/jobs/" + job.id); } catch { await sleep(2000); continue; }
    log.textContent = j.log.join("\n");
    log.scrollTop = log.scrollHeight;
    status.textContent = { running: "running", done: "done", failed: "failed" }[j.status];
    status.className = "badge " + { running: "warn", done: "ok", failed: "bad" }[j.status];
    if (j.status !== "running") break;
    await sleep(1000);
  }
  onDone?.();
}

$("#job-close").addEventListener("click", () => $("#job-modal").close());
const sleep = ms => new Promise(r => setTimeout(r, ms));

// ---------- views ----------

const views = {};
let current = "";

function route() {
  const name = (location.hash || "#overview").slice(1);
  if (!views[name]) { location.hash = "#overview"; return; }
  current = name;
  document.querySelectorAll(".view").forEach(v => v.hidden = v.id !== "view-" + name);
  document.querySelectorAll("#nav a").forEach(a => a.classList.toggle("active", a.dataset.view === name));
  if (name !== "logs") stopFollow();
  guard(() => views[name]());
}
window.addEventListener("hashchange", route);

function refresh() { if (current) guard(() => views[current]()); }

// --- overview

views.overview = async () => {
  const [o, jobs] = await Promise.all([api("GET", "/api/overview"), api("GET", "/api/jobs")]);
  const cards = [];
  if (o.socket_error) cards.push(card("Admin socket", "unreachable", o.socket_error));
  else cards.push(card("soju", "running", o.server_status));
  if (o.process) cards.push(card("Process", "pid " + o.process.pid, `RSS ${bytes(o.process.rss_bytes)} · ${o.process.threads} threads · started ${ago(o.process.started)}`));
  else cards.push(card("Process", "—", o.process_error));
  if (o.pod) {
    const soju = o.pod.containers.find(c => c.name === "soju") || {};
    cards.push(card("Pod", o.pod.phase, `${o.pod.name} on ${o.pod.node}`));
    cards.push(card("Container restarts", String(soju.restart_count ?? "—"), soju.last_exit ? "last: " + soju.last_exit : (soju.image || "")));
  } else if (o.pod_error) cards.push(card("Pod", "—", o.pod_error));
  cards.push(card("soju.db", bytes(o.db_size)));
  cards.push(card("Volume /data", bytes(o.volume_free) + " free", "of " + bytes(o.volume_total)));
  $("#overview-cards").replaceChildren(...cards);

  const list = $("#jobs-list");
  if (!jobs.length) { list.replaceChildren("None since the panel started."); return; }
  list.replaceChildren(h("table", {},
    h("tr", {}, h("th", {}, "#"), h("th", {}, "Operation"), h("th", {}, "User"), h("th", {}, "Started"), h("th", {}, "State")),
    jobs.map(j => h("tr", {},
      h("td", {}, j.id), h("td", {}, j.kind), h("td", {}, j.user), h("td", {}, when(j.started)),
      h("td", {}, badge(j.status, { done: "ok", failed: "bad", running: "warn" }[j.status]), j.error ? " " + j.error : "")))));
};

// --- users

let selectedUser = null;
let usersCache = [];

views.users = async () => {
  const res = await api("GET", "/api/users");
  usersCache = res.users;
  if (res.status_error) toast("Could not fetch live status: " + res.status_error, true);
  if (res.upstream_error) toast("Could not read upstream-user-ip: " + res.upstream_error, true);
  const ul = $("#user-list");
  ul.replaceChildren(...usersCache.map(u => h("li", {
    class: u.username === selectedUser ? "active" : "",
    dataset: { user: u.username },
    onclick: () => { selectedUser = u.username; views.users(); },
  },
  h("span", {}, h("span", { class: "muted small" }, "#" + u.id + " "), u.username),
  h("span", { class: "row gap" },
    (u.upstream_ips || []).some(ip => !ip.configured) ? badge("IP missing", "bad") : null,
    u.admin ? badge("admin", "accent") : null,
    !u.enabled ? badge("off", "bad") : null,
    badge(u.networks + (u.networks === 1 ? " network" : " networks"))))));
  if (!usersCache.find(u => u.username === selectedUser)) selectedUser = usersCache[0]?.username || null;
  if (selectedUser) await renderUser(usersCache.find(u => u.username === selectedUser));
  else $("#user-detail").replaceChildren(h("p", { class: "muted" }, "No users."));
};

async function renderUser(u) {
  document.querySelectorAll("#user-list li").forEach(li => li.classList.toggle("active", li.dataset.user === u.username));
  const detail = $("#user-detail");
  const self = me && u.username === me.user;
  const head = h("div", { class: "user-head" },
    h("div", {},
      h("h2", { style: "margin-bottom:6px" }, u.username, " ", u.admin ? badge("admin", "accent") : null, " ", u.enabled ? badge("enabled", "ok") : badge("disabled", "bad"), " ", !u.loaded && u.enabled ? badge("not loaded", "warn") : null),
      h("dl", { class: "kv" },
        h("dt", {}, "ID"), h("dd", {}, u.id),
        h("dt", {}, "Outgoing IP"), h("dd", {}, upstreamIPsEl(u)),
        h("dt", {}, "Nick"), h("dd", {}, u.nick || "—"),
        h("dt", {}, "Realname"), h("dd", {}, u.realname || "—"),
        h("dt", {}, "Max networks"), h("dd", {}, u.max_networks < 0 ? "unlimited" : u.max_networks),
        h("dt", {}, "Created"), h("dd", {}, when(u.created_at)),
        h("dt", {}, "Last active"), h("dd", {}, u.last_seen ? ago(u.last_seen) : "—"))),
    h("div", { class: "actions" },
      h("button", { class: "btn", onclick: () => editUser(u) }, "Edit"),
      h("button", { class: "btn", onclick: () => changePassword(u) }, "Password"),
      h("button", { class: "btn danger", disabled: self, title: self ? "You can't delete yourself" : null, onclick: () => deleteUser(u) }, "Delete")));

  const netsBox = h("div", {}, h("p", { class: "muted" }, "Loading networks…"));
  detail.replaceChildren(head,
    h("div", { class: "view-head", style: "margin:20px 0 10px" }, h("h2", { style: "margin:0" }, "Networks"),
      h("button", { class: "btn primary small", onclick: () => networkForm(u.username) }, "New network")),
    netsBox);

  const res = await api("GET", `/api/users/${encodeURIComponent(u.username)}/networks`);
  if (res.status_error) netsBox.append(h("p", { class: "error" }, "Live status unavailable: " + res.status_error));
  if (!res.networks.length) { netsBox.replaceChildren(h("p", { class: "muted" }, "No networks.")); return; }
  netsBox.replaceChildren(...res.networks.map(n => networkCard(u.username, n)));
}

// upstreamIPsEl shows the per-user source address(es) from upstream-user-ip
// and whether the host actually has them.
function upstreamIPsEl(u) {
  if (!u.upstream_ips) return h("span", { class: "muted" }, "server default (no upstream-user-ip)");
  return h("div", { class: "ip-list" }, u.upstream_ips.map(ip => ip.error
    ? h("div", {}, badge("error", "bad"), " ", ip.error)
    : h("div", {},
      h("code", {}, ip.ip), " ",
      !ip.configured ? badge("missing on host", "bad")
        : ip.active ? badge("active", "ok")
        : badge("idle", ""),
      !ip.configured ? h("div", { class: "hint" }, `Add ${ip.ip} to the node (e.g. soju-ipv6.service on the soju host), or this user can't connect to ${ip.range.includes(":") ? "IPv6" : "IPv4"} networks.`) : null)));
}

function stateBadge(state) {
  if (state.startsWith("connected")) return badge(state, "ok");
  if (state.startsWith("disabled")) return badge("disabled", "");
  if (state.startsWith("disconnected")) return badge("disconnected", "bad");
  return badge(state, "warn");
}

function networkCard(user, n) {
  const base = `/api/users/${encodeURIComponent(user)}/networks/${n.id}`;
  const chBox = h("div", { class: "channels", hidden: true });
  const act = (label, fn, cls = "") => h("button", { class: "btn small " + cls, onclick: fn }, label);
  return h("div", { class: "net" },
    h("div", { class: "net-head" },
      h("div", {}, h("span", { class: "net-title" }, n.display_name), " ", stateBadge(n.state)),
      h("div", { class: "net-actions" },
        act("Edit", () => networkForm(user, n)),
        act("Reconnect", () => guard(async () => { outputToast(await api("POST", base + "/reconnect"), "Reconnecting"); refresh(); })),
        act(n.enabled ? "Disable" : "Enable", () => guard(async () => {
          outputToast(await api("PATCH", base, { enabled: !n.enabled })); refresh();
        })),
        act("SASL", () => saslForm(user, n)),
        act("Raw", () => quoteForm(user, n)),
        act(`Channels (${n.channels})`, () => toggleChannels(user, n, chBox)),
        act("Delete", () => confirmAction("Delete network", `Network "${n.display_name}" of ${user} will be removed, along with its saved channels.`, "Delete",
          async () => { outputToast(await api("DELETE", base)); refresh(); }), "danger"))),
    h("div", { class: "net-meta" },
      h("span", {}, n.addr),
      n.nick ? h("span", {}, "nick " + n.nick) : null,
      n.sasl_mechanism ? h("span", {}, `SASL ${n.sasl_mechanism}${n.sasl_username ? " (" + n.sasl_username + ")" : ""}`) : h("span", {}, "no SASL"),
      n.has_pass ? h("span", {}, "server PASS set") : null,
      n.auto_away ? null : h("span", {}, "auto-away off"),
      n.details ? h("span", {}, n.details) : null),
    chBox);
}

function editUser(u) {
  const self = me && u.username === me.user;
  openForm({
    title: "Edit " + u.username,
    fields: [
      { name: "nick", label: "Nick", value: u.nick },
      { name: "realname", label: "Realname", value: u.realname },
      { name: "max_networks", label: "Max networks", type: "number", value: u.max_networks, hint: "-1 = unlimited" },
      { name: "admin", label: "Administrator", type: "checkbox", value: u.admin },
      { name: "enabled", label: "Enabled", type: "checkbox", value: u.enabled },
    ],
    onSubmit: async v => {
      const body = {};
      if (v.nick !== u.nick) body.nick = v.nick;
      if (v.realname !== u.realname) body.realname = v.realname;
      if (v.max_networks !== null && v.max_networks !== u.max_networks) body.max_networks = v.max_networks;
      if (v.admin !== u.admin && !self) body.admin = v.admin;
      if (v.enabled !== u.enabled && !self) body.enabled = v.enabled;
      if (!Object.keys(body).length) return;
      outputToast(await api("PATCH", "/api/users/" + encodeURIComponent(u.username), body));
      refresh();
    },
  });
}

function changePassword(u) {
  openForm({
    title: "Password for " + u.username,
    fields: [{ name: "password", label: "New password", type: "password", required: true }],
    onSubmit: async v => { outputToast(await api("PATCH", "/api/users/" + encodeURIComponent(u.username), { password: v.password })); },
  });
}

function deleteUser(u) {
  openForm({
    title: "Delete user",
    intro: `"${u.username}" will be deleted with all its networks, channels and history. Type the username to confirm.`,
    fields: [{ name: "confirm", label: "Username", required: true }],
    ok: "Delete", danger: true,
    onSubmit: async v => {
      if (v.confirm !== u.username) throw new Error("The name doesn't match");
      outputToast(await api("DELETE", "/api/users/" + encodeURIComponent(u.username)));
      selectedUser = null;
      refresh();
    },
  });
}

$("[data-action=new-user]").addEventListener("click", () => openForm({
  title: "New user",
  fields: [
    { name: "username", label: "Username", required: true, pattern: "[^\\s]+" },
    { name: "password", label: "Password", type: "password", required: true },
    { name: "nick", label: "Nick (optional)" },
    { name: "realname", label: "Realname (optional)" },
    { name: "admin", label: "Administrator", type: "checkbox" },
  ],
  ok: "Create",
  onSubmit: async v => {
    const body = { username: v.username, password: v.password, admin: v.admin };
    if (v.nick) body.nick = v.nick;
    if (v.realname) body.realname = v.realname;
    outputToast(await api("POST", "/api/users", body));
    selectedUser = v.username;
    refresh();
  },
}));

function networkForm(user, n) {
  const editing = !!n;
  openForm({
    title: editing ? "Edit " + n.display_name : "New network for " + user,
    fields: [
      { name: "addr", label: "Address", value: n?.addr, required: true, placeholder: "ircs://irc.libera.chat", hint: "ircs://host[:port], irc+insecure://…" },
      { name: "name", label: "Name", value: n?.name, placeholder: "libera" },
      { name: "nick", label: "Nick", value: n?.nick },
      { name: "username", label: "Username", value: n?.username },
      { name: "realname", label: "Realname", value: n?.realname },
      { name: "pass", label: "Server password (PASS)", type: "password", hint: editing ? (n.has_pass ? "One is stored; leave empty to keep it" : "Empty = no PASS") : "Optional" },
      { name: "connect_commands", label: "Commands on connect (one per line)", type: "textarea", mono: true, rows: 3, value: (n?.connect_commands || []).join("\n"), placeholder: "PRIVMSG NickServ :IDENTIFY …" },
      { name: "enabled", label: "Enabled", type: "checkbox", value: editing ? n.enabled : true },
      { name: "auto_away", label: "Auto-away", type: "checkbox", value: editing ? n.auto_away : true },
      editing ? null : { name: "ignore_limit", label: "Ignore the user's network limit", type: "checkbox" },
    ].filter(Boolean),
    ok: editing ? "Save" : "Create",
    onSubmit: async v => {
      const cmds = v.connect_commands.split("\n").map(s => s.trim()).filter(Boolean);
      const body = {};
      for (const k of ["addr", "name", "nick", "username", "realname"]) {
        if (!editing ? v[k] : v[k] !== (n[k] || "")) body[k] = v[k];
      }
      if (v.pass) body.pass = v.pass;
      if (!editing || cmds.join("\n") !== n.connect_commands.join("\n")) {
        if (cmds.length || editing) body.connect_commands = cmds;
      }
      if (!editing || v.enabled !== n.enabled) body.enabled = v.enabled;
      if (!editing || v.auto_away !== n.auto_away) body.auto_away = v.auto_away;
      if (!editing && v.ignore_limit) body.ignore_limit = true;
      if (editing && !Object.keys(body).length) return;
      const path = `/api/users/${encodeURIComponent(user)}/networks` + (editing ? "/" + n.id : "");
      outputToast(await api(editing ? "PATCH" : "POST", path, body));
      refresh();
    },
  });
}

function saslForm(user, n) {
  const base = `/api/users/${encodeURIComponent(user)}/networks/${n.id}/sasl`;
  openForm({
    title: "SASL PLAIN · " + n.display_name,
    intro: n.sasl_mechanism ? `Current: ${n.sasl_mechanism}${n.sasl_username ? " as " + n.sasl_username : ""}.` : "This network has no SASL configured.",
    fields: [
      { name: "username", label: "SASL username", value: n.sasl_username || n.nick, required: true },
      { name: "password", label: "SASL password", type: "password", required: true },
      { name: "reconnect", label: "Reconnect to apply it now", type: "checkbox", value: true },
    ],
    onSubmit: async v => { outputToast(await api("PUT", base, v)); refresh(); },
  });
  if (n.sasl_mechanism) {
    const reset = h("button", { class: "btn danger", type: "button", onclick: () => guard(async () => {
      outputToast(await api("DELETE", base)); modal.close(); refresh();
    }) }, "Remove SASL");
    $("#modal-body").append(h("div", {}, reset));
  }
}

function quoteForm(user, n) {
  openForm({
    title: "Raw line to " + n.display_name,
    intro: "Sent as-is to this network's IRC server.",
    fields: [{ name: "line", label: "IRC command", required: true, placeholder: "PRIVMSG NickServ :INFO" }],
    ok: "Send",
    onSubmit: async v => { outputToast(await api("POST", `/api/users/${encodeURIComponent(user)}/networks/${n.id}/quote`, v), "Sent"); },
  });
}

const filterOpts = [["default", "default"], ["none", "never"], ["highlight", "on highlight"], ["message", "on any message"]];

async function toggleChannels(user, n, box, force = false) {
  if (!box.hidden && !force) { box.hidden = true; return; }
  box.hidden = false;
  const base = `/api/users/${encodeURIComponent(user)}/networks/${n.id}/channels`;
  const chans = await guard(() => api("GET", base));
  if (!chans) return;
  const reload = () => toggleChannels(user, n, box, true);
  const label = v => (filterOpts.find(o => o[0] === v) || [v, v])[1];
  box.replaceChildren(
    h("div", { class: "row gap", style: "justify-content:space-between;margin-bottom:6px" },
      h("h3", { style: "margin:0" }, "Saved channels"),
      h("button", { class: "btn small", onclick: () => channelForm(base, null, reload) }, "Add channel")),
    chans.length ? h("div", { class: "table-wrap" }, h("table", {},
      h("tr", {}, h("th", {}, "Canal"), h("th", {}, "State"), h("th", {}, "Reenviar si detached"), h("th", {}, "Re-attach"), h("th", {}, "Auto-detach"), h("th", {})),
      chans.map(c => h("tr", {},
        h("td", {}, c.name, c.has_key ? " 🔑" : ""),
        h("td", {}, c.detached ? badge("detached", "warn") : badge("attached", "ok")),
        h("td", {}, label(c.relay_detached)),
        h("td", {}, label(c.reattach_on)),
        h("td", {}, c.detach_after ? `${Math.round(c.detach_after / 60)} min · ${label(c.detach_on)}` : "—"),
        h("td", { class: "actions-cell" },
          h("button", { class: "btn small", onclick: () => channelForm(base, c, reload) }, "Edit"),
          h("button", { class: "btn small danger", onclick: () => confirmAction("Remove channel", `${c.name} will be removed from the saved channels.`, "Remove",
            async () => { outputToast(await api("DELETE", base + "/" + encodeURIComponent(c.name))); reload(); }) }, "Remove")))))) : h("p", { class: "muted" }, "None."));
}

function channelForm(base, c, done) {
  openForm({
    title: c ? "Channel " + c.name : "Add channel",
    fields: [
      c ? null : { name: "name", label: "Channel", required: true, placeholder: "#soju" },
      { name: "detached", label: "Detached (hidden from clients)", type: "checkbox", value: c?.detached },
      { name: "relay_detached", label: "Relay messages while detached", type: "select", options: filterOpts, value: c?.relay_detached || "default" },
      { name: "reattach_on", label: "Re-attach automatically", type: "select", options: filterOpts, value: c?.reattach_on || "default" },
      { name: "detach_after", label: "Auto-detach after (minutes of inactivity)", type: "number", min: 0, value: c ? Math.round(c.detach_after / 60) : 0, hint: "0 = never" },
      { name: "detach_on", label: "…resetting the timer on", type: "select", options: filterOpts, value: c?.detach_on || "default" },
    ].filter(Boolean),
    onSubmit: async v => {
      const body = { detached: v.detached, relay_detached: v.relay_detached, reattach_on: v.reattach_on, detach_on: v.detach_on, detach_after: (v.detach_after || 0) * 60 };
      if (c) outputToast(await api("PATCH", base + "/" + encodeURIComponent(c.name), body));
      else outputToast(await api("POST", base, { name: v.name, ...body }));
      done();
    },
  });
}

// --- config

const cfg = { info: null, base: "", text: "", baseMotd: "", motd: "", mode: "form", checkTimer: null, check: null };

views.config = async () => {
  const c = await api("GET", "/api/config");
  cfg.info = c;
  cfg.base = c.configmap ?? c.live;
  cfg.text = cfg.base;
  cfg.baseMotd = cfg.motd = c.motd || "";
  $("#config-live").textContent = c.live;
  $("#config-meta").textContent = c.editable
    ? `Editing ConfigMap "${c.configmap_name}", mounted at ${c.path}.` + (c.configmap !== c.live ? " ⚠ The ConfigMap and the mounted file differ (the kubelet hasn't synced yet, or the change was never applied)." : "")
    : `Read only (${c.path}).` + (c.configmap_error ? " " + c.configmap_error : " Set SOJU_CONFIGMAP to enable editing.");
  renderConfig();
};

function renderConfig() {
  const editable = cfg.info?.editable;
  document.querySelectorAll("#config-mode button").forEach(b => b.classList.toggle("active", b.dataset.mode === cfg.mode));
  const form = $("#config-form"), editor = $("#config-editor");
  form.hidden = cfg.mode !== "form";
  editor.hidden = cfg.mode !== "raw";
  if (cfg.mode === "form") {
    ConfigForm.render(form, cfg.text, {
      adminSocket: cfg.info?.admin_socket,
      motd: { text: cfg.motd, path: cfg.info?.motd_path },
      onChange: configChanged,
      onMotdChange: t => { cfg.motd = t; },
    });
    form.querySelectorAll("input, select, textarea, button").forEach(el => { if (!editable) el.disabled = true; });
  } else {
    editor.value = cfg.text;
    editor.readOnly = !editable;
  }
  configChanged(cfg.text);
}

function configChanged(text) {
  cfg.text = text;
  const dirty = cfg.text !== cfg.base || motdChanged();
  $("[data-action=save-config]").disabled = !cfg.info?.editable || !dirty;
  $("[data-action=revert-config]").disabled = !dirty;
  clearTimeout(cfg.checkTimer);
  cfg.checkTimer = setTimeout(checkConfig, 350);
}

async function checkConfig() {
  const box = $("#config-check");
  try {
    cfg.check = await api("POST", "/api/config/check", { content: cfg.text, motd: cfg.motd });
  } catch (e) {
    if (e.status !== 401) box.replaceChildren(h("div", { class: "callout bad" }, e.message));
    return;
  }
  const { errors, warnings } = cfg.check;
  // Native DOM methods would render null as the text "null", so filter it out.
  box.replaceChildren(...[
    errors.length ? h("div", { class: "callout bad" }, h("b", {}, "soju would refuse this config:"), h("ul", {}, errors.map(e => h("li", {}, e)))) : null,
    warnings.length ? h("div", { class: "callout" }, h("ul", {}, warnings.map(w => h("li", {}, w)))) : null,
  ].filter(Boolean));
  if (errors.length) $("[data-action=save-config]").disabled = true;
}

$("#config-mode").addEventListener("click", ev => {
  const b = ev.target.closest("button[data-mode]");
  if (!b || b.dataset.mode === cfg.mode) return;
  cfg.mode = b.dataset.mode;
  renderConfig();
});
$("#config-editor").addEventListener("input", ev => configChanged(ev.target.value));
$("[data-action=revert-config]").addEventListener("click", () => { cfg.text = cfg.base; cfg.motd = cfg.baseMotd; renderConfig(); });

// Compare like the server does (one trailing newline), so retyping the same text isn't a change.
const normMotd = t => { t = t.replace(/\r\n/g, "\n").replace(/[\n\t ]+$/, ""); return t ? t + "\n" : ""; };
const motdChanged = () => normMotd(cfg.motd) !== normMotd(cfg.baseMotd);

// diffEl shows changed lines with two lines of context around them.
function diffEl(title, before, after) {
  const lines = ConfigForm.diff(before, after)
    .filter((d, i, all) => d[0] !== " " || all.slice(Math.max(0, i - 2), i + 3).some(x => x[0] !== " "))
    .map(([op, line]) => h("span", { class: op === "+" ? "add" : op === "-" ? "del" : "" }, op + " " + line + "\n"));
  return h("div", {}, h("h3", { style: "margin:0 0 6px" }, title), h("pre", { class: "code diff" }, lines));
}

$("[data-action=save-config]").addEventListener("click", async () => {
  await checkConfig();
  if (cfg.check?.errors.length) { toast("Fix the errors first", true); return; }
  const restart = ConfigForm.needsRestart(cfg.base, cfg.text);
  const content = cfg.text;
  const motd = motdChanged() ? cfg.motd : undefined;
  openForm({
    title: "Review changes",
    fields: [{
      name: "apply", label: "Then", type: "select", value: restart ? "restart" : "reload",
      options: [["reload", "Reload soju (SIGHUP)"], ["restart", "Restart soju (clients reconnect)"], ["none", "Only save the ConfigMap"]],
    }],
    ok: "Save",
    onSubmit: async v => {
      runJob(api("PUT", "/api/config", { content, motd, apply: v.apply }), () => views.config());
    },
  });
  const body = $("#modal-body");
  body.prepend(...[
    content !== cfg.base ? diffEl("config", cfg.base, content) : null,
    motd !== undefined ? diffEl("message of the day", cfg.baseMotd, motd) : null,
  ].filter(Boolean));
  if (restart) body.prepend(h("div", { class: "callout" }, "These changes touch listen, db or message-store, which only take effect after a restart."));
});

// --- database

let statsCache = null;

views.database = async () => {
  const [s, backups] = await Promise.all([api("GET", "/api/db/stats"), api("GET", "/api/backups")]);
  statsCache = s;
  $("#db-cards").replaceChildren(
    card("soju.db", bytes(s.file_size), `WAL ${bytes(s.wal_size)} · SQLite ${s.sqlite_version}`),
    card("Reclaimable space", bytes(s.free_pages * s.page_size), "free pages, reclaimed by VACUUM"),
    card("Messages", s.messages.toLocaleString(), s.targets.length + " conversations"),
    card("Backups", bytes(s.backups_bytes), backups.length + " files"),
    card("Volume /data", bytes(s.volume_free) + " free", "of " + bytes(s.volume_total)));

  // purge selectors
  const nets = new Map();
  for (const t of s.targets) nets.set(t.network_id, `${t.username} / ${t.network}`);
  const netSel = $("#purge-network");
  const prevNet = netSel.value;
  netSel.replaceChildren(h("option", { value: 0 }, "All"), ...[...nets].map(([id, l]) => h("option", { value: id }, l)));
  if (nets.has(Number(prevNet))) netSel.value = prevNet;
  fillTargets();

  $("#targets-table").replaceChildren(
    h("tr", {}, h("th", {}, "User / network"), h("th", {}, "Conversation"), h("th", { class: "num" }, "Messages"), h("th", {}, "Oldest"), h("th", {}, "Newest"), h("th", {})),
    ...s.targets.slice(0, 200).map(t => h("tr", {},
      h("td", {}, `${t.username} / ${t.network}`), h("td", {}, t.target),
      h("td", { class: "num" }, t.messages.toLocaleString()),
      h("td", {}, when(t.oldest)), h("td", {}, ago(t.newest)),
      h("td", { class: "actions-cell" }, h("button", { class: "btn small", onclick: () => {
        netSel.value = t.network_id; fillTargets(); $("#purge-target").value = t.target_id;
        $("#purge-form").scrollIntoView({ behavior: "smooth" }); previewPurge();
      } }, "Purge…")))));

  $("#backups-table").replaceChildren(
    h("tr", {}, h("th", {}, "File"), h("th", { class: "num" }, "Size"), h("th", {}, "Date"), h("th", {})),
    ...(backups.length ? backups.map(b => h("tr", {},
      h("td", {}, h("code", {}, b.name)), h("td", { class: "num" }, bytes(b.size)), h("td", {}, when(b.mod_time)),
      h("td", { class: "actions-cell" },
        h("a", { class: "btn small", href: "/api/backups/" + encodeURIComponent(b.name), download: b.name }, "Download"),
        h("button", { class: "btn small danger", onclick: () => confirmAction("Delete backup", b.name, "Delete",
          async () => { await api("DELETE", "/api/backups/" + encodeURIComponent(b.name)); views.database(); }) }, "Delete"))))
      : [h("tr", {}, h("td", { colspan: 4, class: "muted" }, "No backups yet."))]));
};

function fillTargets() {
  const net = Number($("#purge-network").value);
  const sel = $("#purge-target");
  const targets = (statsCache?.targets || []).filter(t => !net || t.network_id === net);
  sel.replaceChildren(h("option", { value: 0 }, "All"), ...targets.map(t => h("option", { value: t.target_id }, `${t.target} (${t.messages})`)));
  sel.disabled = !net;
}
$("#purge-network").addEventListener("change", () => { fillTargets(); previewPurge(); });
$("#purge-target").addEventListener("change", previewPurge);

function purgeFilter() {
  const f = new FormData($("#purge-form"));
  return {
    network_id: Number(f.get("network_id") || 0),
    target_id: Number(f.get("target_id") || 0),
    older_than_days: Number(f.get("older_than_days") || 0),
  };
}

async function previewPurge() {
  const out = $("#purge-preview");
  out.textContent = "counting…";
  const r = await guard(() => api("POST", "/api/db/purge/preview", purgeFilter()));
  out.textContent = r ? `${r.messages.toLocaleString()} messages would be deleted` : "";
  return r;
}
$("[data-action=purge-preview]").addEventListener("click", previewPurge);

$("#purge-form").addEventListener("submit", async ev => {
  ev.preventDefault();
  const r = await previewPurge();
  if (!r) return;
  if (!r.messages) { toast("No matching messages"); return; }
  const f = purgeFilter();
  const form = new FormData($("#purge-form"));
  const scope = f.target_id ? "from that conversation" : f.network_id ? "from that network" : "from ALL networks and users";
  const age = f.older_than_days ? `older than ${f.older_than_days} days` : "regardless of age";
  confirmAction("Purge messages", `${r.messages.toLocaleString()} messages ${scope}, ${age}, will be deleted. This can only be undone by restoring a backup.`, "Purge",
    async () => { runJob(api("POST", "/api/db/purge", { ...f, backup: form.get("backup") === "on", vacuum: form.get("vacuum") === "on" }), () => views.database()); });
});

document.addEventListener("click", ev => {
  const btn = ev.target.closest("[data-action]");
  if (!btn) return;
  const a = btn.dataset.action;
  if (a === "backup") runJob(api("POST", "/api/backups"), () => views.database());
  if (a === "check") runJob(api("POST", "/api/db/check"));
  if (a === "vacuum") confirmAction("VACUUM", "Rewrites soju.db to reclaim space. soju's writes are blocked while it runs (seconds to a few minutes), and it needs free space equal to the database size.", "Run",
    async () => { runJob(api("POST", "/api/db/vacuum"), () => views.database()); });
  if (a === "reload") guard(async () => { outputToast(await api("POST", "/api/soju/reload")); });
  if (a === "restart") confirmAction("Restart soju", "soju gets SIGTERM and the kubelet restarts the container in the same pod. Clients and upstream connections drop for a few seconds.", "Restart",
    async () => { runJob(api("POST", "/api/soju/restart"), refresh); });
  if (a === "debug") guard(async () => { outputToast(await api("POST", "/api/server/debug", { enabled: btn.dataset.enabled === "true" })); });
  if (a === "refresh-logs") views.logs();
  if (a === "logout") guard(async () => { await api("POST", "/api/logout"); showLogin(); });
});

$("#notice-form").addEventListener("submit", ev => {
  ev.preventDefault();
  const text = new FormData(ev.target).get("text");
  guard(async () => { outputToast(await api("POST", "/api/server/notice", { text }), "Notice sent"); ev.target.reset(); });
});

// --- logs

let logsText = "";
let followTimer = null;

views.logs = async () => {
  const q = new URLSearchParams({ container: $("#logs-container").value, tail: $("#logs-tail").value, previous: $("#logs-previous").checked ? "1" : "0" });
  try {
    const r = await api("GET", "/api/logs?" + q);
    logsText = r.logs;
  } catch (e) {
    logsText = "";
    $("#logs-output").textContent = e.message;
    return;
  }
  renderLogs();
};

function renderLogs() {
  const out = $("#logs-output");
  const atBottom = out.scrollTop + out.clientHeight >= out.scrollHeight - 20;
  const f = $("#logs-filter").value.toLowerCase();
  out.textContent = f ? logsText.split("\n").filter(l => l.toLowerCase().includes(f)).join("\n") : logsText;
  if (atBottom || !out.dataset.seen) { out.scrollTop = out.scrollHeight; out.dataset.seen = "1"; }
}

function stopFollow() { clearInterval(followTimer); followTimer = null; $("#logs-follow").checked = false; }
$("#logs-filter").addEventListener("input", renderLogs);
for (const id of ["#logs-container", "#logs-tail", "#logs-previous"]) $(id).addEventListener("change", () => views.logs());
$("#logs-follow").addEventListener("change", ev => {
  clearInterval(followTimer);
  followTimer = ev.target.checked ? setInterval(() => views.logs(), 5000) : null;
});

// --- console

views.console = async () => {
  const sel = $("#console-as");
  const prev = sel.value;
  const res = await api("GET", "/api/users");
  sel.replaceChildren(h("option", { value: "" }, "(admin)"), ...res.users.map(u => h("option", { value: u.username }, "as " + u.username)));
  sel.value = prev;
};

$("#console-form").addEventListener("submit", async ev => {
  ev.preventDefault();
  const f = new FormData(ev.target);
  const out = $("#console-output");
  const prompt = (f.get("as") ? f.get("as") + "> " : "admin> ") + f.get("command");
  try {
    const r = await api("POST", "/api/command", { as: f.get("as"), command: f.get("command") });
    out.textContent = prompt + "\n" + (r.output.join("\n") || "(ok)") + "\n\n" + out.textContent;
  } catch (e) {
    if (e.status === 401) return;
    out.textContent = prompt + "\nERROR: " + e.message + "\n\n" + out.textContent;
  }
});

// ---------- session ----------

function showLogin() {
  stopFollow();
  me = null;
  $("#app").hidden = true;
  $("#login").hidden = false;
}

function showApp(info) {
  me = info;
  csrf = info.csrf;
  $("#whoami").textContent = "Signed in as " + info.user;
  $("#login").hidden = true;
  $("#app").hidden = false;
  route();
}

$("#login-form").addEventListener("submit", async ev => {
  ev.preventDefault();
  const f = new FormData(ev.target);
  const err = $("#login-error");
  err.hidden = true;
  try {
    const r = await api("POST", "/api/login", { username: f.get("username"), password: f.get("password") });
    ev.target.reset();
    showApp(r);
  } catch (e) {
    err.textContent = e.message;
    err.hidden = false;
  }
});

(async () => {
  try { showApp(await api("GET", "/api/me")); }
  catch { showLogin(); }
})();
