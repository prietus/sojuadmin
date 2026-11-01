"use strict";

// Structured editor for soju's config file (scfg format).
//
// The file stays the source of truth: the form reads values out of it and
// writes them back by rewriting only the directive lines that changed, so
// comments, ordering and untouched lines survive every edit.

const ConfigForm = (() => {
  // ---------- scfg parsing / serialization ----------

  // splitWords mirrors go-scfg: whitespace-separated words, '' or "" quotes,
  // backslash escapes, '#' starts a comment only at the beginning of a line.
  function splitWords(line) {
    const words = [];
    let cur = "", inWord = false, quote = "", escape = false;
    for (const ch of line) {
      if (escape) { cur += ch; escape = false; continue; }
      if (ch === "\\") { escape = true; inWord = true; continue; }
      if (quote) {
        if (ch === quote) quote = "";
        else cur += ch;
        continue;
      }
      if (!words.length && !inWord && ch === "#") return null;
      if (ch === "'" || ch === '"') { quote = ch; inWord = true; continue; }
      if (ch === " " || ch === "\t") {
        if (inWord) { words.push(cur); cur = ""; inWord = false; }
        continue;
      }
      cur += ch;
      inWord = true;
    }
    if (inWord) words.push(cur);
    return words;
  }

  function parse(text) {
    return text.replace(/\n$/, "").split("\n").map(raw => {
      const words = splitWords(raw);
      if (words === null) return { raw, kind: "comment" };
      if (!words.length) return { raw, kind: "blank" };
      return { raw, kind: "dir", name: words[0], params: words.slice(1) };
    });
  }

  function quote(word) {
    if (word !== "" && !/[\s"'\\{}]/.test(word) && !word.startsWith("#")) return word;
    return '"' + word.replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '"';
  }

  const serialize = (name, params) => [name, ...params].map(quote).join(" ");
  const sameParams = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);

  // ---------- schema ----------

  const DIRECTIVE_ALIASES = { log: "message-store" };

  const LISTEN_SCHEMES = [
    ["ircs", "IRC over TLS", ":6697"],
    ["irc+insecure", "IRC, plain text", "0.0.0.0:6667"],
    ["irc", "IRC, plain text (localhost only)", "localhost:6667"],
    ["unix", "IRC on a Unix socket", "/run/soju/irc.sock"],
    ["https", "HTTPS (WebSocket + uploads)", ":443"],
    ["http+insecure", "HTTP, plain text (WebSocket + uploads)", "0.0.0.0:8080"],
    ["http", "HTTP, plain text (localhost only)", "localhost:8080"],
    ["http+unix", "HTTP on a Unix socket", "/run/soju/http.sock"],
    ["wss", "WebSocket over TLS", ":443"],
    ["ws+insecure", "WebSocket, plain text", "0.0.0.0:8080"],
    ["ws", "WebSocket, plain text (localhost only)", "localhost:8080"],
    ["ws+unix", "WebSocket on a Unix socket", "/run/soju/ws.sock"],
    ["ident", "Ident", ":113"],
    ["http+prometheus", "Prometheus metrics (localhost only)", "localhost:9090"],
    ["http+insecure+prometheus", "Prometheus metrics", "0.0.0.0:9090"],
    ["http+pprof", "pprof profiling (localhost only)", "localhost:6060"],
    ["unix+admin", "Admin socket (sojuctl, this panel)", "/run/soju/admin"],
  ];

  const SECTIONS = [
    {
      title: "Listeners",
      intro: "Addresses soju accepts connections on. Changes need a soju restart.",
      fields: [{ key: "listen", type: "listeners", restart: true }],
    },
    {
      title: "Server identity",
      fields: [
        { key: "hostname", type: "text", label: "Hostname", placeholder: "irc.example.org", help: "Fully qualified domain name of the bouncer." },
        { key: "title", type: "text", label: "Title", help: "Shown as the network name to clients that haven't picked a network." },
        { key: "icon", type: "text", label: "Icon", placeholder: "https://example.org/icon.png", help: "An https:// URL, or a local path (needs an HTTP listener)." },
      ],
    },
    {
      title: "Message of the day",
      intro: "Sent to clients that connect to the bouncer itself (not bound to a network). soju re-reads it on reload, no restart needed.",
      fields: [{ key: "motd", type: "motd" }],
    },
    {
      title: "TLS",
      intro: "Only needed when soju terminates TLS itself (ircs://, https://, wss://). Leave empty if the ingress does it.",
      fields: [{ key: "tls", type: "pair", labels: ["Certificate file (PEM)", "Key file (PEM)"] }],
    },
    {
      title: "HTTP & WebSocket",
      fields: [
        { key: "http-ingress", type: "text", label: "External URL", placeholder: "https://irc.example.org", help: "Public URL where the HTTP listeners are exposed. Default: https://<hostname>." },
        { key: "http-origin", type: "list", label: "Allowed WebSocket origins", placeholder: "https://app.example.org", help: "One glob pattern per line. Empty = only the request's own host." },
        {
          key: "file-upload", type: "driver", label: "File uploads",
          drivers: [["", "Disabled"], ["fs", "Store in a directory"], ["http", "Forward to an HTTP service"]],
          source: { fs: ["Directory", "/data/uploads"], http: ["Upload URL", "http://uploader:8081/upload"] },
          help: "Requires an HTTP listener.",
        },
      ],
    },
    {
      title: "Storage",
      fields: [
        {
          key: "db", type: "driver", label: "Database", restart: true,
          drivers: [["", "Default (SQLite, ./soju.db)"], ["sqlite3", "SQLite"], ["postgres", "PostgreSQL"]],
          source: { sqlite3: ["File", "/data/soju.db"], postgres: ["Connection string", "host=/run/postgresql dbname=soju"] },
          sourceRequired: true,
        },
        {
          key: "message-store", type: "driver", label: "Message history", restart: true,
          drivers: [["", "Default (database)"], ["db", "Database (with full-text search)"], ["fs", "Files on disk (ZNC format, lossy)"], ["memory", "Memory only (last 4K per chat)"]],
          source: { fs: ["Directory", "/data/logs"] },
          sourceRequired: true,
        },
        { key: "message-expiry", type: "days", label: "Delete messages older than", help: "soju cleans up once a day. Empty = keep forever. Run VACUUM afterwards to reclaim disk space." },
      ],
    },
    {
      title: "Users & authentication",
      fields: [
        { key: "max-user-networks", type: "number", label: "Max enabled networks per user", min: 0, help: "Empty = unlimited." },
        { key: "disable-inactive-user", type: "days", label: "Disable users inactive for", help: "Counted from their last disconnection. Empty = never." },
        { key: "enable-user-on-auth", type: "bool", label: "Re-enable disabled users when they log in" },
        {
          key: "auth", type: "driver", label: "Authentication",
          drivers: [["", "Internal (default)"], ["internal", "Internal"], ["http", "HTTP basic auth"], ["oauth2", "OAuth 2.0"], ["pam", "PAM"]],
          source: { http: ["URL", "https://auth.example.org/check"], oauth2: ["Authorization server URL", "https://id:secret@auth.example.org"] },
          sourceRequired: true,
        },
        { key: "client-cert-auth", type: "bool", label: "Client certificate authentication" },
      ],
    },
    {
      title: "Proxies & networking",
      fields: [
        { key: "accept-proxy-ip", type: "list", label: "Trusted proxy addresses", placeholder: "10.0.0.0/8", help: "CIDRs (or localhost), one per line, allowed to set PROXY / Forwarded / X-Forwarded-* headers." },
        { key: "accept-proxy-unix", type: "bool", label: "Trust proxy headers on Unix sockets" },
        { key: "upstream-user-ip", type: "list", label: "Per-user outgoing IP ranges", placeholder: "2001:db8::/56", help: "At most one IPv4 and one IPv6 CIDR; each user gets its own address." },
      ],
    },
    {
      title: "Other directives",
      intro: "Lines this form doesn't know about. soju v0.11 refuses to start on unknown directives, so this should normally be empty.",
      fields: [{ key: "__other", type: "other" }],
    },
  ];

  const KNOWN = new Set(SECTIONS.flatMap(s => s.fields.map(f => f.key)).filter(k => k !== "__other"));
  const RESTART_KEYS = new Set(SECTIONS.flatMap(s => s.fields).filter(f => f.restart).map(f => f.key));
  const groupOf = name => {
    const n = DIRECTIVE_ALIASES[name] || name;
    return KNOWN.has(n) ? n : "__other";
  };

  // values: group -> list of directive param arrays; __other keeps raw lines.
  function extract(lines) {
    const values = {};
    for (const l of lines) {
      if (l.kind !== "dir") continue;
      const g = groupOf(l.name);
      (values[g] ||= []).push(g === "__other" ? [l.raw.trim()] : l.params);
    }
    return values;
  }

  // merge rewrites `text` so that each group's directives match `values`,
  // touching as few lines as possible.
  function merge(text, values) {
    const lines = parse(text);
    const used = {};
    const lastPos = {};
    const out = [];
    for (const l of lines) {
      if (l.kind !== "dir") { out.push(l.raw); continue; }
      const g = groupOf(l.name);
      const want = values[g] || [];
      const i = used[g] || 0;
      if (i >= want.length) continue; // removed
      used[g] = i + 1;
      if (g === "__other") {
        out.push(want[i][0] === l.raw.trim() ? l.raw : want[i][0]);
      } else {
        // A changed deprecated alias (log) is rewritten under its current name.
        out.push(sameParams(want[i], l.params) ? l.raw : serialize(DIRECTIVE_ALIASES[l.name] ? g : l.name, want[i]));
      }
      lastPos[g] = out.length - 1;
    }
    // New directives go right after the last one of the same kind, or at the end.
    const order = [...KNOWN, "__other"];
    for (const g of order) {
      const want = values[g] || [];
      const extra = want.slice(used[g] || 0).map(p => g === "__other" ? p[0] : serialize(g, p));
      if (!extra.length) continue;
      if (g in lastPos) {
        const at = lastPos[g] + 1;
        out.splice(at, 0, ...extra);
        for (const k of Object.keys(lastPos)) if (lastPos[k] >= at) lastPos[k] += extra.length;
        lastPos[g] = at + extra.length - 1;
      } else {
        while (out.length && out[out.length - 1].trim() === "") out.pop();
        out.push(...extra);
        lastPos[g] = out.length - 1;
      }
    }
    return out.join("\n") + "\n";
  }

  // ---------- line diff (LCS) ----------

  function diff(a, b) {
    const lines = t => t === "" ? [] : t.replace(/\n$/, "").split("\n");
    const A = lines(a), B = lines(b);
    const n = A.length, m = B.length;
    const dp = Array.from({ length: n + 1 }, () => new Uint16Array(m + 1));
    for (let i = n - 1; i >= 0; i--)
      for (let j = m - 1; j >= 0; j--)
        dp[i][j] = A[i] === B[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    const out = [];
    let i = 0, j = 0;
    while (i < n || j < m) {
      if (i < n && j < m && A[i] === B[j]) { out.push([" ", A[i]]); i++; j++; }
      else if (j < m && (i >= n || dp[i][j + 1] >= dp[i + 1][j])) { out.push(["+", B[j]]); j++; }
      else { out.push(["-", A[i]]); i++; }
    }
    return out;
  }

  // needsRestart reports whether a change touches directives SIGHUP can't apply.
  function needsRestart(before, after) {
    const a = extract(parse(before)), b = extract(parse(after));
    return [...RESTART_KEYS].some(k => JSON.stringify(a[k] || []) !== JSON.stringify(b[k] || []));
  }

  // ---------- form rendering ----------

  // motd: { text, path } — the managed MOTD stored in the ConfigMap next to
  // the config; onMotdChange receives its new text ("" = no managed MOTD).
  function render(container, text, { adminSocket, motd, onChange, onMotdChange }) {
    const lines = parse(text);
    const values = extract(lines);
    const readers = {}; // key -> () => list of param arrays
    const emit = () => {
      const next = {};
      for (const [k, read] of Object.entries(readers)) next[k] = read();
      // Groups without a form field (e.g. a second auth line) stay as they are.
      for (const [k, v] of Object.entries(values)) if (!(k in next)) next[k] = v;
      if (motdReader) onMotdChange(motdReader());
      onChange(merge(text, next));
    };
    let motdReader = null;
    const setMotdReader = fn => { motdReader = fn; };

    const sections = SECTIONS.map(sec => {
      const body = sec.fields.map(f => fieldEl(f, values[f.key] || [], readers, emit, { adminSocket, motd, setMotdReader }));
      if (sec.fields[0].type === "other" && !(values.__other || []).length) return null;
      return h("section", { class: "panel cfg-section" },
        h("h2", {}, sec.title),
        sec.intro ? h("p", { class: "muted small cfg-intro" }, sec.intro) : null,
        h("div", { class: "cfg-fields" }, body));
    });
    container.replaceChildren(...sections.filter(Boolean));
  }

  const restartChip = f => f.restart ? h("span", { class: "badge warn", title: "Takes effect after restarting soju" }, "restart") : null;

  function labeled(f, control, extra) {
    return h("div", { class: "cfg-field" },
      h("label", {}, h("span", { class: "cfg-label" }, f.label, " ", restartChip(f)), control),
      extra || null,
      f.help ? h("span", { class: "hint" }, f.help) : null);
  }

  function fieldEl(f, current, readers, emit, opts) {
    const on = el => { el.addEventListener("input", emit); el.addEventListener("change", emit); return el; };
    const first = current[0] || [];

    switch (f.type) {
      case "text":
      case "number": {
        const input = on(h("input", { type: f.type, placeholder: f.placeholder, min: f.min }));
        input.value = first[0] ?? "";
        readers[f.key] = () => input.value.trim() === "" ? [] : [[input.value.trim()]];
        return labeled(f, input);
      }
      case "days": {
        const input = on(h("input", { type: "number", min: 1, step: "any", placeholder: "never" }));
        input.value = (first[0] || "").replace(/d$/, "");
        readers[f.key] = () => input.value === "" ? [] : [[input.value + "d"]];
        return labeled(f, h("div", { class: "row gap" }, input, h("span", { class: "muted" }, "days")));
      }
      case "bool": {
        const sel = on(h("select", {},
          h("option", { value: "" }, "Default (off)"), h("option", { value: "true" }, "Yes"), h("option", { value: "false" }, "No")));
        sel.value = first[0] || "";
        readers[f.key] = () => sel.value ? [[sel.value]] : [];
        return labeled(f, sel);
      }
      case "pair": {
        const a = on(h("input", { placeholder: "/etc/ssl/soju/fullchain.pem" }));
        const b = on(h("input", { placeholder: "/etc/ssl/soju/privkey.pem" }));
        a.value = first[0] || ""; b.value = first[1] || "";
        readers[f.key] = () => (a.value || b.value) ? [[a.value.trim(), b.value.trim()]] : [];
        return h("div", { class: "cfg-field two" },
          h("label", {}, f.labels[0], a), h("label", {}, f.labels[1], b));
      }
      case "list": {
        const ta = on(h("textarea", { rows: 3, placeholder: f.placeholder, class: "mono" }));
        ta.value = first.join("\n");
        readers[f.key] = () => {
          const items = ta.value.split(/\s+/).filter(Boolean);
          return items.length ? [items] : [];
        };
        return labeled(f, ta);
      }
      case "driver": {
        if (current.length > 1) {
          return labeled(f, h("p", { class: "muted small" }, `${current.length} ${f.key} lines in the file; edit them in Raw file mode.`));
        }
        const sel = on(h("select", {}, f.drivers.map(([v, l]) => h("option", { value: v }, l))));
        const known = f.drivers.some(([v]) => v === (first[0] || ""));
        if (!known) sel.append(h("option", { value: first[0] }, first[0]));
        sel.value = first[0] || "";
        const src = on(h("input", {}));
        src.value = first.slice(1).join(" ");
        const srcLabel = h("span", {});
        const srcWrap = h("label", { class: "cfg-sub" }, srcLabel, src);
        const sync = () => {
          const s = f.source?.[sel.value];
          srcWrap.hidden = !s && !src.value;
          srcLabel.textContent = s ? s[0] : "Parameter";
          src.placeholder = s ? s[1] : "";
          src.required = !!(s && f.sourceRequired);
        };
        sel.addEventListener("change", sync);
        sync();
        readers[f.key] = () => {
          if (!sel.value) return [];
          const v = src.value.trim();
          return [v ? [sel.value, v] : [sel.value]];
        };
        return labeled(f, sel, srcWrap);
      }
      case "listeners":
        return listenersEl(f, current, readers, emit, opts);
      case "motd":
        return motdEl(f, first, readers, emit, opts);
      case "other": {
        const ta = on(h("textarea", { rows: 4, class: "mono" }));
        ta.value = current.map(p => p[0]).join("\n");
        readers[f.key] = () => ta.value.split("\n").map(s => s.trim()).filter(s => s && !s.startsWith("#")).map(s => [s]);
        return h("div", { class: "cfg-field" }, ta);
      }
    }
  }

  function motdEl(f, current, readers, emit, { motd, setMotdReader }) {
    const managed = motd?.path || "/etc/soju/motd";
    const path = current[0] || "";
    const mode = h("select", {},
      h("option", { value: "none" }, "No message of the day"),
      h("option", { value: "text" }, "Write it here"),
      h("option", { value: "file" }, "Use an existing file"));
    mode.value = !path ? (motd?.text ? "text" : "none") : path === managed ? "text" : "file";

    const text = h("textarea", { rows: 6, class: "mono", placeholder: "Welcome to the bouncer!\nRules: be nice." });
    text.value = motd?.text || "";
    const file = h("input", { class: "mono", placeholder: "/data/motd" });
    file.value = path !== managed ? path : "";

    const textWrap = h("div", { class: "cfg-field" }, text,
      h("span", { class: "hint" }, `Stored in the ConfigMap and mounted at ${managed}. Each line is sent as a separate MOTD line.`));
    const fileWrap = h("label", { class: "cfg-sub" }, "File path inside the soju container", file,
      h("span", { class: "hint" }, "soju won't start if the file doesn't exist."));
    const sync = () => {
      textWrap.hidden = mode.value !== "text";
      fileWrap.hidden = mode.value !== "file";
    };
    for (const el of [mode, text, file]) { el.addEventListener("input", emit); el.addEventListener("change", emit); }
    mode.addEventListener("change", sync);
    sync();

    readers[f.key] = () => {
      if (mode.value === "text") return text.value.trim() ? [[managed]] : [];
      if (mode.value === "file") return file.value.trim() ? [[file.value.trim()]] : [];
      return [];
    };
    // The text is kept while the box is visible; other modes drop the stored MOTD.
    setMotdReader(() => mode.value === "text" ? text.value : "");
    return h("div", { class: "cfg-field cfg-wide" }, mode, textWrap, fileWrap);
  }

  function splitListen(uri) {
    const m = /^([a-z0-9+]+):\/\/(.*)$/i.exec(uri);
    return m ? [m[1], m[2]] : ["ircs", uri];
  }

  function listenersEl(f, current, readers, emit, { adminSocket }) {
    const list = h("div", { class: "listeners" });
    const rows = [];

    const addRow = (uri, focus) => {
      const [scheme, addr] = splitListen(uri);
      const sel = h("select", {}, LISTEN_SCHEMES.map(([v, l]) => h("option", { value: v }, `${v}:// — ${l}`)));
      if (!LISTEN_SCHEMES.some(([v]) => v === scheme)) sel.append(h("option", { value: scheme }, scheme + "://"));
      sel.value = scheme;
      const input = h("input", { class: "mono" });
      input.value = addr;
      const locked = scheme === "unix+admin" && adminSocket && addr.replace(/^\/+/, "/") === adminSocket;
      const row = { sel, input };
      const remove = h("button", {
        class: "btn small ghost", type: "button", title: locked ? "This panel needs the admin socket" : "Remove listener",
        disabled: locked,
        onclick: () => { rows.splice(rows.indexOf(row), 1); el.remove(); emit(); },
      }, "✕");
      const ph = () => { input.placeholder = (LISTEN_SCHEMES.find(([v]) => v === sel.value) || [])[2] || ""; };
      sel.addEventListener("change", () => { ph(); emit(); });
      input.addEventListener("input", emit);
      if (locked) { sel.disabled = true; input.readOnly = true; }
      ph();
      const el = h("div", { class: "listener" }, sel, input, remove,
        locked ? h("span", { class: "hint listener-note" }, "Used by this panel — can't be removed here.") : null);
      rows.push(row);
      list.append(el);
      if (focus) input.focus();
    };

    for (const p of current) addRow(p[0] || "");
    readers[f.key] = () => rows.map(r => [r.sel.value + "://" + r.input.value.trim()]);

    return h("div", { class: "cfg-field" },
      list,
      h("div", {}, h("button", { class: "btn small", type: "button", onclick: () => { addRow("irc+insecure://", true); emit(); } }, "Add listener")));
  }

  return { parse, merge, diff, render, needsRestart, extract };
})();
