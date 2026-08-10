(() => {
  "use strict";

  // --- state ---
  const state = {
    processes: [],
    search: "",
    group: "",
    logTarget: null,
    logStream: "stdout",
    logActive: false,
  };

  // --- element cache ---
  const $ = (sel, root = document) => root.querySelector(sel);
  const el = {
    tbody: $("#tbody"),
    empty: $("#empty-state"),
    banner: $("#error-banner"),
    spinner: $("#refresh-spinner"),
    hint: $("#updated-hint"),
    stats: $("#stats"),
    search: $("#search-input"),
    group: $("#group-select"),
    logBody: $("#log-body"),
    logPre: $("#log-body pre"),
    logMeta: $("#log-meta"),
    logSpinner: $("#log-spinner"),
    logTitle: $("#log-title"),
    logSeg: $("#log-stream-seg"),
    logOverlay: $("#log-overlay"),
    detailOverlay: $("#detail-overlay"),
    detailTitle: $("#detail-title"),
    detailBody: $("#detail-body"),
  };

  // --- tiny utils ---
  const esc = (s) => {
    const d = document.createElement("div");
    d.textContent = s == null ? "" : String(s);
    return d.innerHTML;
  };
  const bytes = (b) => {
    b = Number(b) || 0;
    const u = ["B", "KB", "MB", "GB"];
    let i = 0;
    while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
    return (i ? b.toFixed(i > 1 ? 1 : 0) : b) + " " + u[i];
  };
  const uptime = (p) => {
    if (!["running", "restarting"].includes(p.status) || !p.last_started_at) return "–";
    const s = Math.max(0, Math.floor(Date.now() / 1000) - p.last_started_at);
    const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600),
      m = Math.floor((s % 3600) / 60), sec = s % 60;
    return d > 0 ? `${d}d ${h}h` : h > 0 ? `${h}h ${m}m` : m > 0 ? `${m}m ${sec}s` : `${sec}s`;
  };

  // --- debounced spinner ---
  const spin = {
    timers: {},
    show(ref, key) {
      clearTimeout(this.timers[key]);
      this.timers[key] = setTimeout(() => ref.classList.add("on"), 400);
    },
    hide(ref, key) {
      clearTimeout(this.timers[key]);
      ref.classList.remove("on");
    },
  };

  const banner = {
    show: (msg) => { el.banner.style.display = "block"; el.banner.textContent = msg; },
    hide: () => { el.banner.style.display = "none"; },
  };

  // --- data ---
  async function api(path, opts) {
    const res = await fetch(path, opts);
    const isJson = (res.headers.get("content-type") || "").includes("json");
    const data = isJson ? await res.json().catch(() => null) : await res.text();
    if (!res.ok) throw new Error((data && data.message) || `HTTP ${res.status}`);
    return data;
  }

  const act = async (target, action, btn) => {
    btn?.classList.add("busy");
    try {
      const d = await api(`/api/processes/${encodeURIComponent(target)}/${action}`, { method: "POST" });
      el.hint.textContent = d?.message || `${action} ok`;
    } catch (e) {
      banner.show(`Action ${action} on ${target} failed: ${e.message}`);
    } finally {
      btn?.classList.remove("busy");
    }
  };

  // --- rendering ---
  const filtered = () => {
    const term = state.search.trim().toLowerCase();
    return state.processes.filter((p) =>
      (!state.group || (p.namespace || "") === state.group) &&
      (!term || p.name.toLowerCase().includes(term) || String(p.id).includes(term) || String(p.status || "").includes(term))
    );
  };

  const groupOptions = () => {
    const groups = [...new Set(state.processes.map((p) => p.namespace).filter(Boolean))].sort();
    const cur = el.group.value;
    el.group.innerHTML = '<option value="">All groups</option>' +
      groups.map((g) => `<option value="${esc(g)}">${esc(g)}</option>`).join("");
    el.group.value = groups.includes(cur) ? cur : "";
    state.group = el.group.value;
  };

  const stats = () => {
    const by = state.processes.reduce((acc, p) => { acc[p.status] = (acc[p.status] || 0) + 1; return acc; }, {});
    const chip = (label, count, cls) => `<span class="stat ${cls}"><b>${count}</b> ${label}</span>`;
    el.stats.innerHTML =
      chip("total", state.processes.length, "") +
      chip("running", by.running || 0, "ok") +
      chip("restarting", by.restarting || 0, "warn") +
      chip("stopped", by.stopped || 0, "") +
      chip("crashed", by.crashed || 0, "bad") +
      chip("errored", by.errored || 0, "bad");
  };

  const row = (p) => {
    const running = p.status === "running";
    const action = (label, action, disabled, cls) => {
      const b = document.createElement("button");
      b.className = "small" + (cls ? " " + cls : "");
      b.textContent = label;
      b.disabled = !!disabled;
      b.dataset.target = p.name;
      b.dataset.action = action;
      return b;
    };
    const tr = document.createElement("tr");
    tr.className = "clickable";
    tr.dataset.name = p.name;
    tr.innerHTML = `
      <td><span class="badge"><span class="dot ${esc(p.status)}"></span>${esc(p.status || "unknown")}</span></td>
      <td class="name-cell">${esc(p.name)}</td>
      <td class="num">${p.id}</td>
      <td class="num">${p.pid ?? "–"}</td>
      <td>${uptime(p)}</td>
      <td class="num">${Number(p.cpu_percent || 0).toFixed(1)}</td>
      <td class="num">${bytes(p.memory_bytes)}</td>
      <td class="num">${p.restart_count ?? 0}</td>
      <td><span class="health ${esc(p.health_status || "unknown")}">${esc(p.health_status || "unknown")}</span></td>
      <td class="actions"></td>`;
    const cell = $(".actions", tr);
    cell.append(
      action(running ? "Restart" : "Start", "restart", false),
      action("Stop", "stop", !running, "danger"),
      action("Reload", "reload", !running),
      action("Logs", "logs", false),
      action("Detail", "detail", false),
    );
    return tr;
  };

  const groupRow = (key, count) => {
    const tr = document.createElement("tr");
    tr.className = "group-row";
    const td = document.createElement("td");
    td.colSpan = 10;
    td.innerHTML = `<span class="group-label">${esc(key)}</span><span class="muted"> (${count})</span>`;
    tr.appendChild(td);
    return tr;
  };

  const table = () => {
    const visible = filtered();
    el.empty.style.display = visible.length ? "none" : "block";
    const frag = document.createDocumentFragment();
    const groups = new Map();
    visible.forEach((p) => {
      const key = p.namespace || "default";
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(p);
    });
    groups.forEach((members, key) => {
      frag.appendChild(groupRow(key, members.length));
      members.forEach((p) => frag.appendChild(row(p)));
    });
    el.tbody.replaceChildren(frag);
  };

  const render = () => { stats(); table(); };

  // --- SSE: processes ---
  let procES = null;
  const procSSE = () => {
    procES?.close();
    spin.show(el.spinner, "proc");
    procES = new EventSource("/api/processes/stream");
    procES.onmessage = (ev) => {
      spin.hide(el.spinner, "proc");
      try {
        state.processes = JSON.parse(ev.data);
        banner.hide();
        groupOptions();
        render();
        el.hint.textContent = "updated " + new Date().toLocaleTimeString();
      } catch (e) { console.error("SSE parse error", e); }
    };
    procES.onerror = () => spin.hide(el.spinner, "proc");
  };

  // --- logs (SSE) ---
  let logES = null;
  const openLogs = (name, stream = "stdout") => {
    Object.assign(state, { logTarget: name, logStream: stream, logActive: true });
    el.logTitle.textContent = `Logs — ${name}`;
    setStreamSeg();
    el.logPre.textContent = "";
    el.logMeta.textContent = "";
    el.logOverlay.classList.add("open");
    startLogSSE();
  };
  const closeLogs = () => {
    el.logOverlay.classList.remove("open");
    Object.assign(state, { logActive: false, logTarget: null });
    stopLogSSE();
  };
  const setStreamSeg = () =>
    el.logSeg.querySelectorAll("button").forEach((b) => b.classList.toggle("active", b.dataset.stream === state.logStream));
  const startLogSSE = () => {
    stopLogSSE();
    el.logPre.textContent = "";
    spin.show(el.logSpinner, "log");
    logES = new EventSource(`/api/processes/${encodeURIComponent(state.logTarget)}/logs/stream?stream=${encodeURIComponent(state.logStream)}`);
    logES.onmessage = (ev) => {
      spin.hide(el.logSpinner, "log");
      el.logPre.className = ["stderr", "error"].includes(state.logStream) ? "stderr" : "";
      if (ev.data) {
        el.logPre.textContent += ev.data + "\n";
        el.logBody.scrollTop = el.logBody.scrollHeight;
      }
    };
    logES.onerror = () => spin.hide(el.logSpinner, "log");
  };
  const stopLogSSE = () => { logES?.close(); logES = null; spin.hide(el.logSpinner, "log"); };

  // --- detail modal ---
  const detailGrid = (rows) => rows.map(([k, v]) => `<div class="k">${esc(k)}</div><div class="v">${esc(v ?? "-")}</div>`).join("");
  const openDetail = (name) => {
    const p = state.processes.find((x) => x.name === name);
    if (!p) return;
    const section = (title, rows) => `<div class="detail-section"><h3>${esc(title)}</h3><div class="detail-grid">${detailGrid(rows)}</div></div>`;
    const base = [
      ["ID", p.id], ["Name", p.name], ["Namespace", p.namespace], ["Status", p.status],
      ["Desired", p.desired_state], ["PID", p.pid], ["Uptime", uptime(p)],
      ["Restarts", `${p.restart_count}/${p.max_restarts}`], ["CPU", `${(Number(p.cpu_percent) || 0).toFixed(1)}%`],
      ["Memory", bytes(p.memory_bytes)],
      ["Command", `${p.command} ${p.args.join(" ")}`], ["CWD", p.cwd],
    ];
    el.detailTitle.textContent = `Process Detail — ${p.name}`;
    el.detailBody.innerHTML =
      section("Overview", base) +
      section("Paths", [["Stdout Log", p.stdout_log], ["Stderr Log", p.stderr_log]]) +
      section("Environment", Object.entries(p.env || {}).length ? Object.entries(p.env) : [["(redacted)", "–"]]) +
      (p.resource_limits ? section("Resource Limits", [
        ["Max Memory", p.resource_limits.max_memory_mb ? `${p.resource_limits.max_memory_mb} MB` : "-"],
        ["Max CPU", p.resource_limits.max_cpu_percent != null ? `${p.resource_limits.max_cpu_percent}%` : "-"],
      ]) : "") +
      (p.health_check ? section("Health Check", [
        ["Command", p.health_check.command],
        ["Interval", `${p.health_check.interval_secs}s / timeout ${p.health_check.timeout_secs}s`],
        ["Max Failures", p.health_check.max_failures],
      ]) : "");
    el.detailOverlay.classList.add("open");
  };
  const closeDetail = () => el.detailOverlay.classList.remove("open");
  const closeOverlays = () => { closeLogs(); closeDetail(); };

  // --- events (delegated + direct) ---
  el.tbody.addEventListener("click", (e) => {
    const btn = e.target.closest("button");
    const tr = e.target.closest("tr[data-name]");
    if (btn) {
      const { target, action } = btn.dataset;
      if (action === "logs") openLogs(target, "stdout");
      else if (action === "detail") openDetail(target);
      else act(target, action, btn);
    } else if (tr) {
      openLogs(tr.dataset.name, "stdout");
    }
  });
  $("#refresh-btn").addEventListener("click", procSSE);
  $("#stop-all-btn").addEventListener("click", () => act("all", "stop"));
  $("#restart-all-btn").addEventListener("click", () => act("all", "restart"));
  $("#detail-close").addEventListener("click", closeDetail);
  $("#log-close").addEventListener("click", closeLogs);
  $("#log-refresh").addEventListener("click", startLogSSE);
  el.logSeg.addEventListener("click", (e) => {
    const b = e.target.closest("button[data-stream]");
    if (!b) return;
    state.logStream = b.dataset.stream;
    setStreamSeg();
    startLogSSE();
  });
  [el.logOverlay, el.detailOverlay].forEach((ov) =>
    ov.addEventListener("click", (e) => { if (e.target === ov) closeOverlays(); }));
  el.search.addEventListener("input", (e) => { state.search = e.target.value; table(); });
  el.group.addEventListener("change", (e) => { state.group = e.target.value; table(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeOverlays(); });
  document.addEventListener("visibilitychange", () => { if (!document.hidden) procSSE(); });

  // --- boot ---
  $("#addr").textContent = "http://" + location.host;
  procSSE();
})();
