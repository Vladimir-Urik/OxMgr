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
  const esc = (str) => {
    const div = document.createElement("div");
    div.textContent = str == null ? "" : String(str);
    return div.innerHTML;
  };
  const bytes = (bytesVal) => {
    bytesVal = Number(bytesVal) || 0;
    const units = ["B", "KB", "MB", "GB"];
    let idx = 0;
    while (bytesVal >= 1024 && idx < units.length - 1) { bytesVal /= 1024; idx++; }
    return `${idx ? bytesVal.toFixed(idx > 1 ? 1 : 0) : bytesVal} ${units[idx]}`;
  };
  const uptime = (proc) => {
    if (!["running", "restarting"].includes(proc.status) || !proc.last_started_at) return "–";
    const secs = Math.max(0, Math.floor(Date.now() / 1000) - proc.last_started_at);
    const days = Math.floor(secs / 86400), hours = Math.floor((secs % 86400) / 3600),
      mins = Math.floor((secs % 3600) / 60), sec = secs % 60;
    return days > 0 ? `${days}d ${hours}h` : hours > 0 ? `${hours}h ${mins}m` : mins > 0 ? `${mins}m ${sec}s` : `${sec}s`;
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
    if (!res.ok) throw new Error(data?.message || `HTTP ${res.status}`);
    return data;
  }

  const act = async (target, action, btn) => {
    btn?.classList.add("busy");
    try {
      const data = await api(`/api/processes/${encodeURIComponent(target)}/${action}`, { method: "POST" });
      el.hint.textContent = data?.message || `${action} ok`;
    } catch (e) {
      banner.show(`Action ${action} on ${target} failed: ${e.message}`);
    } finally {
      btn?.classList.remove("busy");
    }
  };

  // --- rendering ---
  const filtered = () => {
    const term = state.search.trim().toLowerCase();
    return state.processes.filter((proc) =>
      (!state.group || (proc.namespace || "") === state.group) &&
      (!term || proc.name.toLowerCase().includes(term) || String(proc.id).includes(term) || String(proc.status || "").includes(term))
    );
  };

  const groupOptions = () => {
    const groups = [...new Set(state.processes.map((proc) => proc.namespace).filter(Boolean))].sort();
    const cur = el.group.value;
    el.group.innerHTML = `<option value="">All groups</option>${groups.map((grp) => `<option value="${esc(grp)}">${esc(grp)}</option>`).join("")}`;
    el.group.value = groups.includes(cur) ? cur : "";
    state.group = el.group.value;
  };

  const stats = () => {
    const by = state.processes.reduce((acc, proc) => { acc[proc.status] = (acc[proc.status] || 0) + 1; return acc; }, {});
    const chip = (label, count, cls) => `<span class="stat ${cls}"><b>${count}</b> ${label}</span>`;
    el.stats.innerHTML =
      chip("total", state.processes.length, "") +
      chip("running", by.running || 0, "ok") +
      chip("restarting", by.restarting || 0, "warn") +
      chip("stopped", by.stopped || 0, "") +
      chip("crashed", by.crashed || 0, "bad") +
      chip("errored", by.errored || 0, "bad");
  };

  const row = (proc) => {
    const running = proc.status === "running";
    const action = (label, cmd, disabled, cls) => {
      const btn = document.createElement("button");
      btn.className = `small${cls ? ` ${cls}` : ""}`;
      btn.textContent = label;
      btn.disabled = Boolean(disabled);
      btn.dataset.target = proc.name;
      btn.dataset.action = cmd;
      return btn;
    };
    const tr = document.createElement("tr");
    tr.className = "clickable";
    tr.dataset.name = proc.name;
    tr.innerHTML = `
      <td><span class="badge"><span class="dot ${esc(proc.status)}"></span>${esc(proc.status || "unknown")}</span></td>
      <td class="name-cell">${esc(proc.name)}</td>
      <td class="num">${proc.id}</td>
      <td class="num">${proc.pid ?? "–"}</td>
      <td>${uptime(proc)}</td>
      <td class="num">${Number(proc.cpu_percent || 0).toFixed(1)}</td>
      <td class="num">${bytes(proc.memory_bytes)}</td>
      <td class="num">${proc.restart_count ?? 0}</td>
      <td><span class="health ${esc(proc.health_status || "unknown")}">${esc(proc.health_status || "unknown")}</span></td>
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
    visible.forEach((proc) => {
      const key = proc.namespace || "default";
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(proc);
    });
    groups.forEach((members, key) => {
      frag.appendChild(groupRow(key, members.length));
      members.forEach((proc) => frag.appendChild(row(proc)));
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
        el.hint.textContent = `updated ${new Date().toLocaleTimeString()}`;
      } catch (e) { console.error("SSE parse error", e); }
    };
    procES.onerror = () => spin.hide(el.spinner, "proc");
  };

  // --- logs (SSE) ---
  let logES = null;
  const setStreamSeg = () =>
    el.logSeg.querySelectorAll("button").forEach((btn) => btn.classList.toggle("active", btn.dataset.stream === state.logStream));
  const stopLogSSE = () => { logES?.close(); logES = null; spin.hide(el.logSpinner, "log"); };
  const startLogSSE = () => {
    stopLogSSE();
    el.logPre.textContent = "";
    spin.show(el.logSpinner, "log");
    logES = new EventSource(`/api/processes/${encodeURIComponent(state.logTarget)}/logs/stream?stream=${encodeURIComponent(state.logStream)}`);
    logES.onmessage = (ev) => {
      spin.hide(el.logSpinner, "log");
      el.logPre.className = ["stderr", "error"].includes(state.logStream) ? "stderr" : "";
      if (ev.data) {
        el.logPre.textContent += `${ev.data}\n`;
        el.logBody.scrollTop = el.logBody.scrollHeight;
      }
    };
    logES.onerror = () => spin.hide(el.logSpinner, "log");
  };
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

  // --- detail modal ---
  const detailGrid = (rows) => rows.map(([k, v]) => `<div class="k">${esc(k)}</div><div class="v">${esc(v ?? "-")}</div>`).join("");
  const openDetail = (name) => {
    const proc = state.processes.find((candidate) => candidate.name === name);
    if (!proc) return;
    const section = (title, rows) => `<div class="detail-section"><h3>${esc(title)}</h3><div class="detail-grid">${detailGrid(rows)}</div></div>`;
    const base = [
      ["ID", proc.id], ["Name", proc.name], ["Namespace", proc.namespace], ["Status", proc.status],
      ["Desired", proc.desired_state], ["PID", proc.pid], ["Uptime", uptime(proc)],
      ["Restarts", `${proc.restart_count}/${proc.max_restarts}`], ["CPU", `${(Number(proc.cpu_percent) || 0).toFixed(1)}%`],
      ["Memory", bytes(proc.memory_bytes)],
      ["Command", `${proc.command} ${proc.args.join(" ")}`], ["CWD", proc.cwd],
    ];
    el.detailTitle.textContent = `Process Detail — ${proc.name}`;
    el.detailBody.innerHTML =
      section("Overview", base) +
      section("Paths", [["Stdout Log", proc.stdout_log], ["Stderr Log", proc.stderr_log]]) +
      section("Environment", Object.entries(proc.env || {}).length ? Object.entries(proc.env) : [["(redacted)", "–"]]) +
      (proc.resource_limits ? section("Resource Limits", [
        ["Max Memory", proc.resource_limits.max_memory_mb ? `${proc.resource_limits.max_memory_mb} MB` : "-"],
        ["Max CPU", proc.resource_limits.max_cpu_percent != null ? `${proc.resource_limits.max_cpu_percent}%` : "-"],
      ]) : "") +
      (proc.health_check ? section("Health Check", [
        ["Command", proc.health_check.command],
        ["Interval", `${proc.health_check.interval_secs}s / timeout ${proc.health_check.timeout_secs}s`],
        ["Max Failures", proc.health_check.max_failures],
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
    const btn = e.target.closest("button[data-stream]");
    if (!btn) return;
    state.logStream = btn.dataset.stream;
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
  $("#addr").textContent = `http://${location.host}`;
  procSSE();
})();
