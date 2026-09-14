"use strict";
// Dashboard for daemon web UI. Inlined by render_dashboard_html.
(() => {
  const EMPTY = "–", UNKNOWN = "unknown";
  const SEC = { DAY: 86400, HOUR: 3600, MINUTE: 60 };
  const BYTE = { KILOBYTE: 1024, UNITS: ["B", "KB", "MB", "GB"], DECIMALS: [0, 0, 1, 1] };
  const LIVE = ["running", "restarting"];
  const SPIN_MS = 400, INT = { MIN: 200, MAX: 10000, DEF: 2000 };
  const STDERR_STREAMS = ["stderr", "error"];
  const ERROR_STATUSES = ["crashed", "errored"];
  const CONFIRM_ACTS = ["restart", "stop", "reload"];
  const ERROR_MAX_LEN = 120;
  const EVENT_STATUS = {
    "process:started": "starting",
    "process:online": "running",
    "process:stopped": "stopped",
    "process:exited": "stopped",
    "process:crashed": "crashed",
    "process:restarting": "restarting",
    "process:errored": "errored",
  };

  const sel = (query, root = document) => root.querySelector(query);
  const clamp = (val, min, max) => Math.max(min, Math.min(max, val));

  // Collect the optional fields a process event may carry, skipping absent ones
  const eventPatch = (event) => {
    const patch = {};
    if (event.process?.pid) patch.pid = event.process.pid;
    if (event.data?.exit_code !== undefined) patch.last_exit_code = event.data.exit_code;
    if (event.data?.restart_count !== undefined) patch.restart_count = event.data.restart_count;
    return patch;
  };

  // Show the environment label in the header, tinted with the configured color
  const applyLabel = (label, color) => {
    if (!label) return;
    const elem = sel("#env-label");
    elem.textContent = label;
    elem.classList.add("visible");
    if (!color) return;
    elem.style.color = color;
    if (color.startsWith("#")) {
      elem.style.borderColor = `${color}4d`;
      elem.style.backgroundColor = `${color}26`;
      return;
    }
    elem.style.borderColor = color.replace(")", ", 0.3)").replace("rgb(", "rgba(");
    elem.style.backgroundColor = color.replace(")", ", 0.15)").replace("rgb(", "rgba(");
  };

  // Pure formatters
  const fmt = {
    esc(val) { const div = document.createElement("div"); div.textContent = val ?? ""; return div.innerHTML; },
    bytes(val) {
      let size = Number(val) || 0, idx = 0;
      while (size >= BYTE.KILOBYTE && idx < 3) { size /= BYTE.KILOBYTE; idx++; }
      return `${size.toFixed(BYTE.DECIMALS[idx])} ${BYTE.UNITS[idx]}`;
    },
    pct: val => (Number(val) || 0).toFixed(1),
    dur(sec) {
      const day = ~~(sec / SEC.DAY);
      if (day) return `${day}d ${~~((sec % SEC.DAY) / SEC.HOUR)}h`;
      const hours = ~~(sec / SEC.HOUR);
      if (hours) return `${hours}h ${~~((sec % SEC.HOUR) / SEC.MINUTE)}m`;
      const min = ~~(sec / SEC.MINUTE);
      return min ? `${min}m ${sec % SEC.MINUTE}s` : `${sec}s`;
    },
    up(proc) {
      if (!LIVE.includes(proc.status) || !proc.last_started_at) return EMPTY;
      return this.dur(Math.max(0, ~~(Date.now() / 1000) - proc.last_started_at));
    },
    time: () => new Date().toLocaleTimeString(),
  };

  // EventBus
  class Bus {
    #subs = new Map();
    on(evt, func) { (this.#subs.get(evt) ?? this.#subs.set(evt, new Set()).get(evt)).add(func); }
    emit(evt, data) { this.#subs.get(evt)?.forEach(func => func(data)); }
  }

  // Filter predicates (pure, one concern each)
  const matchesGroup = (proc, group) => !group || (proc.namespace ?? "") === group;
  const matchesStatus = (proc, status) => !status || proc.status === status;
  const matchesTerm = (proc, term) => !term || `${proc.name} ${proc.id} ${proc.status ?? ""}`.toLowerCase().includes(term);

  // State store
  class Store {
    #bus; #data = { procs: [], search: "", group: "", status: "", interval: INT.DEF };
    constructor(bus) { this.#bus = bus; }
    get(key) { return this.#data[key]; }
    set(key, val) { this.#data[key] = val; this.#bus.emit(`state:${key}`, val); }
    find(name) { return this.#data.procs.find(proc => proc.name === name); }
    visible() {
      const term = this.#data.search.trim().toLowerCase();
      const { group, status } = this.#data;
      return this.#data.procs.filter(proc => matchesGroup(proc, group) && matchesStatus(proc, status) && matchesTerm(proc, term));
    }
    namespaces() { return [...new Set(this.#data.procs.map(proc => proc.namespace).filter(Boolean))].sort(); }
    counts() {
      return this.#data.procs.reduce((cnt, proc) => {
        cnt[proc.status] = (cnt[proc.status] ?? 0) + 1;
        return cnt;
      }, {});
    }
  }

  // Standalone fetch helper (no class dependency)
  const apiRequest = async (path, opts = {}) => {
    const res = await fetch(path, opts);
    const body = await (res.headers.get("content-type")?.includes("json") ? res.json().catch(() => null) : res.text());
    if (!res.ok) throw new Error(body?.message ?? `HTTP ${res.status}`);
    return body;
  };

  // API client
  class Api {
    #bus; #procSrc = null; #logSrc = null; #eventSrc = null;
    constructor(bus) { this.#bus = bus; }
    async action(target, act) {
      this.#bus.emit("act:start", { target, act });
      try {
        const body = await apiRequest(`/api/processes/${encodeURIComponent(target)}/${act}`, { method: "POST" });
        this.#bus.emit("act:done", { msg: body?.message ?? `${act} ok` });
        return body;
      } catch (err) { this.#bus.emit("act:err", { target, act, err: err.message }); throw err; }
    }
    static async config() { try { const res = await fetch("/api/config"); return res.ok ? res.json() : null; } catch { return null; } }
    procStream(interval) {
      this.#procSrc?.close();
      this.#bus.emit("proc:start");
      this.#procSrc = new EventSource(`/api/processes/stream?interval_ms=${interval}`);
      this.#procSrc.onmessage = evt => this.#bus.emit("proc:data", JSON.parse(evt.data));
      this.#procSrc.onerror = () => this.#bus.emit("proc:err");
    }
    // Fetch last 100 lines from the log file so the viewer opens with context
    async #fetchTail(target, stream) {
      try {
        const res = await fetch(`/api/processes/${encodeURIComponent(target)}/logs?stream=${stream}&lines=100`);
        if (!res.ok) return;
        const data = await res.json();
        if (data.lines) this.#bus.emit("log:tail", data.lines);
      } catch { /* ignore fetch errors, continue to stream */ }
    }
    // Subscribe to live log lines via BusEvent
    #subscribeLog(target, stream) {
      const eventType = STDERR_STREAMS.includes(stream) ? "log:err" : "log:out";
      this.#logSrc = new EventSource(`/api/events/stream?subscribe=${encodeURIComponent(eventType)}&process=${encodeURIComponent(target)}`);
      this.#logSrc.onmessage = evt => {
        try {
          const event = JSON.parse(evt.data);
          if (event.data?.line) this.#bus.emit("log:data", event.data.line);
        } catch { /* ignore parse errors */ }
      };
      this.#logSrc.onerror = () => this.#bus.emit("log:err");
    }
    // Fetch tail from log file first, then subscribe to BusEvent stream for new logs
    async logStream(target, stream) {
      this.stopLog();
      this.#bus.emit("log:start");
      await this.#fetchTail(target, stream);
      this.#subscribeLog(target, stream);
    }
    stopLog() { this.#logSrc?.close(); this.#logSrc = null; }
    // Global event stream for process status updates
    eventStream() {
      this.#eventSrc?.close();
      this.#eventSrc = new EventSource(`/api/events/stream?subscribe=${encodeURIComponent("process:*")}`);
      this.#eventSrc.onmessage = evt => {
        try {
          const event = JSON.parse(evt.data);
          this.#bus.emit("event:process", event);
        } catch { /* ignore */ }
      };
    }
    stopEvents() { this.#eventSrc?.close(); this.#eventSrc = null; }
  }

  // Spinner with delay
  class Spin {
    #timers = new Map();
    show(elem, key) { clearTimeout(this.#timers.get(key)); this.#timers.set(key, setTimeout(() => elem.classList.add("on"), SPIN_MS)); }
    hide(elem, key) { clearTimeout(this.#timers.get(key)); this.#timers.delete(key); elem.classList.remove("on"); }
  }

  // Modal base
  class Modal {
    constructor(overlay, panel) {
      this.overlay = overlay;
      this.panel = panel;
      this.#initFullscreen();
      this.#initResize();
    }
    #initFullscreen() {
      const header = this.panel.querySelector(".log-head");
      if (header) {
        header.addEventListener("dblclick", evt => {
          if (!evt.target.closest("button")) this.panel.classList.toggle("fullscreen");
        });
      }
    }
    #initResize() {
      const handles = ['n', 's', 'e', 'w', 'nw', 'ne', 'sw', 'se'];
      handles.forEach(dir => {
        const handle = document.createElement('div');
        handle.className = `resize-handle resize-handle-${dir}`;
        handle.dataset.resize = dir;
        this.panel.appendChild(handle);
      });
      this.panel.addEventListener('mousedown', this.#onResizeStart.bind(this));
    }
    #onResizeStart(evt) {
      const handle = evt.target.closest('.resize-handle');
      if (!handle || this.panel.classList.contains('fullscreen')) return;
      evt.preventDefault();
      const dir = handle.dataset.resize;
      const rect = this.panel.getBoundingClientRect();
      const startX = evt.clientX, startY = evt.clientY;
      const startW = rect.width, startH = rect.height;
      const minW = 320, minH = 200;
      const maxW = window.innerWidth * 0.98, maxH = window.innerHeight * 0.98;

      const onMove = (e) => {
        const dx = e.clientX - startX, dy = e.clientY - startY;
        let newW = startW, newH = startH;
        if (dir.includes('e')) newW = clamp(startW + dx, minW, maxW);
        if (dir.includes('w')) newW = clamp(startW - dx, minW, maxW);
        if (dir.includes('s')) newH = clamp(startH + dy, minH, maxH);
        if (dir.includes('n')) newH = clamp(startH - dy, minH, maxH);
        this.panel.style.width = `${newW}px`;
        this.panel.style.height = `${newH}px`;
      };
      const onUp = () => {
        document.removeEventListener('mousemove', onMove);
        document.removeEventListener('mouseup', onUp);
      };
      document.addEventListener('mousemove', onMove);
      document.addEventListener('mouseup', onUp);
    }
    open() { this.overlay.classList.add("open"); }
    close() { this.overlay.classList.remove("open"); this.panel.classList.remove("fullscreen"); }
  }

  // Log modal with virtual scroll
  class LogModal extends Modal {
    #api; #spin; #bus; target = null; stream = "stdout";
    #lines = []; #lineHeight = 18; #visibleCount = 0; #scrollTop = 0; #autoScroll = true;
    constructor(overlay, panel, api, bus, spin) {
      super(overlay, panel);
      this.#api = api; this.#bus = bus; this.#spin = spin;
      this.els = {
        title: sel("#log-title"),
        body: sel("#log-body"),
        meta: sel("#log-meta"),
        spin: sel("#log-spinner"),
        seg: sel("#log-stream-seg"),
        viewport: null,
        content: null,
        spacerTop: null,
        spacerBottom: null,
      };
      this.#setupVirtualScroll();
      this.#bind();
    }
    #setupVirtualScroll() {
      // Replace <pre> with virtual scroll structure
      const oldPre = sel("#log-body pre");
      if (oldPre) oldPre.remove();

      this.els.viewport = document.createElement("div");
      this.els.viewport.className = "log-viewport";

      this.els.spacerTop = document.createElement("div");
      this.els.spacerTop.className = "log-spacer-top";

      this.els.content = document.createElement("pre");
      this.els.content.className = "log-content";

      this.els.spacerBottom = document.createElement("div");
      this.els.spacerBottom.className = "log-spacer-bottom";

      this.els.viewport.append(this.els.spacerTop, this.els.content, this.els.spacerBottom);
      this.els.body.appendChild(this.els.viewport);

      this.els.body.addEventListener("scroll", () => this.#onScroll());
    }
    #onScroll() {
      const st = this.els.body.scrollTop;
      const atBottom = this.els.body.scrollHeight - this.els.body.clientHeight - st < 50;
      this.#autoScroll = atBottom;
      if (Math.abs(st - this.#scrollTop) > this.#lineHeight) {
        this.#scrollTop = st;
        this.#render();
      }
    }
    #render() {
      const viewportHeight = this.els.body.clientHeight;
      this.#visibleCount = Math.ceil(viewportHeight / this.#lineHeight) + 10; // buffer
      const startIdx = Math.max(0, Math.floor(this.#scrollTop / this.#lineHeight) - 5);
      const endIdx = Math.min(this.#lines.length, startIdx + this.#visibleCount);

      this.els.spacerTop.style.height = `${startIdx * this.#lineHeight}px`;
      this.els.spacerBottom.style.height = `${Math.max(0, (this.#lines.length - endIdx) * this.#lineHeight)}px`;
      this.els.content.textContent = this.#lines.slice(startIdx, endIdx).join("\n");

      // Update line count in meta
      const base = `${this.stream} · tail, then live`;
      this.els.meta.textContent = this.#lines.length > 0 ? `${base} · ${this.#lines.length} lines` : base;
    }
    #scrollToBottom() {
      if (this.#autoScroll) {
        this.els.body.scrollTop = this.els.body.scrollHeight;
      }
    }
    #addLines(newLines) {
      if (!newLines || !newLines.length) return;
      const arr = Array.isArray(newLines) ? newLines : newLines.split("\n").filter(l => l);
      this.#lines.push(...arr);
      // Cap at 10000 lines to prevent memory issues
      if (this.#lines.length > 10000) {
        this.#lines = this.#lines.slice(-10000);
      }
      this.#render();
      this.#scrollToBottom();
    }
    #bind() {
      this.#bus.on("log:tail", lines => {
        this.#spin.hide(this.els.spin, "log");
        this.#lines = Array.isArray(lines) ? [...lines] : (lines ? lines.split("\n").filter(l => l) : []);
        this.#autoScroll = true;
        this.#render();
        this.#scrollToBottom();
      });
      this.#bus.on("log:data", line => { if (line) this.#addLines([line]); });
      this.#bus.on("log:err", () => this.#spin.hide(this.els.spin, "log"));
      this.els.seg.addEventListener("click", evt => { const btn = evt.target.closest("button[data-stream]"); if (!btn) return; this.stream = btn.dataset.stream; this.#highlight(); this.#start(); });
      sel("#log-close").addEventListener("click", () => this.close());
      sel("#log-refresh").addEventListener("click", () => this.#start());
    }
    #highlight() { this.els.seg.querySelectorAll("button").forEach(btn => btn.classList.toggle("active", btn.dataset.stream === this.stream)); }
    #start() {
      this.#lines = [];
      this.#autoScroll = true;
      this.els.content.className = this.stream === "stdout" ? "log-content" : "log-content stderr";
      this.els.meta.textContent = `${this.stream} · tail, then live`;
      this.#render();
      this.#spin.show(this.els.spin, "log");
      this.#api.logStream(this.target, this.stream);
    }
    show(name, stream = "stdout") {
      this.target = name; this.stream = stream;
      this.els.title.textContent = `Logs — ${name}`;
      this.#highlight(); this.open(); this.#start();
    }
    close() { super.close(); this.target = null; this.#lines = []; this.#api.stopLog(); }
  }

  // Detail modal helpers (pure functions)
  const detailGrid = (rows) => rows.map(([key, val]) => `<div class="k">${fmt.esc(key)}</div><div class="v">${fmt.esc(val ?? "-")}</div>`).join("");
  const detailSection = (title, rows) => `<div class="detail-section"><h3>${fmt.esc(title)}</h3><div class="detail-grid">${detailGrid(rows)}</div></div>`;
  const detailErrorSection = (error) => `<div class="detail-section error-section"><h3>Last Error</h3><pre class="error-pre">${fmt.esc(error)}</pre></div>`;
  const detailOverview = (proc) => detailSection("Overview", [["ID", proc.id], ["Name", proc.name], ["Namespace", proc.namespace], ["Status", proc.status], ["Desired", proc.desired_state], ["PID", proc.pid],
    ["Uptime", fmt.up(proc)], ["Restarts", `${proc.restart_count}/${proc.max_restarts}`], ["CPU", `${fmt.pct(proc.cpu_percent)}%`], ["Memory", fmt.bytes(proc.memory_bytes)],
    ["Command", `${proc.command} ${(proc.args ?? []).join(" ")}`], ["CWD", proc.cwd], ["Exit Code", proc.last_exit_code]]);
  const detailEnv = (proc) => detailSection("Environment", Object.keys(proc.env ?? {}).length ? Object.entries(proc.env) : [["(redacted)", EMPTY]]);
  const detailLimits = (lim) => detailSection("Resource Limits", [["Max Memory", lim.max_memory_mb ? `${lim.max_memory_mb} MB` : "-"], ["Max CPU", lim.max_cpu_percent == null ? "-" : `${lim.max_cpu_percent}%`]]);
  const detailHealth = (hck) => detailSection("Health Check", [["Command", hck.command], ["Interval", `${hck.interval_secs}s / timeout ${hck.timeout_secs}s`], ["Max Failures", hck.max_failures]]);
  const detailBody = (proc) => {
    const sections = [
      detailOverview(proc),
      detailSection("Paths", [["Stdout Log", proc.stdout_log], ["Stderr Log", proc.stderr_log]]),
    ];
    if (proc.last_error) sections.push(detailErrorSection(proc.last_error));
    sections.push(detailEnv(proc));
    if (proc.resource_limits) sections.push(detailLimits(proc.resource_limits));
    if (proc.health_check) sections.push(detailHealth(proc.health_check));
    return sections.join("");
  };

  // Detail modal
  class DetailModal extends Modal {
    #store;
    constructor(overlay, panel, store) {
      super(overlay, panel);
      this.#store = store;
      this.els = { title: sel("#detail-title"), body: sel("#detail-body") };
      sel("#detail-close").addEventListener("click", () => this.close());
    }
    show(name) {
      const proc = this.#store.find(name);
      if (!proc) return;
      this.els.title.textContent = `Process Detail — ${proc.name}`;
      this.els.body.innerHTML = detailBody(proc);
      this.open();
    }
  }

  // Confirm modal
  class ConfirmModal {
    #overlay; #panel; #resolve = null;
    constructor(overlay) {
      this.#overlay = overlay;
      this.#panel = sel(".confirm-panel", overlay);
      this.els = { title: sel("#confirm-title"), message: sel("#confirm-message"), okBtn: sel("#confirm-ok") };
      sel("#confirm-cancel").addEventListener("click", () => this.#respond(false));
      sel("#confirm-ok").addEventListener("click", () => this.#respond(true));
      this.#overlay.addEventListener("click", evt => { if (evt.target === this.#overlay) this.#respond(false); });
    }
    #respond(result) {
      this.#overlay.classList.remove("open");
      if (this.#resolve) { this.#resolve(result); this.#resolve = null; }
    }
    confirm(action, target) {
      const isAll = target === "all";
      const actionLabel = action.charAt(0).toUpperCase() + action.slice(1);
      this.els.title.textContent = `${actionLabel} ${isAll ? "All Processes" : target}?`;
      this.els.message.textContent = isAll
        ? `This will ${action} ALL running processes. This action may cause service disruption.`
        : `Are you sure you want to ${action} "${target}"?`;
      this.els.okBtn.textContent = actionLabel;
      this.els.okBtn.className = ["stop", "restart"].includes(action) ? "small danger" : "small";
      this.#overlay.classList.add("open");
      return new Promise(resolve => { this.#resolve = resolve; });
    }
  }

  // Stats view
  class Stats {
    #elem; #store; #bus;
    static CHIPS = [{ status: "running", cls: "ok" }, { status: "restarting", cls: "warn" }, { status: "stopped", cls: "" }, { status: "crashed", cls: "bad" }, { status: "errored", cls: "bad" }];
    constructor(elem, store, bus) { this.#elem = elem; this.#store = store; this.#bus = bus; this.#bind(); }
    #bind() {
      this.#elem.addEventListener("click", evt => {
        const chip = evt.target.closest(".stat");
        if (!chip) return;
        const status = chip.dataset.status || "";
        const current = this.#store.get("status");
        this.#store.set("status", current === status ? "" : status);
        this.#bus.emit("filter:changed");
      });
    }
    #chip(label, num, cls, status) {
      const active = this.#store.get("status") === status ? " active" : "";
      return `<span class="stat ${cls}${active}" data-status="${status}"><b>${num}</b> ${label}</span>`;
    }
    render() {
      const counts = this.#store.counts();
      this.#elem.innerHTML = this.#chip("total", this.#store.get("procs").length, "", "") + Stats.CHIPS.map(chip => this.#chip(chip.status, counts[chip.status] ?? 0, chip.cls, chip.status)).join("");
    }
  }

  // Table helper functions (pure, no class dependency)
  const tableBtn = (proc, { label, act, cls, run }) => {
    const btn = document.createElement("button");
    btn.className = cls ? `small ${cls}` : "small";
    btn.textContent = label; btn.disabled = run && proc.status !== "running";
    btn.dataset.target = proc.name; btn.dataset.action = act;
    return btn;
  };
  const tableCells = (proc) => {
    const view = { status: proc.status || UNKNOWN, pid: proc.pid ?? EMPTY, restarts: proc.restart_count ?? 0, health: proc.health_status || UNKNOWN };
    return `<td><span class="badge"><span class="dot ${fmt.esc(proc.status)}"></span>${fmt.esc(view.status)}</span></td>
      <td class="name-cell">${fmt.esc(proc.name)}</td><td class="num">${fmt.esc(proc.id)}</td><td class="num">${fmt.esc(view.pid)}</td>
      <td>${fmt.esc(fmt.up(proc))}</td><td class="num">${fmt.esc(fmt.pct(proc.cpu_percent))}</td><td class="num">${fmt.esc(fmt.bytes(proc.memory_bytes))}</td>
      <td class="num">${fmt.esc(view.restarts)}</td><td><span class="health ${fmt.esc(view.health)}">${fmt.esc(view.health)}</span></td><td class="actions"></td>`;
  };
  // Reduce a raw last_error into a single-line summary for the inline error row
  const errorSummary = (lastError) => {
    // Prefer the "Last stderr:" portion when present
    const stderrMatch = lastError.match(/Last stderr:\n?([\s\S]*)/);
    const errorText = stderrMatch ? stderrMatch[1].trim() : lastError.split("\n")[0];
    const firstLine = errorText.split("\n")[0];
    return {
      text: firstLine.slice(0, ERROR_MAX_LEN),
      ellipsis: errorText.length > ERROR_MAX_LEN ? "\u2026" : "",
    };
  };
  const tableErrorRow = (proc) => {
    if (!proc.last_error || !ERROR_STATUSES.includes(proc.status)) return null;
    const row = document.createElement("tr");
    row.className = "error-row";
    const cell = document.createElement("td");
    cell.colSpan = 10;
    const { text, ellipsis } = errorSummary(proc.last_error);
    cell.innerHTML = `<span class="error-inline"><span class="error-icon">\u26a0</span> ${fmt.esc(text)}${ellipsis} <a href="#" class="error-detail-link" data-name="${fmt.esc(proc.name)}">View detail</a></span>`;
    row.appendChild(cell);
    return row;
  };
  const tableRow = (proc) => {
    const row = document.createElement("tr");
    row.className = "clickable"; row.dataset.name = proc.name; row.innerHTML = tableCells(proc);
    const restartBtn = tableBtn(proc, { label: proc.status === "running" ? "Restart" : "Start", act: "restart" });
    sel(".actions", row).append(restartBtn, ...Table.ACTS.map(spec => tableBtn(proc, spec)));
    return row;
  };
  const tableGroupRow = (name, count) => {
    const row = document.createElement("tr"); row.className = "group-row";
    const cell = document.createElement("td"); cell.colSpan = 10;
    cell.innerHTML = `<span class="group-label">${fmt.esc(name)}</span><span class="muted"> (${count})</span>`;
    row.appendChild(cell); return row;
  };

  // Table view
  class Table {
    #tbody; #empty; #store; #bus;
    static ACTS = [{ label: "Stop", act: "stop", cls: "danger", run: 1 }, { label: "Reload", act: "reload", run: 1 }, { label: "Logs", act: "logs" }, { label: "Detail", act: "detail" }];
    constructor(tbody, empty, store, bus) { this.#tbody = tbody; this.#empty = empty; this.#store = store; this.#bus = bus; }
    render() {
      const visible = this.#store.visible();
      this.#empty.style.display = visible.length ? "none" : "block";
      const groups = new Map();
      visible.forEach(proc => { const key = proc.namespace || "default"; (groups.get(key) ?? groups.set(key, []).get(key)).push(proc); });
      const frag = document.createDocumentFragment();
      groups.forEach((members, name) => {
        frag.appendChild(tableGroupRow(name, members.length));
        members.forEach(proc => {
          frag.appendChild(tableRow(proc));
          const errRow = tableErrorRow(proc);
          if (errRow) frag.appendChild(errRow);
        });
      });
      this.#tbody.replaceChildren(frag);
    }
  }

  // Group select
  class GroupSel {
    #elem; #store;
    constructor(elem, store) { this.#elem = elem; this.#store = store; }
    render() {
      const namespaces = this.#store.namespaces(), selected = this.#elem.value;
      const options = namespaces.map(nsp => `<option value="${fmt.esc(nsp)}">${fmt.esc(nsp)}</option>`).join("");
      this.#elem.innerHTML = `<option value="">All groups</option>${options}`;
      this.#elem.value = namespaces.includes(selected) ? selected : "";
      this.#store.set("group", this.#elem.value);
    }
  }

  // Main controller
  class App {
    constructor() {
      this.bus = new Bus();
      this.store = new Store(this.bus);
      this.api = new Api(this.bus);
      this.spin = new Spin();
      this.banner = { elem: sel("#error-banner"), show(msg) { this.elem.style.display = "block"; this.elem.textContent = msg; }, hide() { this.elem.style.display = "none"; } };
      this.stats = new Stats(sel("#stats"), this.store, this.bus);
      this.table = new Table(sel("#tbody"), sel("#empty-state"), this.store, this.bus);
      this.grpSel = new GroupSel(sel("#group-select"), this.store);
      const logOverlay = sel("#log-overlay");
      const detailOverlay = sel("#detail-overlay");
      this.logModal = new LogModal(logOverlay, sel(".log-panel", logOverlay), this.api, this.bus, this.spin);
      this.detailModal = new DetailModal(detailOverlay, sel(".detail-panel", detailOverlay), this.store);
      this.confirmModal = new ConfirmModal(sel("#confirm-overlay"));
      this.hint = sel("#updated-hint");
      this.spinEl = sel("#refresh-spinner");
      this.#bind();
    }
    #bind() {
      this.bus.on("proc:start", () => this.spin.show(this.spinEl, "proc"));
      this.bus.on("proc:data", procs => {
        this.spin.hide(this.spinEl, "proc");
        this.store.set("procs", procs);
        this.banner.hide();
        this.grpSel.render();
        this.#render();
        this.hint.textContent = `updated ${fmt.time()}`;
      });
      this.bus.on("proc:err", () => this.spin.hide(this.spinEl, "proc"));
      this.bus.on("act:done", ({ msg }) => { this.hint.textContent = msg; });
      this.bus.on("act:err", ({ target, act, err }) => this.banner.show(`Action ${act} on ${target} failed: ${err}`));
      this.bus.on("filter:changed", () => this.#render());

      // Real-time process status updates via BusEvent
      this.bus.on("event:process", event => this.#onProcessEvent(event));

      sel("#tbody").addEventListener("click", evt => this.#onTableClick(evt));

      sel("#refresh-btn").addEventListener("click", () => this.#stream());
      sel("#stop-all-btn").addEventListener("click", () => {
        this.confirmModal.confirm("stop", "all").then(ok => { if (ok) this.api.action("all", "stop"); });
      });
      sel("#restart-all-btn").addEventListener("click", () => {
        this.confirmModal.confirm("restart", "all").then(ok => { if (ok) this.api.action("all", "restart"); });
      });
      sel("#search-input").addEventListener("input", evt => { this.store.set("search", evt.target.value); this.table.render(); });
      sel("#group-select").addEventListener("change", evt => { this.store.set("group", evt.target.value); this.table.render(); });

      [sel("#log-overlay"), sel("#detail-overlay")].forEach(overlay => overlay.addEventListener("click", evt => { if (evt.target === overlay) this.#closeAll(); }));
      document.addEventListener("keydown", evt => { if (evt.key === "Escape") this.#closeAll(); });
      document.addEventListener("visibilitychange", () => { if (!document.hidden) this.#stream(); });
    }
    #closeAll() { this.logModal.close(); this.detailModal.close(); }
    #render() { this.stats.render(); this.table.render(); }
    #stream() { this.api.procStream(this.store.get("interval")); }
    // Apply a status update from a BusEvent onto the matching process in the store
    #onProcessEvent(event) {
      const name = event.process?.name;
      const newStatus = EVENT_STATUS[event.event];
      if (!name || !newStatus) return;
      const procs = this.store.get("procs");
      const idx = procs.findIndex(proc => proc.name === name);
      if (idx === -1 || procs[idx].status === newStatus) return;
      procs[idx] = { ...procs[idx], status: newStatus, ...eventPatch(event) };
      this.store.set("procs", [...procs]);
      this.#render();
      this.hint.textContent = `${name}: ${newStatus} · ${fmt.time()}`;
    }
    // Route a click inside the table to the right target: error link, action button, or row
    #onTableClick(evt) {
      const detailLink = evt.target.closest(".error-detail-link");
      if (detailLink) {
        evt.preventDefault();
        this.detailModal.show(detailLink.dataset.name);
        return;
      }
      const btn = evt.target.closest("button");
      if (btn) { this.#runAction(btn.dataset); return; }
      const row = evt.target.closest("tr[data-name]");
      if (row) this.logModal.show(row.dataset.name);
    }
    #runAction({ target, action }) {
      if (action === "logs") this.logModal.show(target);
      else if (action === "detail") this.detailModal.show(target);
      else if (CONFIRM_ACTS.includes(action)) this.#confirmAction(action, target);
    }
    #confirmAction(action, target) {
      this.confirmModal.confirm(action, target).then(ok => { if (ok) this.api.action(target, action); });
    }
    async init() {
      const params = new URLSearchParams(location.search);
      const urlInt = parseInt(params.get("interval_ms"), 10);
      const cfg = await Api.config();
      if (!Number.isNaN(urlInt)) this.store.set("interval", clamp(urlInt, INT.MIN, INT.MAX));
      else if (cfg?.interval_ms) this.store.set("interval", clamp(cfg.interval_ms, INT.MIN, INT.MAX));
      if (cfg?.label) applyLabel(cfg.label, cfg.label_color);
      this.#stream();
      this.api.eventStream(); // Subscribe to real-time process events
    }
  }

  sel("#addr").textContent = `http://${location.host}`;
  new App().init();
})();
