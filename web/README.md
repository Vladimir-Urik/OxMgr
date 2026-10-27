# oxmgr web dashboard

React + TypeScript app served by the oxmgr daemon when `OXMGR_DASHBOARD=1`.
The daemon embeds `dist/` at compile time (`src/daemon/dashboard.rs`), so the
build output is committed and `cargo build` works without Node.js.

```bash
npm ci
npm run build   # tsc --noEmit && vite build → dist/
npm run dev     # hot reload, proxies /api (and the WebSocket) to OXMGR_API_URL
```

Keep the output names fixed (`assets/app.js`, `assets/app.css`): the daemon
serves exactly those paths. Fonts are inlined into `app.css`.

See [docs/UI.md](../docs/UI.md#web-dashboard) for the API, WebSocket messages
and security model.
