import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The daemon embeds dist/ with include_str!, so file names must be fixed and
// fonts inlined (src/daemon/dashboard.rs serves exactly these paths).
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
    assetsInlineLimit: 1024 * 1024,
    cssCodeSplit: false,
    modulePreload: { polyfill: false },
    rollupOptions: {
      output: {
        entryFileNames: "assets/app.js",
        chunkFileNames: "assets/app-[name].js",
        assetFileNames: "assets/app[extname]",
        inlineDynamicImports: true,
      },
    },
  },
  server: {
    // `npm run dev` proxies the API to a daemon started with OXMGR_DASHBOARD=1.
    proxy: {
      "/api": {
        target: process.env.OXMGR_API_URL ?? "http://127.0.0.1:47812",
        ws: true,
        changeOrigin: false,
      },
    },
  },
});
