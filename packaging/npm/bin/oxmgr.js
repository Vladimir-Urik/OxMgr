#!/usr/bin/env node

const path = require("path");
const fs = require("fs");
const { spawn } = require("child_process");

const exeName = process.platform === "win32" ? "oxmgr.exe" : "oxmgr";
const binPath = path.join(__dirname, "..", "vendor", exeName);

if (!fs.existsSync(binPath)) {
  console.error("oxmgr binary is missing. Reinstall package: npm install oxmgr");
  process.exit(1);
}

const child = spawn(binPath, process.argv.slice(2), {
  stdio: "inherit",
});

child.on("exit", (code, signal) => {
  if (signal) {
    process.kill(process.pid, signal);
    return;
  }
  process.exit(code ?? 1);
});
