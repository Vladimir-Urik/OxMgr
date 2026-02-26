const fs = require("fs");
const path = require("path");
const https = require("https");
const crypto = require("crypto");
const { spawnSync } = require("child_process");

const pkg = require("../package.json");

function targetTriple() {
  const key = `${process.platform}-${process.arch}`;
  const map = {
    "linux-x64": { target: "x86_64-unknown-linux-gnu", ext: "tar.gz" },
    "darwin-x64": { target: "x86_64-apple-darwin", ext: "tar.gz" },
    "darwin-arm64": { target: "aarch64-apple-darwin", ext: "tar.gz" },
    "win32-x64": { target: "x86_64-pc-windows-msvc", ext: "zip" }
  };
  return map[key] || null;
}

function repositorySlug() {
  const fromEnv = process.env.OXMGR_NPM_REPOSITORY;
  if (fromEnv) {
    return fromEnv;
  }

  const url = (pkg.repository && pkg.repository.url) || "";
  const match = url.match(/github\.com[/:]([^/]+\/[^/.]+)(?:\.git)?$/i);
  if (!match) {
    throw new Error("Unable to determine GitHub repository slug. Set OXMGR_NPM_REPOSITORY=owner/repo");
  }
  return match[1];
}

function download(url, destination) {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(destination);
    https
      .get(url, (response) => {
        if ([301, 302, 307, 308].includes(response.statusCode)) {
          if (!response.headers.location) {
            reject(new Error(`Redirect without location for ${url}`));
            return;
          }
          file.close();
          fs.rmSync(destination, { force: true });
          download(response.headers.location, destination).then(resolve).catch(reject);
          return;
        }

        if (response.statusCode !== 200) {
          reject(new Error(`Download failed (${response.statusCode}) for ${url}`));
          return;
        }

        response.pipe(file);
        file.on("finish", () => file.close(resolve));
      })
      .on("error", (error) => {
        file.close();
        fs.rmSync(destination, { force: true });
        reject(error);
      });
  });
}

function downloadText(url) {
  return new Promise((resolve, reject) => {
    let data = "";
    https
      .get(url, (response) => {
        if ([301, 302, 307, 308].includes(response.statusCode)) {
          if (!response.headers.location) {
            reject(new Error(`Redirect without location for ${url}`));
            return;
          }
          downloadText(response.headers.location).then(resolve).catch(reject);
          return;
        }

        if (response.statusCode !== 200) {
          reject(new Error(`Download failed (${response.statusCode}) for ${url}`));
          return;
        }

        response.setEncoding("utf8");
        response.on("data", (chunk) => {
          data += chunk;
        });
        response.on("end", () => resolve(data));
      })
      .on("error", reject);
  });
}

function ensureSuccess(result, command) {
  if (result.status !== 0) {
    throw new Error(`${command} failed with exit code ${result.status}`);
  }
}

async function main() {
  const triple = targetTriple();
  if (!triple) {
    throw new Error(`Unsupported platform: ${process.platform}/${process.arch}`);
  }

  const version = pkg.version;
  if (!version || version === "0.0.0-development") {
    throw new Error("Package version is not set for release build");
  }

  const repo = repositorySlug();
  const base = process.env.OXMGR_DIST_BASE || `https://github.com/${repo}/releases/download/v${version}`;
  const archiveName = `oxmgr-v${version}-${triple.target}.${triple.ext}`;
  const archivePath = path.join(__dirname, "..", archiveName);
  const vendorDir = path.join(__dirname, "..", "vendor");

  fs.mkdirSync(vendorDir, { recursive: true });
  const binName = process.platform === "win32" ? "oxmgr.exe" : "oxmgr";

  const downloadUrl = `${base}/${archiveName}`;
  const checksumUrl = `${downloadUrl}.sha256`;
  console.log(`Downloading ${downloadUrl}`);
  await download(downloadUrl, archivePath);

  console.log(`Verifying checksum ${checksumUrl}`);
  const checksumText = await downloadText(checksumUrl);
  const expectedHash = checksumText.trim().split(/\s+/)[0].toLowerCase();
  const actualHash = crypto
    .createHash("sha256")
    .update(fs.readFileSync(archivePath))
    .digest("hex")
    .toLowerCase();

  if (!expectedHash || expectedHash !== actualHash) {
    throw new Error(`Checksum mismatch for ${archiveName}`);
  }

  if (triple.ext === "zip") {
    const unzip = spawnSync(
      "powershell",
      [
        "-NoProfile",
        "-Command",
        `Expand-Archive -Path '${archivePath}' -DestinationPath '${vendorDir}' -Force`
      ],
      { stdio: "inherit" }
    );
    ensureSuccess(unzip, "Expand-Archive");
  } else {
    const untar = spawnSync("tar", ["-xzf", archivePath, "-C", vendorDir], {
      stdio: "inherit"
    });
    ensureSuccess(untar, "tar");
  }

  const installedPath = path.join(vendorDir, binName);
  if (!fs.existsSync(installedPath)) {
    throw new Error(`Archive does not contain ${binName}`);
  }

  if (process.platform !== "win32") {
    fs.chmodSync(installedPath, 0o755);
  }

  fs.rmSync(archivePath, { force: true });
  console.log(`Installed ${installedPath}`);
}

main().catch((error) => {
  console.error(error.message || error);
  process.exit(1);
});
