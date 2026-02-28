#!/usr/bin/env python3

from __future__ import annotations

import argparse
import datetime as dt
import html
import json
import os
import pathlib
import re
import urllib.error
import urllib.parse
import urllib.request


USER_AGENT = "oxmgr-download-metrics/1.0"
TIMEOUT_SECONDS = 30

ASSET_LABELS = {
    "linux_tarball": "Linux tar.gz",
    "mac_intel_tarball": "macOS Intel tar.gz",
    "mac_arm_tarball": "macOS Apple Silicon tar.gz",
    "windows_zip": "Windows zip",
    "deb_package": "Debian .deb",
    "other": "Other release asset",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate a static download metrics dashboard."
    )
    parser.add_argument("--repo", required=True, help="GitHub repository slug, e.g. owner/repo")
    parser.add_argument("--output-dir", required=True, help="Directory to write the site files into")
    parser.add_argument("--pages-base-url", required=True, help="Canonical GitHub Pages base URL")
    parser.add_argument("--choco-package", default="", help="Chocolatey package name to scrape")
    parser.add_argument(
        "--brew-formula",
        default="",
        help="Homebrew formula token for formulae.brew.sh lookups when available",
    )
    return parser


def http_get(url: str, headers: dict[str, str] | None = None) -> tuple[str, urllib.response.addinfourl]:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/json, text/html;q=0.9, */*;q=0.8",
            **(headers or {}),
        },
    )
    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
        encoding = response.headers.get_content_charset() or "utf-8"
        body = response.read().decode(encoding, "replace")
        return body, response


def http_get_json(url: str, headers: dict[str, str] | None = None) -> object:
    body, _ = http_get(url, headers=headers)
    return json.loads(body)


def github_headers() -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def is_payload_asset(name: str) -> bool:
    if name == "SHA256SUMS" or name == "SHA256SUMS.asc":
        return False
    if name.endswith(".sha256") or name.endswith(".sha256.asc"):
        return False
    if name.endswith(".asc"):
        return False
    return True


def classify_asset(name: str) -> str:
    if name.endswith("x86_64-unknown-linux-gnu.tar.gz"):
        return "linux_tarball"
    if name.endswith("x86_64-apple-darwin.tar.gz"):
        return "mac_intel_tarball"
    if name.endswith("aarch64-apple-darwin.tar.gz"):
        return "mac_arm_tarball"
    if name.endswith("x86_64-pc-windows-msvc.zip"):
        return "windows_zip"
    if re.search(r"_amd64\.deb$", name):
        return "deb_package"
    return "other"


def fetch_github_releases(repo: str) -> list[dict[str, object]]:
    releases: list[dict[str, object]] = []
    page = 1
    while True:
        url = f"https://api.github.com/repos/{repo}/releases?per_page=100&page={page}"
        payload = http_get_json(url, headers=github_headers())
        if not isinstance(payload, list):
            raise RuntimeError(f"Unexpected GitHub releases response for {repo}")
        if not payload:
            break
        releases.extend(payload)
        if len(payload) < 100:
            break
        page += 1
    return [release for release in releases if not release.get("draft")]


def fetch_github_metrics(repo: str) -> dict[str, object]:
    releases = fetch_github_releases(repo)
    asset_totals: dict[str, int] = {key: 0 for key in ASSET_LABELS}
    release_rows: list[dict[str, object]] = []
    total_payload_downloads = 0

    for release in releases:
        assets = release.get("assets", [])
        if not isinstance(assets, list):
            continue

        row_counts: dict[str, int] = {key: 0 for key in ASSET_LABELS}
        payload_assets = []

        for asset in assets:
            if not isinstance(asset, dict):
                continue

            name = str(asset.get("name", ""))
            if not name or not is_payload_asset(name):
                continue

            download_count = int(asset.get("download_count", 0) or 0)
            browser_download_url = str(asset.get("browser_download_url", ""))
            kind = classify_asset(name)

            asset_totals[kind] += download_count
            row_counts[kind] += download_count
            total_payload_downloads += download_count

            payload_assets.append(
                {
                    "name": name,
                    "kind": kind,
                    "label": ASSET_LABELS[kind],
                    "download_count": download_count,
                    "url": browser_download_url,
                }
            )

        release_rows.append(
            {
                "tag_name": str(release.get("tag_name", "")),
                "published_at": str(release.get("published_at", "")),
                "html_url": str(release.get("html_url", "")),
                "payload_downloads": sum(asset["download_count"] for asset in payload_assets),
                "assets": payload_assets,
                "counts": row_counts,
            }
        )

    release_rows.sort(key=lambda row: row["published_at"], reverse=True)
    latest_release = release_rows[0] if release_rows else None

    artifact_totals = [
        {"key": key, "label": ASSET_LABELS[key], "download_count": asset_totals[key]}
        for key in (
            "linux_tarball",
            "mac_intel_tarball",
            "mac_arm_tarball",
            "windows_zip",
            "deb_package",
            "other",
        )
        if asset_totals[key] > 0 or key != "other"
    ]

    return {
        "repo": repo,
        "release_count": len(release_rows),
        "total_payload_downloads": total_payload_downloads,
        "latest_release": latest_release,
        "artifact_totals": artifact_totals,
        "releases": release_rows,
    }


def fetch_homebrew_metrics(formula: str) -> dict[str, object]:
    if not formula:
        return {
            "status": "disabled",
            "message": "No formula token configured for Homebrew lookups.",
        }

    url = f"https://formulae.brew.sh/api/formula/{urllib.parse.quote(formula)}.json"
    try:
        payload = http_get_json(url)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {
                "status": "unavailable",
                "formula": formula,
                "message": "No public formulae.brew.sh analytics entry was found for this formula.",
            }
        raise

    if not isinstance(payload, dict):
        raise RuntimeError(f"Unexpected Homebrew response for formula {formula}")

    analytics = payload.get("analytics", {})
    if not isinstance(analytics, dict):
        analytics = {}

    def analytics_value(category: str, days: str) -> int | None:
        category_data = analytics.get(category, {})
        if not isinstance(category_data, dict):
            return None
        bucket = category_data.get(days, {})
        if not isinstance(bucket, dict):
            return None
        raw = bucket.get(formula)
        return int(raw) if raw is not None else None

    return {
        "status": "available",
        "formula": formula,
        "install": {days: analytics_value("install", days) for days in ("30d", "90d", "365d")},
        "install_on_request": {
            days: analytics_value("install_on_request", days) for days in ("30d", "90d", "365d")
        },
        "page_url": f"https://formulae.brew.sh/formula/{urllib.parse.quote(formula)}",
    }


def extract_first(pattern: str, text: str) -> str | None:
    match = re.search(pattern, text, flags=re.IGNORECASE | re.DOTALL)
    if not match:
        return None
    return match.group(1).strip()


def parse_int(text: str | None) -> int | None:
    if not text:
        return None
    digits = re.sub(r"[^0-9]", "", text)
    if not digits:
        return None
    return int(digits)


def fetch_chocolatey_metrics(package_name: str) -> dict[str, object]:
    if not package_name:
        return {
            "status": "disabled",
            "message": "No Chocolatey package configured.",
        }

    url = f"https://community.chocolatey.org/packages/{urllib.parse.quote(package_name)}"
    body, _ = http_get(url)

    total_downloads = parse_int(
        extract_first(r'id="totalDownloadCount"[^>]*>\s*([^<]+)\s*<', body)
    )
    current_downloads = parse_int(
        extract_first(r'id="currentDownloadCount"[^>]*>\s*([^<]+)\s*<', body)
    )
    current_version = extract_first(
        r"Downloads of v\s*([^:<]+)\s*:",
        body,
    )
    last_updated = extract_first(r'id="lastUpdated"[^>]*>\s*([^<]+)\s*<', body)

    if total_downloads is None:
        raise RuntimeError(f"Unable to parse Chocolatey download count for {package_name}")

    return {
        "status": "available",
        "package": package_name,
        "page_url": url,
        "total_downloads": total_downloads,
        "current_version_downloads": current_downloads,
        "current_version": current_version,
        "last_updated": last_updated,
    }


def number(value: int | None) -> str:
    if value is None:
        return "n/a"
    return f"{value:,}"


def iso_to_display(value: str) -> str:
    if not value:
        return "n/a"
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return value
    return parsed.strftime("%Y-%m-%d")


def asset_notes(kind: str) -> str:
    if kind in {"linux_tarball", "mac_intel_tarball", "mac_arm_tarball"}:
        return "Shared by Homebrew, npm postinstall, and direct manual downloads."
    if kind == "windows_zip":
        return "Shared by Chocolatey, npm postinstall, and direct manual downloads."
    if kind == "deb_package":
        return "Tracks direct .deb downloads only. APT installs from GitHub Pages are not visible here."
    return "Release asset downloaded directly from GitHub Releases."


def render_homebrew_panel(homebrew: dict[str, object], github_metrics: dict[str, object]) -> str:
    status = str(homebrew.get("status", "unavailable"))

    if status == "available":
        install = homebrew.get("install", {})
        install_on_request = homebrew.get("install_on_request", {})
        if not isinstance(install, dict) or not isinstance(install_on_request, dict):
            raise RuntimeError("Unexpected Homebrew analytics payload")

        rows = "".join(
            f"""
            <tr>
              <th>{days}</th>
              <td>{number(install.get(days))}</td>
              <td>{number(install_on_request.get(days))}</td>
            </tr>
            """
            for days in ("30d", "90d", "365d")
        )
        page_url = html.escape(str(homebrew.get("page_url", "")))
        return f"""
        <div class="panel">
          <div class="panel-head">
            <div>
              <p class="eyebrow">Homebrew</p>
              <h2>Exact formula analytics</h2>
            </div>
            <a class="link-chip" href="{page_url}">formulae.brew.sh</a>
          </div>
          <p class="muted">These are exact Homebrew analytics from the public formula catalog.</p>
          <table>
            <thead>
              <tr>
                <th>Window</th>
                <th>Install</th>
                <th>Install on request</th>
              </tr>
            </thead>
            <tbody>{rows}</tbody>
          </table>
        </div>
        """

    artifact_rows = []
    for artifact in github_metrics["artifact_totals"]:
        if artifact["key"] not in {"linux_tarball", "mac_intel_tarball", "mac_arm_tarball"}:
            continue
        artifact_rows.append(
            f"""
            <tr>
              <th>{html.escape(artifact["label"])}</th>
              <td>{number(artifact["download_count"])}</td>
              <td>{html.escape(asset_notes(artifact["key"]))}</td>
            </tr>
            """
        )

    message = html.escape(
        str(homebrew.get("message", "Exact Homebrew analytics are unavailable in this report."))
    )
    return f"""
    <div class="panel">
      <div class="panel-head">
        <div>
          <p class="eyebrow">Homebrew</p>
          <h2>Indirect signal only</h2>
        </div>
        <span class="pill warn">custom tap blind spot</span>
      </div>
      <p class="muted">{message}</p>
      <table>
        <thead>
          <tr>
            <th>Artifact</th>
            <th>GitHub downloads</th>
            <th>Interpretation</th>
          </tr>
        </thead>
        <tbody>{''.join(artifact_rows)}</tbody>
      </table>
    </div>
    """


def render_chocolatey_panel(chocolatey: dict[str, object]) -> str:
    status = str(chocolatey.get("status", "unavailable"))
    if status != "available":
        message = html.escape(str(chocolatey.get("message", "Chocolatey data was not available.")))
        return f"""
        <div class="panel">
          <div class="panel-head">
            <div>
              <p class="eyebrow">Chocolatey</p>
              <h2>Unavailable right now</h2>
            </div>
            <span class="pill warn">best effort</span>
          </div>
          <p class="muted">{message}</p>
        </div>
        """

    page_url = html.escape(str(chocolatey.get("page_url", "")))
    version = html.escape(str(chocolatey.get("current_version") or "current"))
    last_updated = html.escape(str(chocolatey.get("last_updated") or "n/a"))
    return f"""
    <div class="panel">
      <div class="panel-head">
        <div>
          <p class="eyebrow">Chocolatey</p>
          <h2>Exact package page counts</h2>
        </div>
        <a class="link-chip" href="{page_url}">community.chocolatey.org</a>
      </div>
      <div class="stats-grid">
        <article class="stat-card">
          <p>Total downloads</p>
          <strong>{number(chocolatey.get("total_downloads"))}</strong>
        </article>
        <article class="stat-card">
          <p>Downloads of v{version}</p>
          <strong>{number(chocolatey.get("current_version_downloads"))}</strong>
        </article>
        <article class="stat-card">
          <p>Last updated on package page</p>
          <strong>{last_updated}</strong>
        </article>
      </div>
    </div>
    """


def render_github_panel(github_metrics: dict[str, object]) -> str:
    artifact_rows = "".join(
        f"""
        <tr>
          <th>{html.escape(artifact['label'])}</th>
          <td>{number(artifact['download_count'])}</td>
          <td>{html.escape(asset_notes(artifact['key']))}</td>
        </tr>
        """
        for artifact in github_metrics["artifact_totals"]
        if artifact["download_count"] > 0
    )

    release_rows = []
    for release in github_metrics["releases"]:
        release_rows.append(
            f"""
            <tr>
              <th><a href="{html.escape(release['html_url'])}">{html.escape(release['tag_name'])}</a></th>
              <td>{iso_to_display(str(release['published_at']))}</td>
              <td>{number(release['counts']['linux_tarball'])}</td>
              <td>{number(release['counts']['mac_intel_tarball'])}</td>
              <td>{number(release['counts']['mac_arm_tarball'])}</td>
              <td>{number(release['counts']['windows_zip'])}</td>
              <td>{number(release['counts']['deb_package'])}</td>
              <td>{number(release['payload_downloads'])}</td>
            </tr>
            """
        )

    return f"""
    <div class="panel">
      <div class="panel-head">
        <div>
          <p class="eyebrow">GitHub Releases</p>
          <h2>Release asset downloads</h2>
        </div>
        <span class="pill ok">exact per asset</span>
      </div>
      <p class="muted">These counts come directly from GitHub release assets. They are exact for the files, but some assets are shared across multiple install channels.</p>
      <table>
        <thead>
          <tr>
            <th>Asset type</th>
            <th>Total downloads</th>
            <th>Interpretation</th>
          </tr>
        </thead>
        <tbody>{artifact_rows}</tbody>
      </table>
      <div class="spacer"></div>
      <table>
        <thead>
          <tr>
            <th>Release</th>
            <th>Published</th>
            <th>Linux</th>
            <th>macOS Intel</th>
            <th>macOS ARM</th>
            <th>Windows</th>
            <th>.deb</th>
            <th>Total</th>
          </tr>
        </thead>
        <tbody>{''.join(release_rows)}</tbody>
      </table>
    </div>
    """


def render_apt_panel() -> str:
    return """
    <div class="panel">
      <div class="panel-head">
        <div>
          <p class="eyebrow">APT</p>
          <h2>No exact install counter</h2>
        </div>
        <span class="pill warn">GitHub Pages blind spot</span>
      </div>
      <p class="muted">The APT repository is currently served as static files from GitHub Pages. That setup does not give this project per-package download or install logs, so exact APT usage is intentionally called out as unknown here.</p>
    </div>
    """


def render_html_report(
    report: dict[str, object],
    pages_base_url: str,
) -> str:
    github_metrics = report["github"]
    homebrew = report["homebrew"]
    chocolatey = report["chocolatey"]
    generated_at = html.escape(str(report["generated_at"]))
    pages_base_url = pages_base_url.rstrip("/")
    repo = html.escape(str(report["repo"]))
    repo_url = f"https://github.com/{repo}"

    latest_release = github_metrics.get("latest_release") or {}
    latest_tag = html.escape(str(latest_release.get("tag_name") or "n/a"))
    latest_date = iso_to_display(str(latest_release.get("published_at") or ""))

    if str(homebrew.get("status")) == "available":
        homebrew_card_value = number(homebrew["install"].get("30d"))
        homebrew_card_label = "30d exact installs"
    else:
        homebrew_card_value = "n/a"
        homebrew_card_label = "custom tap"

    chocolatey_total = (
        number(chocolatey.get("total_downloads"))
        if str(chocolatey.get("status")) == "available"
        else "n/a"
    )

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Oxmgr Download Metrics</title>
  <style>
    :root {{
      --bg: #f4efe6;
      --panel: rgba(255, 252, 247, 0.86);
      --panel-strong: #fffaf2;
      --ink: #142013;
      --muted: #576256;
      --accent: #cb5f2d;
      --border: rgba(20, 32, 19, 0.12);
      --ok: #235d3a;
      --warn: #915b00;
      --shadow: 0 24px 60px rgba(37, 30, 20, 0.12);
    }}

    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      color: var(--ink);
      background:
        radial-gradient(circle at top left, rgba(203, 95, 45, 0.18), transparent 30%),
        radial-gradient(circle at top right, rgba(35, 93, 58, 0.14), transparent 24%),
        linear-gradient(180deg, #faf5ec 0%, var(--bg) 100%);
      font-family: "Iowan Old Style", "Palatino Linotype", "Book Antiqua", Georgia, serif;
      line-height: 1.5;
    }}

    a {{
      color: inherit;
    }}

    .shell {{
      width: min(1180px, calc(100% - 32px));
      margin: 0 auto;
      padding: 40px 0 56px;
    }}

    .hero {{
      padding: 28px;
      border: 1px solid var(--border);
      border-radius: 28px;
      background: linear-gradient(145deg, rgba(255, 250, 242, 0.94), rgba(255, 247, 238, 0.72));
      box-shadow: var(--shadow);
      overflow: hidden;
      position: relative;
    }}

    .hero::after {{
      content: "";
      position: absolute;
      inset: auto -60px -60px auto;
      width: 220px;
      height: 220px;
      border-radius: 999px;
      background: radial-gradient(circle, rgba(203, 95, 45, 0.22), transparent 70%);
      pointer-events: none;
    }}

    .eyebrow {{
      margin: 0 0 8px;
      color: var(--accent);
      font-size: 0.9rem;
      font-weight: 700;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }}

    h1 {{
      margin: 0;
      font-size: clamp(2.2rem, 5vw, 4.4rem);
      line-height: 0.96;
      max-width: 11ch;
    }}

    h2 {{
      margin: 0;
      font-size: 1.5rem;
    }}

    .hero-copy {{
      margin: 18px 0 0;
      max-width: 70ch;
      color: var(--muted);
      font-size: 1.02rem;
    }}

    .hero-actions {{
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      margin-top: 22px;
    }}

    .link-chip,
    .hero-actions a {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 10px 14px;
      border-radius: 999px;
      border: 1px solid var(--border);
      background: rgba(255, 255, 255, 0.72);
      text-decoration: none;
      font-size: 0.95rem;
    }}

    .hero-actions a.primary {{
      background: var(--ink);
      color: #fff8ef;
      border-color: var(--ink);
    }}

    .overview {{
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 14px;
      margin-top: 18px;
    }}

    .overview-card,
    .panel,
    .stat-card {{
      border: 1px solid var(--border);
      background: var(--panel);
      border-radius: 24px;
      box-shadow: var(--shadow);
    }}

    .overview-card {{
      padding: 18px 18px 20px;
    }}

    .overview-card p,
    .stat-card p,
    .muted {{
      margin: 0;
      color: var(--muted);
    }}

    .overview-card strong,
    .stat-card strong {{
      display: block;
      margin-top: 10px;
      font-size: 1.9rem;
      line-height: 1;
    }}

    .grid {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 18px;
      margin-top: 18px;
    }}

    .panel {{
      padding: 22px;
    }}

    .panel-head {{
      display: flex;
      justify-content: space-between;
      gap: 12px;
      align-items: flex-start;
      margin-bottom: 14px;
    }}

    .pill {{
      display: inline-flex;
      align-items: center;
      padding: 6px 10px;
      border-radius: 999px;
      font-size: 0.82rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      border: 1px solid transparent;
      white-space: nowrap;
    }}

    .pill.ok {{
      background: rgba(35, 93, 58, 0.12);
      color: var(--ok);
      border-color: rgba(35, 93, 58, 0.16);
    }}

    .pill.warn {{
      background: rgba(145, 91, 0, 0.12);
      color: var(--warn);
      border-color: rgba(145, 91, 0, 0.16);
    }}

    .stats-grid {{
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 12px;
      margin-top: 16px;
    }}

    .stat-card {{
      padding: 16px;
      background: var(--panel-strong);
    }}

    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 0.95rem;
    }}

    th,
    td {{
      padding: 12px 10px;
      border-bottom: 1px solid var(--border);
      text-align: left;
      vertical-align: top;
    }}

    th {{
      font-size: 0.82rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--muted);
    }}

    tbody tr:last-child th,
    tbody tr:last-child td {{
      border-bottom: none;
    }}

    .spacer {{
      height: 18px;
    }}

    .footer {{
      margin-top: 18px;
      padding: 20px 4px 0;
      color: var(--muted);
      font-size: 0.92rem;
    }}

    @media (max-width: 980px) {{
      .overview,
      .grid,
      .stats-grid {{
        grid-template-columns: 1fr 1fr;
      }}
    }}

    @media (max-width: 720px) {{
      .shell {{
        width: min(100% - 20px, 1180px);
        padding-top: 24px;
      }}

      .hero,
      .panel,
      .overview-card,
      .stat-card {{
        border-radius: 20px;
      }}

      .overview,
      .grid,
      .stats-grid {{
        grid-template-columns: 1fr;
      }}

      .panel-head {{
        flex-direction: column;
      }}

      table,
      thead,
      tbody,
      th,
      td,
      tr {{
        display: block;
      }}

      thead {{
        display: none;
      }}

      tbody tr {{
        padding: 12px 0;
        border-bottom: 1px solid var(--border);
      }}

      tbody tr:last-child {{
        border-bottom: none;
      }}

      tbody th,
      tbody td {{
        padding: 4px 0;
        border-bottom: none;
      }}
    }}
  </style>
</head>
<body>
  <main class="shell">
    <section class="hero">
      <p class="eyebrow">Oxmgr distribution telemetry</p>
      <h1>Download Metrics</h1>
      <p class="hero-copy">Published package and artifact signals for <strong>{repo}</strong>. This report distinguishes exact counters from proxies and explicitly keeps blind spots visible instead of pretending the data exists.</p>
      <div class="hero-actions">
        <a class="primary" href="{repo_url}">Repository</a>
        <a href="{html.escape(pages_base_url)}/downloads/data.json">Raw JSON</a>
        <a href="https://community.chocolatey.org/packages/oxmgr">Chocolatey package</a>
      </div>
      <div class="overview">
        <article class="overview-card">
          <p>GitHub asset downloads</p>
          <strong>{number(github_metrics['total_payload_downloads'])}</strong>
        </article>
        <article class="overview-card">
          <p>Releases tracked</p>
          <strong>{number(github_metrics['release_count'])}</strong>
        </article>
        <article class="overview-card">
          <p>Chocolatey total</p>
          <strong>{chocolatey_total}</strong>
        </article>
        <article class="overview-card">
          <p>Homebrew exact</p>
          <strong>{homebrew_card_value}</strong>
          <span class="muted">{homebrew_card_label}</span>
        </article>
      </div>
      <p class="hero-copy">Latest release: <strong>{latest_tag}</strong> on <strong>{latest_date}</strong>. Snapshot generated at <strong>{generated_at}</strong>.</p>
    </section>

    <section class="grid">
      {render_github_panel(github_metrics)}
      {render_chocolatey_panel(chocolatey)}
      {render_homebrew_panel(homebrew, github_metrics)}
      {render_apt_panel()}
    </section>

    <p class="footer">The Linux and macOS tarballs are shared between Homebrew installs, npm postinstall downloads, and manual downloads. The Windows zip is shared between Chocolatey, npm postinstall, and manual downloads. Exact APT installs are not observable with the current GitHub Pages hosting model.</p>
  </main>
</body>
</html>
"""


def build_report(repo: str, brew_formula: str, choco_package: str) -> dict[str, object]:
    github_metrics = fetch_github_metrics(repo)

    try:
        homebrew = fetch_homebrew_metrics(brew_formula)
    except Exception as exc:  # pragma: no cover - best-effort external fetch
        homebrew = {"status": "error", "message": str(exc)}

    try:
        chocolatey = fetch_chocolatey_metrics(choco_package)
    except Exception as exc:  # pragma: no cover - best-effort external fetch
        chocolatey = {"status": "error", "message": str(exc)}

    return {
        "generated_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        "repo": repo,
        "github": github_metrics,
        "homebrew": homebrew,
        "chocolatey": chocolatey,
        "apt": {
            "status": "unavailable",
            "message": "The GitHub Pages-backed APT repository does not expose exact download or install logs here.",
        },
    }


def write_output(report: dict[str, object], output_dir: pathlib.Path, pages_base_url: str) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "data.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (output_dir / "index.html").write_text(
        render_html_report(report, pages_base_url),
        encoding="utf-8",
    )


def main() -> int:
    args = build_parser().parse_args()
    output_dir = pathlib.Path(args.output_dir)
    report = build_report(
        repo=args.repo,
        brew_formula=args.brew_formula,
        choco_package=args.choco_package,
    )
    write_output(report, output_dir, args.pages_base_url)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
