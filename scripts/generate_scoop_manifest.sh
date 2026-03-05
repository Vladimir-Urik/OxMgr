#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: $0 <repo> <version> <asset_url> <asset_sha256>" >&2
  exit 1
fi

REPO="$1"
VERSION="$2"
ASSET_URL="$3"
ASSET_SHA="$4"

cat <<MANIFEST
{
  "version": "${VERSION}",
  "description": "Oxmgr is a lightweight, cross-platform process manager.",
  "homepage": "https://github.com/${REPO}",
  "license": "MIT",
  "architecture": {
    "64bit": {
      "url": "${ASSET_URL}",
      "hash": "${ASSET_SHA}"
    }
  },
  "bin": "oxmgr.exe",
  "checkver": {
    "github": "${REPO}"
  },
  "autoupdate": {
    "architecture": {
      "64bit": {
        "url": "https://github.com/${REPO}/releases/download/v\$version/oxmgr-v\$version-x86_64-pc-windows-msvc.zip"
      }
    }
  }
}
MANIFEST
