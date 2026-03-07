#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: $0 <repo> <version> <archive_sha256> <license_sha256>" >&2
  exit 1
fi

REPO="$1"
VERSION="$2"
ARCHIVE_SHA="$3"
LICENSE_SHA="$4"

cat <<SRCINFO
pkgbase = oxmgr-bin
	pkgdesc = Lightweight cross-platform process manager
	pkgver = ${VERSION}
	pkgrel = 1
	url = https://github.com/${REPO}
	arch = x86_64
	license = MIT
	depends = gcc-libs
	depends = glibc
	optdepends = systemd: install and manage the oxmgr daemon as a systemd service
	provides = oxmgr
	conflicts = oxmgr
	source = https://github.com/${REPO}/releases/download/v${VERSION}/oxmgr-v${VERSION}-x86_64-unknown-linux-gnu.tar.gz
	source = LICENSE::https://raw.githubusercontent.com/${REPO}/v${VERSION}/LICENSE
	sha256sums = ${ARCHIVE_SHA}
	sha256sums = ${LICENSE_SHA}

pkgname = oxmgr-bin
SRCINFO
