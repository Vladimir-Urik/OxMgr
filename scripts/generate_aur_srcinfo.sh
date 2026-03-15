#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 5 ]]; then
  echo "usage: $0 <repo> <version> <intel_sha256> <arm_sha256> <license_sha256>" >&2
  exit 1
fi

REPO="$1"
VERSION="$2"
INTEL_SHA="$3"
ARM_SHA="$4"
LICENSE_SHA="$5"

cat <<SRCINFO
pkgbase = oxmgr-bin
	pkgdesc = Lightweight cross-platform process manager
	pkgver = ${VERSION}
	pkgrel = 1
	url = https://github.com/${REPO}
	arch = x86_64
	arch = aarch64
	license = MIT
	depends = gcc-libs
	depends = glibc
	optdepends = systemd: install and manage the oxmgr daemon as a systemd service
	provides = oxmgr
	conflicts = oxmgr
	source = LICENSE::https://raw.githubusercontent.com/${REPO}/v${VERSION}/LICENSE
	sha256sums = ${LICENSE_SHA}
	source_x86_64 = https://github.com/${REPO}/releases/download/v${VERSION}/oxmgr-v${VERSION}-x86_64-unknown-linux-gnu.tar.gz
	sha256sums_x86_64 = ${INTEL_SHA}
	source_aarch64 = https://github.com/${REPO}/releases/download/v${VERSION}/oxmgr-v${VERSION}-aarch64-unknown-linux-gnu.tar.gz
	sha256sums_aarch64 = ${ARM_SHA}

pkgname = oxmgr-bin
SRCINFO
