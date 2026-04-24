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

cat <<PKGBUILD
pkgname=oxmgr-bin
pkgver=${VERSION}
pkgrel=1
pkgdesc="Lightweight cross-platform process manager"
arch=('x86_64' 'aarch64')
url="https://github.com/${REPO}"
license=('MIT')
optdepends=('systemd: install and manage the oxmgr daemon as a systemd service')
provides=('oxmgr')
conflicts=('oxmgr')
source_x86_64=(
  "https://github.com/${REPO}/releases/download/v\${pkgver}/oxmgr-v\${pkgver}-x86_64-unknown-linux-musl.tar.gz"
)
source_aarch64=(
  "https://github.com/${REPO}/releases/download/v\${pkgver}/oxmgr-v\${pkgver}-aarch64-unknown-linux-musl.tar.gz"
)
source=(
  "LICENSE::https://raw.githubusercontent.com/${REPO}/v\${pkgver}/LICENSE"
)
sha256sums_x86_64=(
  '${INTEL_SHA}'
)
sha256sums_aarch64=(
  '${ARM_SHA}'
)
sha256sums=(
  '${LICENSE_SHA}'
)

package() {
  install -Dm755 "\${srcdir}/oxmgr" "\${pkgdir}/usr/bin/oxmgr"
  install -Dm644 "\${srcdir}/LICENSE" "\${pkgdir}/usr/share/licenses/\${pkgname}/LICENSE"
}
PKGBUILD
