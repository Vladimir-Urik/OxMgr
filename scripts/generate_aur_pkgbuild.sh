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

cat <<PKGBUILD
pkgname=oxmgr-bin
pkgver=${VERSION}
pkgrel=1
pkgdesc="Lightweight cross-platform process manager"
arch=('x86_64')
url="https://github.com/${REPO}"
license=('MIT')
depends=('gcc-libs' 'glibc')
optdepends=('systemd: install and manage the oxmgr daemon as a systemd service')
provides=('oxmgr')
conflicts=('oxmgr')
source=(
  "https://github.com/${REPO}/releases/download/v\${pkgver}/oxmgr-v\${pkgver}-x86_64-unknown-linux-gnu.tar.gz"
  "LICENSE::https://raw.githubusercontent.com/${REPO}/v\${pkgver}/LICENSE"
)
sha256sums=(
  '${ARCHIVE_SHA}'
  '${LICENSE_SHA}'
)

package() {
  install -Dm755 "\${srcdir}/oxmgr" "\${pkgdir}/usr/bin/oxmgr"
  install -Dm644 "\${srcdir}/LICENSE" "\${pkgdir}/usr/share/licenses/\${pkgname}/LICENSE"
}
PKGBUILD
