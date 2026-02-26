#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <deb_path> <repo_out_dir> <version>" >&2
  exit 1
fi

DEB_PATH="$1"
REPO_OUT="$2"
VERSION="$3"

POOL_DIR="${REPO_OUT}/pool/main/o/oxmgr"
DIST_DIR="${REPO_OUT}/dists/stable/main/binary-amd64"

rm -rf "${REPO_OUT}"
mkdir -p "${POOL_DIR}" "${DIST_DIR}"
cp "${DEB_PATH}" "${POOL_DIR}/"

(
  cd "${REPO_OUT}"
  dpkg-scanpackages --multiversion pool > dists/stable/main/binary-amd64/Packages
  gzip -9c dists/stable/main/binary-amd64/Packages > dists/stable/main/binary-amd64/Packages.gz

  cat > dists/stable/Release <<RELEASE
Origin: oxmgr
Label: oxmgr
Suite: stable
Codename: stable
Architectures: amd64
Components: main
Description: Oxmgr APT repository
Version: ${VERSION}
RELEASE

  if command -v apt-ftparchive >/dev/null 2>&1; then
    TMP_RELEASE=$(mktemp)
    apt-ftparchive release dists/stable > "${TMP_RELEASE}"
    cat "${TMP_RELEASE}" >> dists/stable/Release
    rm -f "${TMP_RELEASE}"
  fi
)

cat > "${REPO_OUT}/index.html" <<'HTML'
<!doctype html>
<html>
<head><meta charset="utf-8"><title>oxmgr apt repo</title></head>
<body>
<h1>oxmgr apt repository</h1>
<p>Add repository:</p>
<pre>deb [trusted=yes] https://REPLACE_ME stable main</pre>
</body>
</html>
HTML
