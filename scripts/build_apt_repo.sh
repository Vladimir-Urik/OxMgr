#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 3 ]]; then
  echo "usage: $0 <repo_out_dir> <version> <deb_path>..." >&2
  exit 1
fi

REPO_OUT="$1"
VERSION="$2"
shift 2

POOL_DIR="${REPO_OUT}/pool/main/o/oxmgr"

rm -rf "${REPO_OUT}"
mkdir -p "${POOL_DIR}"

for DEB_PATH in "$@"; do
  cp "${DEB_PATH}" "${POOL_DIR}/"
done

# Collect architectures based on provided debs
ARCHS=()
for DEB_PATH in "$@"; do
  ARCH=$(basename "${DEB_PATH}" .deb | awk -F'_' '{print $3}')
  ARCHS+=("$ARCH")
done

# Remove duplicates
ARCHS=($(printf "%s\n" "${ARCHS[@]}" | sort -u))

(
  cd "${REPO_OUT}"
  for ARCH in "${ARCHS[@]}"; do
    DIST_DIR="dists/stable/main/binary-${ARCH}"
    mkdir -p "${DIST_DIR}"
    dpkg-scanpackages --arch "${ARCH}" --multiversion pool > "${DIST_DIR}/Packages"
    gzip -9c "${DIST_DIR}/Packages" > "${DIST_DIR}/Packages.gz"
  done

  ARCH_LIST=$(IFS=" " ; echo "${ARCHS[*]}")

  cat > dists/stable/Release <<RELEASE
Origin: oxmgr
Label: oxmgr
Suite: stable
Codename: stable
Architectures: ${ARCH_LIST}
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
