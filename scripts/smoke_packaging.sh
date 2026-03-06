#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

pushd "$ROOT_DIR/packaging/npm" >/dev/null
npm pack --dry-run >/dev/null

mkdir -p vendor
cat > vendor/oxmgr <<'EOF'
#!/usr/bin/env bash
echo "Oxmgr process manager"
EOF
chmod +x vendor/oxmgr

WRAPPER_OUTPUT="$(node bin/oxmgr.js --help)"
if [[ "$WRAPPER_OUTPUT" != *"Oxmgr process manager"* ]]; then
  echo "npm wrapper smoke check failed" >&2
  exit 1
fi

rm -f vendor/oxmgr
popd >/dev/null

FORMULA_OUTPUT="$("$ROOT_DIR/scripts/generate_homebrew_formula.sh" \
  "example/oxmgr" \
  "https://example.com/linux.tar.gz" \
  "linuxsha" \
  "https://example.com/macos-intel.tar.gz" \
  "macintelsha" \
  "https://example.com/macos-arm.tar.gz" \
  "macarmsha"
)"

[[ "$FORMULA_OUTPUT" == *"class Oxmgr < Formula"* ]]
[[ "$FORMULA_OUTPUT" == *'assert_match "Oxmgr process manager", output'* ]]

SCOOP_OUTPUT="$("$ROOT_DIR/scripts/generate_scoop_manifest.sh" \
  "example/oxmgr" \
  "1.2.3" \
  "https://example.com/oxmgr.zip" \
  "deadbeef"
)"

printf '%s' "$SCOOP_OUTPUT" | python3 -c '
import json, sys
payload = json.load(sys.stdin)
assert payload["version"] == "1.2.3"
assert payload["bin"] == "oxmgr.exe"
assert payload["architecture"]["64bit"]["hash"] == "deadbeef"
'
