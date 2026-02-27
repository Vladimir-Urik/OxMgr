#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 7 ]]; then
  echo "usage: $0 <repo> <linux_url> <linux_sha> <mac_intel_url> <mac_intel_sha> <mac_arm_url> <mac_arm_sha>" >&2
  exit 1
fi

REPO="$1"
LINUX_URL="$2"
LINUX_SHA="$3"
MAC_INTEL_URL="$4"
MAC_INTEL_SHA="$5"
MAC_ARM_URL="$6"
MAC_ARM_SHA="$7"

cat <<FORMULA
class Oxmgr < Formula
  desc "Lightweight cross-platform process manager"
  homepage "https://github.com/${REPO}"
  license "MIT"

  if OS.mac?
    if Hardware::CPU.arm?
      url "${MAC_ARM_URL}"
      sha256 "${MAC_ARM_SHA}"
    else
      url "${MAC_INTEL_URL}"
      sha256 "${MAC_INTEL_SHA}"
    end
  elsif OS.linux?
    url "${LINUX_URL}"
    sha256 "${LINUX_SHA}"
  end

  def install
    bin.install "oxmgr"
  end

  test do
    output = shell_output("#{bin}/oxmgr --help")
    assert_match "Oxmgr process manager", output
  end
end
FORMULA
