#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 9 ]]; then
  echo "usage: $0 <repo> <linux_intel_url> <linux_intel_sha> <linux_arm_url> <linux_arm_sha> <mac_intel_url> <mac_intel_sha> <mac_arm_url> <mac_arm_sha>" >&2
  exit 1
fi

REPO="$1"
LINUX_INTEL_URL="$2"
LINUX_INTEL_SHA="$3"
LINUX_ARM_URL="$4"
LINUX_ARM_SHA="$5"
MAC_INTEL_URL="$6"
MAC_INTEL_SHA="$7"
MAC_ARM_URL="$8"
MAC_ARM_SHA="$9"

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
    if Hardware::CPU.arm?
      url "${LINUX_ARM_URL}"
      sha256 "${LINUX_ARM_SHA}"
    else
      url "${LINUX_INTEL_URL}"
      sha256 "${LINUX_INTEL_SHA}"
    end
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
