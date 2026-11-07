#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
repo="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d /tmp/afl-shadow-policy.XXXXXX)"
trap 'rm -rf "$tmp"' EXIT
${CC:-cc} -O2 -Wall -Wextra -I"$repo/include" \
  "$repo/test/test-shadow-policy.c" -o "$tmp/test-shadow-policy"
"$tmp/test-shadow-policy"
echo '[+] adaptive shadow policy thresholds passed'
