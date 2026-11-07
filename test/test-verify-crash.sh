#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
set -euo pipefail
ulimit -c 0
repo="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d /tmp/afl-verify-crash.XXXXXX)"
trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/in"
printf A > "$tmp/in/seed"
printf 'state="S"\ncrash="C"\n' > "$tmp/dict"
export AFL_PATH="$repo" AFL_SKIP_CPUFREQ=1 AFL_NO_UI=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_NO_CRASH_README=1
"$repo/afl-clang-fast" -O0 "$repo/test/test-verify-crash.c" -o "$tmp/target"
for mode in off on fresh; do
  if [ "$mode" = off ]; then unset AFL_VERIFY_CRASH; else export AFL_VERIFY_CRASH=1; fi
  if [ "$mode" = fresh ]; then export VERIFY_CRASH_TEST_FRESH=1; else unset VERIFY_CRASH_TEST_FRESH; fi
  "$repo/afl-fuzz" -i "$tmp/in" -o "$tmp/$mode" -x "$tmp/dict" -t 1000 \
    -V 5 -- "$tmp/target" > "$tmp/$mode.log" 2>&1
  count="$(find "$tmp/$mode/default/crashes" -type f ! -name README.txt | wc -l)"
  case "$mode:$count" in
    off:1|on:0|fresh:1) printf '[+] %s: %s saved crashes\n' "$mode" "$count" ;;
    *) cat "$tmp/$mode.log"; echo "unexpected result for $mode: $count" >&2; exit 1 ;;
  esac
done
