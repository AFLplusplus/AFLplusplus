#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
set -euo pipefail
ulimit -c 0
repo="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d /tmp/afl-verify-crash.XXXXXX)"
trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/in"
printf A > "$tmp/in/seed"
printf 'state="S"\n' > "$tmp/state.dict"
printf 'crash="CC"\n' > "$tmp/crash.dict"
export AFL_PATH="$repo" AFL_SKIP_CPUFREQ=1 AFL_NO_UI=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_NO_CRASH_README=1
"$repo/afl-clang-fast" -O0 "$repo/test/test-verify-crash.c" -o "$tmp/target"
for mode in off on fresh; do
  if [ "$mode" = off ]; then unset AFL_VERIFY_CRASH; else export AFL_VERIFY_CRASH=1; fi
  if [ "$mode" = on ]; then
    export AFL_CRASH_PROVENANCE_DEPTH=8 AFL_CRASH_PROVENANCE_MAX_BYTES=1048576
    export AFL_CRASH_SHADOW=1
  else
    unset AFL_CRASH_PROVENANCE_DEPTH AFL_CRASH_PROVENANCE_MAX_BYTES
    unset AFL_CRASH_SHADOW
  fi
  if [ "$mode" = fresh ]; then export VERIFY_CRASH_TEST_FRESH=1; else unset VERIFY_CRASH_TEST_FRESH; fi
  dict="$tmp/state.dict"
  if [ "$mode" = fresh ]; then dict="$tmp/crash.dict"; fi
  "$repo/afl-fuzz" -i "$tmp/in" -o "$tmp/$mode" -x "$dict" -t 1000 \
    -V 5 -- "$tmp/target" > "$tmp/$mode.log" 2>&1
  count="$(find "$tmp/$mode/default/crashes" -maxdepth 1 -type f ! -name README.txt | wc -l)"
  if [ "$count" -lt 1 ]; then
    cat "$tmp/$mode.log"
    echo "no crash saved for $mode" >&2
    exit 1
  fi
  printf '[+] %s: %s saved crashes\n' "$mode" "$count"
  if [ "$mode" = on ]; then
    grep -q '"classification": "state_dependent"' \
      "$tmp/$mode/default/crashes/.provenance/"*.json
    journal="$(find "$tmp/$mode/default/crashes/.provenance/event-000000" \
      -type f -name '*.input' | wc -l)"
    [ "$journal" -ge 2 ] || {
      echo "provenance journal did not retain the causal sequence" >&2
      exit 1
    }
    grep -q '"worker": "isolated_process"' \
      "$tmp/$mode/default/crashes/.provenance/"*.shadow.json
    grep -q '"classification": "state_dependent"' \
      "$tmp/$mode/default/crashes/.provenance/"*.shadow.json
  elif [ "$mode" = fresh ]; then
    grep -q '"classification": "reproduced_same_observation"' \
      "$tmp/$mode/default/crashes/.provenance/"*.json
  fi
done
