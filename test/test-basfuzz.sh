#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later

set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
test -x "$ROOT/afl-fuzz" -a -x "$ROOT/afl-cc" || { echo "SKIP: afl-fuzz/afl-cc not built"; exit 0; }
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

"$ROOT/afl-cc" -o "$WORK/t" "$ROOT/test-instr.c" > /dev/null 2>&1
mkdir -p "$WORK/in"
printf '0' > "$WORK/in/a"
printf '1' > "$WORK/in/b"
printf 'hello' > "$WORK/in/c"

export AFL_NO_UI=1 AFL_SKIP_CPUFREQ=1 AFL_NO_AFFINITY=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1

AFL_BASFUZZ=1 AFL_BASFUZZ_INTERVAL=1 "$ROOT/afl-fuzz" -V 12 -i "$WORK/in" -o "$WORK/o1" -- "$WORK/t" > "$WORK/l1" 2>&1 || { echo "FAIL: run"; cat "$WORK/l1"; exit 1; }
R=$(awk -F: '/^basfuzz_rescores/ {gsub(/ /,"",$2); print $2}' "$WORK/o1/default/fuzzer_stats")
test -n "$R" && test "$R" -ge 1 || { echo "FAIL: no rescore ($R)"; cat "$WORK/o1/default/fuzzer_stats"; exit 1; }

AFL_BASFUZZ=1 AFL_BASFUZZ_INTERVAL=1 "$ROOT/afl-fuzz" -p rare -V 8 -i "$WORK/in" -o "$WORK/o2" -- "$WORK/t" > "$WORK/l2" 2>&1 || { echo "FAIL: rare run"; cat "$WORK/l2"; exit 1; }
grep -q "^basfuzz_rescores" "$WORK/o2/default/fuzzer_stats" || { echo "FAIL: rare stats"; exit 1; }

if AFL_BASFUZZ=1 AFL_BASFUZZ_BOOST=0.5 "$ROOT/afl-fuzz" -V 2 -i "$WORK/in" -o "$WORK/o3" -- "$WORK/t" > "$WORK/l3" 2>&1; then
  echo "FAIL: invalid boost accepted"; exit 1
fi
grep -q "AFL_BASFUZZ_BOOST must be" "$WORK/l3" || { echo "FAIL: no boost error"; cat "$WORK/l3"; exit 1; }

AFL_BASFUZZ=1 "$ROOT/afl-fuzz" -Z -V 3 -i "$WORK/in" -o "$WORK/o4" -- "$WORK/t" > "$WORK/l4" 2>&1 || true
grep -q "AFL_BASFUZZ is ignored" "$WORK/l4" || { echo "FAIL: no -Z warning"; cat "$WORK/l4"; exit 1; }
if grep -q "^basfuzz_rescores" "$WORK/o4/default/fuzzer_stats"; then echo "FAIL: active with -Z"; exit 1; fi

"$ROOT/afl-fuzz" -V 3 -i "$WORK/in" -o "$WORK/o5" -- "$WORK/t" > "$WORK/l5" 2>&1 || true
if grep -q "^basfuzz_rescores" "$WORK/o5/default/fuzzer_stats"; then echo "FAIL: active without AFL_BASFUZZ"; exit 1; fi

echo "PASS: basfuzz"
