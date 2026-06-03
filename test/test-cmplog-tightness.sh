#!/bin/bash
# test/test-cmplog-tightness.sh — smoke test for -l -M
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AFL_DIR="$SCRIPT_DIR/.."
TMP=$(mktemp -d)
trap "rm -rf $TMP" EXIT

# Sanitizers interact badly with the bug-pass ALLOCSIZE/DERIVE runtime;
# strip them so this test exercises CmpLog cleanly regardless of the
# user's shell.
unset AFL_USE_ASAN AFL_USE_MSAN AFL_USE_UBSAN AFL_USE_TSAN AFL_USE_LSAN
unset AFL_LLVM_CMPLOG

if [ ! -x "$AFL_DIR/afl-clang-fast" ] || [ ! -x "$AFL_DIR/afl-fuzz" ]; then
  echo "[-] afl-clang-fast or afl-fuzz missing; skipping"
  exit 0
fi

# Build a CmpLog binary alongside the regular one.
AFL_QUIET=1 AFL_LLVM_CMPLOG=1 "$AFL_DIR/afl-clang-fast" \
  "$SCRIPT_DIR/test-cmplog-tightness.c" -o "$TMP/t.cmplog"
AFL_QUIET=1 "$AFL_DIR/afl-clang-fast" \
  "$SCRIPT_DIR/test-cmplog-tightness.c" -o "$TMP/t"

mkdir -p "$TMP/in" "$TMP/out"
printf '\x00\x00\x00\x00' > "$TMP/in/seed"

# 5-second campaign with -l 2m. We're not asserting that tightness fires —
# just that the new letter parses, the campaign runs, and we don't regress.
set +e
AFL_NO_UI=1 AFL_BENCH_UNTIL_CRASH=1 timeout 8 \
  "$AFL_DIR/afl-fuzz" -i "$TMP/in" -o "$TMP/out" \
  -c "$TMP/t.cmplog" -l 2m -V 5 \
  -- "$TMP/t" >"$TMP/log" 2>&1
rc=$?
set -e

if grep -q "Unknown option value" "$TMP/log"; then
  echo "[!] tightness: -l -M parser regressed"
  exit 1
fi

# Confirm afl-fuzz actually started up and ran.
if ! grep -qiE "fuzzing test case|paths total|cycles done|Entering queue cycle" \
     "$TMP/log"; then
  echo "[!] tightness: afl-fuzz didn't run a campaign"
  cat "$TMP/log"
  exit 1
fi

echo "[+] tightness: -l 2m parsed and campaign ran"
