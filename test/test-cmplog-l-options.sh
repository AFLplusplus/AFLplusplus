#!/bin/bash
# test/test-cmplog-l-options.sh -- verify CmpLog -l M and -l Z behavior.
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AFL_DIR="$SCRIPT_DIR/.."
TMP=$(mktemp -d)
trap "rm -rf $TMP" EXIT

if [ ! -x "$AFL_DIR/afl-clang-fast" ] || [ ! -x "$AFL_DIR/afl-fuzz" ]; then
  echo "[-] afl-clang-fast or afl-fuzz missing; skipping"
  exit 0
fi

unset AFL_LLVM_BUG AFL_LLVM_BUG_SCALAR AFL_LLVM_BUG_BUDGET
unset AFL_LLVM_BUG_SIZEFILL AFL_LLVM_BUG_SLACK AFL_LLVM_BUG_ALLOCSIZE
unset AFL_LLVM_BUG_ALLOCSIZE_FUNCS AFL_LLVM_BUG_ALLOCSIZE_FREE_FUNCS
unset AFL_LLVM_BUG_ALLOCSIZE_DERIVE AFL_LLVM_BUG_SCALAR_SLICE
unset AFL_LLVM_CMPLOG
unset AFL_USE_ASAN AFL_USE_MSAN AFL_USE_UBSAN AFL_USE_TSAN AFL_USE_LSAN

run_fuzz() {

  local log="$1"
  shift
  set +e
  AFL_NO_UI=1 AFL_BENCH_UNTIL_CRASH=1 timeout 10 \
    "$AFL_DIR/afl-fuzz" "$@" >"$log" 2>&1
  local rc=$?
  set -e
  if [ "$rc" -ne 0 ] && [ "$rc" -ne 124 ]; then

    cat "$log"
    return "$rc"

  fi

}

# -l M: the CmpLog stage must observe at least one new inequality-slack
# minimum, not just accept the option letter.
AFL_QUIET=1 AFL_LLVM_CMPLOG=1 "$AFL_DIR/afl-clang-fast" \
  "$SCRIPT_DIR/test-cmplog-tightness.c" -o "$TMP/m.cmplog"
AFL_QUIET=1 "$AFL_DIR/afl-clang-fast" \
  "$SCRIPT_DIR/test-cmplog-tightness.c" -o "$TMP/m"
mkdir -p "$TMP/m.in" "$TMP/m.out"
printf '\x00\x00\x00\x00' > "$TMP/m.in/seed"

run_fuzz "$TMP/m.log" -i "$TMP/m.in" -o "$TMP/m.out" \
  -c "$TMP/m.cmplog" -l 2M -V 3 -- "$TMP/m"

if grep -q "Unknown option value" "$TMP/m.log"; then
  echo "[!] cmplog -l M parser regressed"
  exit 1
fi

m_stats="$TMP/m.out/default/fuzzer_stats"
m_enabled=$(sed -n 's/^cmplog_tightness  : //p' "$m_stats" 2>/dev/null)
m_hits=$(sed -n 's/^cmplog_tight_new  : //p' "$m_stats" 2>/dev/null)
if [ "${m_enabled:-0}" != "1" ] || [ "${m_hits:-0}" -le 0 ]; then
  echo "[!] cmplog -l M did not record tightness minima"
  cat "$m_stats" "$TMP/m.log" 2>/dev/null || true
  exit 1
fi

echo "[+] cmplog -l M: tightness enabled and observed $m_hits minima"

# -l Z must not silently run against a target that lacks derive
# instrumentation. The forkserver handshake should reject it before the
# campaign starts.
AFL_QUIET=1 AFL_LLVM_BUG_ALLOCSIZE=1 "$AFL_DIR/afl-clang-fast" \
  "$SCRIPT_DIR/test-cmplog-size-derive-option.c" -o "$TMP/z-no-derive"
mkdir -p "$TMP/zbad.in" "$TMP/zbad.out"
printf '\x00' > "$TMP/zbad.in/seed"

set +e
AFL_NO_UI=1 AFL_BENCH_UNTIL_CRASH=1 timeout 10 \
  "$AFL_DIR/afl-fuzz" -i "$TMP/zbad.in" -o "$TMP/zbad.out" \
  -c 0 -l 2Z -V 3 -- "$TMP/z-no-derive" >"$TMP/zbad.log" 2>&1
zbad_rc=$?
set -e

if [ "$zbad_rc" -eq 0 ] || \
   ! grep -q "AFL_LLVM_BUG_ALLOCSIZE_DERIVE=1" "$TMP/zbad.log"; then
  echo "[!] cmplog -l Z accepted a target without size-derive support"
  cat "$TMP/zbad.log" 2>/dev/null || true
  exit 1
fi

echo "[+] cmplog -l Z: rejected target without size-derive support"

# -l Z is a fuzzer-side CmpLog option. The target must already be compiled
# with ALLOCSIZE_DERIVE; afl-fuzz must not rely on compile-time AFL_LLVM_BUG_*
# environment variables at runtime.
AFL_QUIET=1 AFL_LLVM_BUG_ALLOCSIZE=1 AFL_LLVM_BUG_ALLOCSIZE_DERIVE=1 \
  "$AFL_DIR/afl-clang-fast" \
  "$SCRIPT_DIR/test-cmplog-size-derive-option.c" -o "$TMP/z"
mkdir -p "$TMP/z.in" "$TMP/z.out"
printf '\x00' > "$TMP/z.in/seed"
marker="$TMP/z.marker"

AFL_CMPLOG_LZ_MARKER="$marker" run_fuzz "$TMP/z.log" \
  -i "$TMP/z.in" -o "$TMP/z.out" -c 0 -l 2Z -V 3 -- "$TMP/z"

if grep -q "Unknown option value" "$TMP/z.log"; then
  echo "[!] cmplog -l Z parser regressed"
  exit 1
fi

z_stats="$TMP/z.out/default/fuzzer_stats"
z_enabled=$(sed -n 's/^cmplog_size_derive: //p' "$z_stats" 2>/dev/null)
if [ "${z_enabled:-0}" != "1" ] || [ ! -s "$marker" ]; then
  echo "[!] cmplog -l Z did not run with a size-derive-capable child"
  cat "$z_stats" "$TMP/z.log" 2>/dev/null || true
  exit 1
fi

echo "[+] cmplog -l Z: option parsed and size-derive child stayed active"

# Derive-only compilation must imply ALLOCSIZE instrumentation. Without that,
# the runtime can advertise -l Z support while no allocations are tracked.
AFL_QUIET=1 AFL_LLVM_BUG_ALLOCSIZE_DERIVE=1 \
  "$AFL_DIR/afl-clang-fast" \
  "$SCRIPT_DIR/test-cmplog-size-derive-option.c" -o "$TMP/z-derive-only"
mkdir -p "$TMP/zonly.in" "$TMP/zonly.out"
printf '\x00' > "$TMP/zonly.in/seed"
marker_only="$TMP/zonly.marker"

AFL_CMPLOG_LZ_MARKER="$marker_only" run_fuzz "$TMP/zonly.log" \
  -i "$TMP/zonly.in" -o "$TMP/zonly.out" -c 0 -l 2Z -V 3 \
  -- "$TMP/z-derive-only"

zonly_stats="$TMP/zonly.out/default/fuzzer_stats"
zonly_enabled=$(sed -n 's/^cmplog_size_derive: //p' "$zonly_stats" 2>/dev/null)
if [ "${zonly_enabled:-0}" != "1" ] || [ ! -s "$marker_only" ]; then
  echo "[!] cmplog -l Z derive-only compile did not imply ALLOCSIZE support"
  cat "$zonly_stats" "$TMP/zonly.log" 2>/dev/null || true
  exit 1
fi

echo "[+] cmplog -l Z: derive-only compile implied ALLOCSIZE support"
