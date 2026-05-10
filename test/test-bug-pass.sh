#!/bin/bash
# test/test-bug-pass.sh — integration test for afl-llvm-bug-pass.so
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AFL_DIR="$SCRIPT_DIR/.."
TMP=$(mktemp -d)
trap "rm -rf $TMP" EXIT

CC="$AFL_DIR/afl-clang-fast"
PLUGIN="$AFL_DIR/afl-llvm-bug-pass.so"

if [ ! -x "$CC" ] || [ ! -e "$PLUGIN" ]; then
  echo "[-] afl-clang-fast or afl-llvm-bug-pass.so not built; skipping"
  exit 0
fi

echo "[*] Testing: afl-llvm-bug-pass.so (SCALAR / BUDGET / SIZEFILL)"

# --- SCALAR ---
AFL_QUIET=1 AFL_LLVM_BUG_SCALAR=1 "$CC" \
  "$SCRIPT_DIR/test-bug-scalar.c" -o "$TMP/scalar"
small=$(printf '\x05\x00\x00\x00' | AFL_LLVM_BUG_SCALAR=1 "$TMP/scalar" 2>&1 \
        | sed -n 's/.*maxval=\([0-9]*\).*/\1/p')
big=$(  printf '\xe8\x03\x00\x00' | AFL_LLVM_BUG_SCALAR=1 "$TMP/scalar" 2>&1 \
        | sed -n 's/.*maxval=\([0-9]*\).*/\1/p')
if [ "${big:-0}" -gt "${small:-0}" ]; then
  echo "[+] SCALAR: maxval grows with input ($small -> $big)"
else
  echo "[!] SCALAR: maxval did not grow ($small -> $big)"
  exit 1
fi

# --- BUDGET ---
AFL_QUIET=1 AFL_LLVM_BUG_BUDGET=1 "$CC" \
  "$SCRIPT_DIR/test-bug-budget-good.c" -o "$TMP/bg"
AFL_QUIET=1 AFL_LLVM_BUG_BUDGET=1 "$CC" \
  "$SCRIPT_DIR/test-bug-budget-bad.c" -o "$TMP/bb"
set +e
printf '\x10\x00\x00\x00' | AFL_LLVM_BUG_BUDGET=1 "$TMP/bg" >/dev/null 2>/dev/null
g=$?
printf '\x10\x00\x00\x00' | AFL_LLVM_BUG_BUDGET=1 "$TMP/bb" >/dev/null 2>"$TMP/bberr"
b=$?
set -e
if [ $g -eq 0 ] && [ $b -ne 0 ] && grep -q "BUDGET violation" "$TMP/bberr"; then
  echo "[+] BUDGET: good=0 bad=$b (caught)"
else
  echo "[!] BUDGET: good=$g bad=$b"
  cat "$TMP/bberr" || true
  exit 1
fi

# --- SIZEFILL ---
AFL_QUIET=1 AFL_LLVM_BUG_SIZEFILL=1 "$CC" \
  "$SCRIPT_DIR/test-bug-sizefill-good.c" -o "$TMP/sg"
AFL_QUIET=1 AFL_LLVM_BUG_SIZEFILL=1 "$CC" \
  "$SCRIPT_DIR/test-bug-sizefill-bad.c" -o "$TMP/sb"
set +e
printf '\x10\x00\x00\x00' | AFL_LLVM_BUG_SIZEFILL=1 "$TMP/sg" >/dev/null 2>/dev/null
g=$?
printf '\x10\x00\x00\x00' | AFL_LLVM_BUG_SIZEFILL=1 "$TMP/sb" >/dev/null 2>"$TMP/sberr"
b=$?
set -e
if [ $g -eq 0 ] && [ $b -ne 0 ] && grep -q "SIZEFILL violation" "$TMP/sberr"; then
  echo "[+] SIZEFILL: good=0 bad=$b (caught)"
else
  echo "[!] SIZEFILL: good=$g bad=$b"
  cat "$TMP/sberr" || true
  exit 1
fi

# --- ALLOCSIZE ---
AFL_QUIET=1 AFL_LLVM_BUG_ALLOCSIZE=1 "$CC" \
  "$SCRIPT_DIR/test-bug-allocsize-good.c" -o "$TMP/ag"
AFL_QUIET=1 AFL_LLVM_BUG_ALLOCSIZE=1 "$CC" \
  "$SCRIPT_DIR/test-bug-allocsize-bad.c" -o "$TMP/ab"
AFL_QUIET=1 AFL_LLVM_BUG_ALLOCSIZE=1 "$CC" \
  "$SCRIPT_DIR/test-bug-allocsize-near.c" -o "$TMP/an"
AFL_QUIET=1 AFL_LLVM_BUG_ALLOCSIZE=1 \
  AFL_LLVM_BUG_ALLOCSIZE_FUNCS=MyAlloc "$CC" \
  "$SCRIPT_DIR/test-bug-allocsize-custom.c" -o "$TMP/ac"

set +e
printf '\x10\x00\x00\x00' | AFL_LLVM_BUG_ALLOCSIZE=1 "$TMP/ag" >/dev/null 2>/dev/null
g=$?
printf '\x10\x00\x00\x00' | AFL_LLVM_BUG_ALLOCSIZE=1 "$TMP/ab" >/dev/null 2>"$TMP/aberr"
b=$?
printf '\x00\x00\x00\x00' | AFL_LLVM_BUG_ALLOCSIZE=1 \
  AFL_LLVM_BUG_ALLOCSIZE_FUNCS=MyAlloc "$TMP/ac" >/dev/null 2>"$TMP/acerr"
c=$?
small=$(printf '\x04\x00\x00\x00' | AFL_LLVM_BUG_ALLOCSIZE=1 "$TMP/an" 2>&1 \
        | sed -n 's/.*maxval=\([0-9]*\).*/\1/p')
big=$(  printf '\x3e\x00\x00\x00' | AFL_LLVM_BUG_ALLOCSIZE=1 "$TMP/an" 2>&1 \
        | sed -n 's/.*maxval=\([0-9]*\).*/\1/p')
set -e

if [ $g -eq 0 ] && [ $b -ne 0 ] && \
   grep -q "ALLOCSIZE soft-OOB" "$TMP/aberr" && \
   [ $c -ne 0 ] && grep -q "ALLOCSIZE soft-OOB" "$TMP/acerr" && \
   [ "${big:-0}" -gt "${small:-0}" ]; then
  echo "[+] ALLOCSIZE: good=0 bad=$b custom=$c headroom=$small->$big"
else
  echo "[!] ALLOCSIZE: good=$g bad=$b custom=$c headroom=$small->$big"
  cat "$TMP/aberr" "$TMP/acerr" || true
  exit 1
fi

# --- ALLOCSIZE_DERIVE ---
AFL_QUIET=1 AFL_LLVM_BUG_ALLOCSIZE=1 AFL_LLVM_BUG_ALLOCSIZE_DERIVE=1 \
  "$CC" -I"$AFL_DIR/include" \
  "$SCRIPT_DIR/test-bug-allocsize-derive.c" -o "$TMP/ad"
set +e
printf '\x00\x00\x00\x00' | AFL_LLVM_BUG_ALLOCSIZE=1 \
  AFL_LLVM_BUG_ALLOCSIZE_DERIVE=1 AFL_CMPLOG_DEBUG=1 \
  "$TMP/ad" 2>"$TMP/ad.err" >/dev/null
ad_rc=$?
set -e

if [ "$ad_rc" -eq 0 ] && grep -q "size=64 off=" "$TMP/ad.err"; then
  echo "[+] ALLOCSIZE_DERIVE: $(grep BUG_ALLOCSIZE_DERIVE $TMP/ad.err)"
else
  echo "[!] ALLOCSIZE_DERIVE: rc=$ad_rc"
  cat "$TMP/ad.err" || true
  exit 1
fi

echo "[+] all bug-pass tests passed"
