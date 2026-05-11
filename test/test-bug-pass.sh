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

# --- SIZEFILL DAG (PHI both arms feed same malloc) ---
# Force -O0 so the volatile-guarded if/else survives to OptimizerLast
# as a real diamond PHI.
AFL_QUIET=1 AFL_LLVM_BUG_SIZEFILL=1 "$CC" -O0 \
  "$SCRIPT_DIR/test-bug-sizefill-dag.c" -o "$TMP/sd"
set +e
printf '\x10\x00\x00\x00' | AFL_LLVM_BUG_SIZEFILL=1 "$TMP/sd" \
  >/dev/null 2>"$TMP/sderr"
sd_rc=$?
set -e
if [ "$sd_rc" -ne 0 ] && grep -q "SIZEFILL violation" "$TMP/sderr"; then
  echo "[+] SIZEFILL DAG: rc=$sd_rc (oracle wired up through DAG-shared malloc)"
else
  echo "[!] SIZEFILL DAG: rc=$sd_rc (oracle did NOT fire — DAG bug)"
  cat "$TMP/sderr" || true
  exit 1
fi

# --- SIZEFILL in/out (callee escapes out-size to a helper) ---
AFL_QUIET=1 AFL_LLVM_BUG_SIZEFILL=1 "$CC" -O0 \
  "$SCRIPT_DIR/test-bug-sizefill-inout.c" -o "$TMP/si"
set +e
printf '\x10\x00\x00\x00' | AFL_LLVM_BUG_SIZEFILL=1 "$TMP/si" \
  >/dev/null 2>"$TMP/sierr"
si_rc=$?
set -e
seen_hint=$(grep -E '^INOUT_HINT_SEEN=' "$TMP/sierr" | sed 's/.*=//')
if [ "$si_rc" -eq 0 ] && [ "${seen_hint:-0}" = "305419896" ]; then
  # 0x12345678 = 305419896
  echo "[+] SIZEFILL in/out: hint preserved across pre-zero (saw $seen_hint)"
else
  echo "[!] SIZEFILL in/out: rc=$si_rc hint=$seen_hint (pre-zero clobbered)"
  cat "$TMP/sierr" || true
  exit 1
fi

# --- SIZEFILL adjacent (nested call's writes must not pollute outer) ---
AFL_QUIET=1 AFL_LLVM_BUG_SIZEFILL=1 AFL_LLVM_BUG_ALLOCSIZE=1 "$CC" -O0 \
  "$SCRIPT_DIR/test-bug-sizefill-adjacent.c" -o "$TMP/sa"
set +e
printf '\x10\x00\x00\x00' | AFL_LLVM_BUG_SIZEFILL=1 \
  AFL_LLVM_BUG_ALLOCSIZE=1 "$TMP/sa" >/dev/null 2>"$TMP/saerr"
sa_rc=$?
set -e
if [ "$sa_rc" -eq 0 ] && ! grep -q "SIZEFILL violation" "$TMP/saerr"; then
  echo "[+] SIZEFILL adjacent: no false positive (rc=$sa_rc)"
else
  echo "[!] SIZEFILL adjacent: rc=$sa_rc (false-positive abort)"
  cat "$TMP/saerr" || true
  exit 1
fi

# --- SLACK FP precision (sub-1 |diff| must not collapse to inv=64) ---
# Build a program with a single user-level FCmp. The runtime emits map
# updates not just for our FCmp but also for FCmps inside atof() etc.,
# so we can't grep "first slot" — instead we look for ANY slot whose
# value DIFFERS between the eq and near runs. With sub-unit scaling,
# our FCmp's slot is one of the differing ones; without scaling, the
# slot's value (64 = max bucket) is identical across both runs.
AFL_QUIET=1 AFL_LLVM_BUG_SLACK=1 "$CC" \
  "$SCRIPT_DIR/test-bug-slack-fp.c" -o "$TMP/fp"
# Program exits with the FCmp result (1 for "less"); set +e for both calls.
set +e
AFL_LLVM_BUG_SLACK=1 "$TMP/fp" 1.0 1.0 2>"$TMP/fperr_eq" >/dev/null
AFL_LLVM_BUG_SLACK=1 "$TMP/fp" 1.0 1.5 2>"$TMP/fperr_near" >/dev/null
set -e
# Sort by slot so diff lines are well-defined; differ-count > 0 means
# at least one slot took different values between the two inputs.
sort "$TMP/fperr_eq" > "$TMP/fp_eq.s"
sort "$TMP/fperr_near" > "$TMP/fp_near.s"
diff_count=$(comm -3 "$TMP/fp_eq.s" "$TMP/fp_near.s" | wc -l | tr -d ' ')
if [ "${diff_count:-0}" -gt 0 ]; then
  echo "[+] SLACK FP precision: $diff_count slot diffs (sub-unit gradient preserved)"
else
  echo "[!] SLACK FP precision: 0 slot diffs (sub-unit gradient lost)"
  cat "$TMP/fperr_eq" || true
  exit 1
fi

# --- ALLOCSIZE track table ---
AFL_QUIET=1 AFL_LLVM_BUG_ALLOCSIZE=1 "$CC" -I"$AFL_DIR/include" \
  "$SCRIPT_DIR/test-bug-allocsize-track.c" -o "$TMP/at"
set +e
printf '\x00\x00\x00\x00' | AFL_LLVM_BUG_ALLOCSIZE=1 \
  "$TMP/at" >/dev/null 2>"$TMP/aterr"
at_rc=$?
set -e
tracked=$(grep -oE 'tracked=[0-9]+' "$TMP/aterr" | head -1 | sed 's/.*=//')
if [ "$at_rc" -eq 0 ] && [ "${tracked:-0}" = "2" ]; then
  echo "[+] ALLOCSIZE track: $tracked allocations recorded"
else
  echo "[!] ALLOCSIZE track: rc=$at_rc tracked=$tracked"
  cat "$TMP/aterr" || true
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
