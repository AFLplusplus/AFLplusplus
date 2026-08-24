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

unset AFL_LLVM_BUG AFL_LLVM_BUG_SCALAR AFL_LLVM_BUG_BUDGET
unset AFL_LLVM_BUG_SIZEFILL AFL_LLVM_BUG_SLACK AFL_LLVM_BUG_ALLOCSIZE
unset AFL_LLVM_BUG_ALLOCSIZE_FUNCS AFL_LLVM_BUG_ALLOCSIZE_FREE_FUNCS
unset AFL_LLVM_BUG_ALLOCSIZE_DERIVE AFL_LLVM_BUG_SCALAR_SLICE
unset AFL_LLVM_CMPLOG
# ALLOCSIZE / DERIVE are disabled under sanitizers by the bug-pass
# runtime (see docs/env_variables.md). Strip any sanitizer envs so the
# tests exercise the full oracle set regardless of the user's shell.
unset AFL_USE_ASAN AFL_USE_MSAN AFL_USE_UBSAN AFL_USE_TSAN AFL_USE_LSAN

echo "[*] Testing: afl-llvm-bug-pass.so (SCALAR / BUDGET / SIZEFILL / SLACK / ALLOCSIZE / DERIVE)"

# --- Aggregate selector ---
AFL_QUIET=1 AFL_LLVM_BUG=1 "$CC" -S -emit-llvm \
  "$SCRIPT_DIR/test-bug-scalar.c" -o "$TMP/all_scalar.ll"
AFL_QUIET=1 AFL_LLVM_BUG=1 "$CC" -S -emit-llvm \
  "$SCRIPT_DIR/test-bug-budget-bad.c" -o "$TMP/all_budget.ll"
AFL_QUIET=1 AFL_LLVM_BUG=1 "$CC" -S -emit-llvm \
  "$SCRIPT_DIR/test-bug-sizefill-bad.c" -o "$TMP/all_sizefill.ll"
AFL_QUIET=1 AFL_LLVM_BUG=1 "$CC" -S -emit-llvm \
  "$SCRIPT_DIR/test-bug-allocsize-bad.c" -o "$TMP/all_allocsize.ll"
AFL_QUIET=1 AFL_LLVM_BUG=1 "$CC" -S -emit-llvm \
  "$SCRIPT_DIR/test-bug-slack-int.c" -o "$TMP/all_slack.ll"
AFL_QUIET=1 AFL_LLVM_BUG=1 "$CC" -I"$AFL_DIR/include" \
  "$SCRIPT_DIR/test-bug-allocsize-derive.c" -o "$TMP/all_derive"
set +e
printf '\x00\x00\x00\x00' | AFL_CMPLOG_DEBUG=1 \
  "$TMP/all_derive" 2>"$TMP/all_derive.err" >/dev/null
all_derive_rc=$?
set -e
if grep -q "call.*__afl_bug_scalar_max" "$TMP/all_scalar.ll" && \
   grep -q "call.*__afl_bug_ws_begin" "$TMP/all_budget.ll" && \
   grep -q "call.*__afl_bug_sf_begin" "$TMP/all_sizefill.ll" && \
   grep -q "call.*__afl_alloc_oracle" "$TMP/all_allocsize.ll" && \
   grep -q "call.*__afl_bug_slack_min" "$TMP/all_slack.ll" && \
   [ "$all_derive_rc" -eq 0 ] && \
   grep -q "size=64 off=" "$TMP/all_derive.err"; then
  echo "[+] AFL_LLVM_BUG=1: aggregate selector enables all bug-pass modes"
else
  echo "[!] AFL_LLVM_BUG=1: aggregate selector did not enable every bug-pass mode"
  cat "$TMP/all_derive.err" 2>/dev/null || true
  exit 1
fi

# --- SCALAR ---
AFL_QUIET=1 AFL_LLVM_BUG_SCALAR=1 "$CC" \
  "$SCRIPT_DIR/test-bug-scalar.c" -o "$TMP/scalar"
small=$(printf '\x05\x00\x00\x00' | "$TMP/scalar" 2>&1 \
        | sed -n 's/.*maxval=\([0-9]*\).*/\1/p')
big=$(  printf '\xe8\x03\x00\x00' | "$TMP/scalar" 2>&1 \
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
AFL_QUIET=1 AFL_LLVM_BUG_BUDGET=1 "$CC" \
  "$SCRIPT_DIR/test-bug-budget-argstore.c" -o "$TMP/ba"
AFL_QUIET=1 AFL_LLVM_BUG_BUDGET=1 "$CC" \
  "$SCRIPT_DIR/test-bug-budget-memset.c" -o "$TMP/bm"
set +e
printf '\x10\x00\x00\x00' | "$TMP/bg" >/dev/null 2>/dev/null
g=$?
printf '\x10\x00\x00\x00' | "$TMP/bb" >/dev/null 2>"$TMP/bberr"
b=$?
printf '\x10\x00\x00\x00' | "$TMP/ba" >/dev/null 2>"$TMP/baerr"
ba=$?
printf '\x10\x00\x00\x00' | "$TMP/bm" >/dev/null 2>"$TMP/bmerr"
bm=$?
set -e
if [ $g -eq 0 ] && [ $b -ne 0 ] && grep -q "BUDGET violation" "$TMP/bberr" && \
   [ $ba -ne 0 ] && grep -q "BUDGET violation" "$TMP/baerr" && \
   [ $bm -ne 0 ] && grep -q "BUDGET violation" "$TMP/bmerr"; then
  echo "[+] BUDGET: good=0 bad=$b argstore=$ba memset=$bm (caught)"
else
  echo "[!] BUDGET: good=$g bad=$b argstore=$ba memset=$bm"
  cat "$TMP/bberr" "$TMP/baerr" "$TMP/bmerr" || true
  exit 1
fi

AFL_QUIET=1 AFL_LLVM_BUG_BUDGET=1 "$CC" -S -emit-llvm \
  "$SCRIPT_DIR/test-bug-huge-copy.c" -o "$TMP/huge_budget.ll"
if grep -q "call.*__afl_bug_ws_store" "$TMP/huge_budget.ll"; then
  echo "[!] BUDGET: huge constant copy length was truncated into ws_store"
  exit 1
fi
echo "[+] BUDGET: huge constant copy lengths skipped without runtime guard"

# --- SIZEFILL ---
AFL_QUIET=1 AFL_LLVM_BUG_SIZEFILL=1 "$CC" \
  "$SCRIPT_DIR/test-bug-sizefill-good.c" -o "$TMP/sg"
AFL_QUIET=1 AFL_LLVM_BUG_SIZEFILL=1 "$CC" \
  "$SCRIPT_DIR/test-bug-sizefill-bad.c" -o "$TMP/sb"
AFL_QUIET=1 AFL_LLVM_BUG_SIZEFILL=1 "$CC" \
  "$SCRIPT_DIR/test-bug-sizefill-memset.c" -o "$TMP/sm"
set +e
printf '\x10\x00\x00\x00' | "$TMP/sg" >/dev/null 2>/dev/null
g=$?
printf '\x10\x00\x00\x00' | "$TMP/sb" >/dev/null 2>"$TMP/sberr"
b=$?
printf '\x10\x00\x00\x00' | "$TMP/sm" >/dev/null 2>"$TMP/smerr"
sm=$?
set -e
if [ $g -eq 0 ] && [ $b -ne 0 ] && grep -q "SIZEFILL violation" "$TMP/sberr" && \
   [ $sm -ne 0 ] && grep -q "SIZEFILL violation" "$TMP/smerr"; then
  echo "[+] SIZEFILL: good=0 bad=$b memset=$sm (caught)"
else
  echo "[!] SIZEFILL: good=$g bad=$b memset=$sm"
  cat "$TMP/sberr" "$TMP/smerr" || true
  exit 1
fi

AFL_QUIET=1 AFL_LLVM_BUG_SIZEFILL=1 "$CC" -S -emit-llvm \
  "$SCRIPT_DIR/test-bug-huge-copy.c" -o "$TMP/huge_sizefill.ll"
if grep -q "call.*__afl_bug_sf_store" "$TMP/huge_sizefill.ll"; then
  echo "[!] SIZEFILL: huge constant copy length was truncated into sf_store"
  exit 1
fi
echo "[+] SIZEFILL: huge constant copy lengths skipped without runtime guard"

# --- Runtime map sizing ---
dump_map_size() {
  local out rc
  set +e
  out=$(AFL_DUMP_MAP_SIZE=1 "$1" 2>/dev/null)
  rc=$?
  set -e
  if [ -z "$out" ]; then
    echo "[!] map-size dump failed for $1 (rc=$rc)" >&2
    return 1
  fi
  printf '%s\n' "$out" | tail -1
}

AFL_QUIET=1 "$CC" "$SCRIPT_DIR/test-bug-scalar.c" -o "$TMP/map_plain"
AFL_QUIET=1 AFL_LLVM_BUG_BUDGET=1 "$CC" \
  "$SCRIPT_DIR/test-bug-scalar.c" -o "$TMP/map_budget"
AFL_QUIET=1 AFL_LLVM_BUG_SIZEFILL=1 "$CC" \
  "$SCRIPT_DIR/test-bug-scalar.c" -o "$TMP/map_sizefill"
AFL_QUIET=1 AFL_LLVM_BUG_SCALAR=1 "$CC" \
  "$SCRIPT_DIR/test-bug-scalar.c" -o "$TMP/map_scalar"
plain_map=$(dump_map_size "$TMP/map_plain")
budget_map=$(dump_map_size "$TMP/map_budget")
sizefill_map=$(dump_map_size "$TMP/map_sizefill")
scalar_map=$(dump_map_size "$TMP/map_scalar")
bug_map_bytes=$((16384 * 4))
if [ "$budget_map" -eq "$plain_map" ] && \
   [ "$sizefill_map" -eq "$plain_map" ] && \
   [ "$scalar_map" -eq $((plain_map + bug_map_bytes)) ]; then
  echo "[+] runtime map sizing: abort-only modes keep base map, SCALAR appends bug map"
else
  echo "[!] runtime map sizing: plain=$plain_map budget=$budget_map sizefill=$sizefill_map scalar=$scalar_map"
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
AFL_QUIET=1 AFL_LLVM_BUG_ALLOCSIZE=1 "$CC" \
  "$SCRIPT_DIR/test-bug-allocsize-helper.c" -o "$TMP/ah"
AFL_QUIET=1 AFL_LLVM_BUG_ALLOCSIZE=1 \
  AFL_LLVM_BUG_ALLOCSIZE_FUNCS=MyAlloc \
  AFL_LLVM_BUG_ALLOCSIZE_FREE_FUNCS=MyFree "$CC" -I"$AFL_DIR/include" \
  "$SCRIPT_DIR/test-bug-allocsize-custom-free.c" -o "$TMP/af"

set +e
printf '\x10\x00\x00\x00' | "$TMP/ag" >/dev/null 2>/dev/null
g=$?
printf '\x10\x00\x00\x00' | "$TMP/ab" >/dev/null 2>"$TMP/aberr"
b=$?
printf '\x00\x00\x00\x00' | "$TMP/ac" >/dev/null 2>"$TMP/acerr"
c=$?
printf '\x10\x00\x00\x00' | "$TMP/ah" >/dev/null 2>"$TMP/aherr"
ah=$?
printf '\x00\x00\x00\x00' | "$TMP/af" >/dev/null 2>"$TMP/aferr"
af=$?
small=$(printf '\x04\x00\x00\x00' | "$TMP/an" 2>&1 \
        | sed -n 's/.*maxval=\([0-9]*\).*/\1/p')
big=$(  printf '\x3e\x00\x00\x00' | "$TMP/an" 2>&1 \
        | sed -n 's/.*maxval=\([0-9]*\).*/\1/p')
freed_tracked=$(grep -oE 'tracked=[0-9]+' "$TMP/aferr" | head -1 | sed 's/.*=//')
set -e

if [ $g -eq 0 ] && [ $b -ne 0 ] && \
   grep -q "ALLOCSIZE soft-OOB" "$TMP/aberr" && \
   [ $c -ne 0 ] && grep -q "ALLOCSIZE soft-OOB" "$TMP/acerr" && \
   [ $ah -ne 0 ] && grep -q "ALLOCSIZE soft-OOB" "$TMP/aherr" && \
   [ $af -eq 0 ] && [ "${freed_tracked:-1}" = "0" ] && \
   [ "${big:-0}" -gt "${small:-0}" ]; then
  echo "[+] ALLOCSIZE: good=0 bad=$b custom=$c helper=$ah free=$freed_tracked headroom=$small->$big"
else
  echo "[!] ALLOCSIZE: good=$g bad=$b custom=$c helper=$ah free_rc=$af free_tracked=$freed_tracked headroom=$small->$big"
  cat "$TMP/aberr" "$TMP/acerr" "$TMP/aherr" "$TMP/aferr" || true
  exit 1
fi

# --- Runtime activation without run-time AFL_LLVM_BUG_* env ---
auto=$(printf '\xe8\x03\x00\x00' | "$TMP/scalar" 2>&1 \
       | sed -n 's/.*maxval=\([0-9]*\).*/\1/p')
if [ "${auto:-0}" -gt 0 ]; then
  echo "[+] runtime auto-activation: scalar hooks active without run-time env"
else
  echo "[!] runtime auto-activation failed: maxval=${auto:-unset}"
  exit 1
fi

# --- SIZEFILL DAG (PHI both arms feed same malloc) ---
# Force -O0 so the volatile-guarded if/else survives to OptimizerLast
# as a real diamond PHI.
AFL_QUIET=1 AFL_LLVM_BUG_SIZEFILL=1 "$CC" -O0 \
  "$SCRIPT_DIR/test-bug-sizefill-dag.c" -o "$TMP/sd"
set +e
printf '\x10\x00\x00\x00' | "$TMP/sd" \
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
printf '\x10\x00\x00\x00' | "$TMP/si" \
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
printf '\x10\x00\x00\x00' | "$TMP/sa" >/dev/null 2>"$TMP/saerr"
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
# --- SLACK integer gradient (closer-to-magic should score higher) ---
# NOTE: the bug pass intentionally ignores AFL_LLVM_ALLOWLIST (it would break
# cross-function bug tracking), so target_cmp is NOT the only instrumented
# comparison.  test-bug-slack-int.c isolates target_cmp's slack slot itself by
# clearing+snapshotting the bug map around the call, so no allowlist is needed.
AFL_QUIET=1 AFL_LLVM_BUG_SLACK=1 \
  "$CC" "$SCRIPT_DIR/test-bug-slack-int.c" -o "$TMP/slack_int"
slack_far=$("$TMP/slack_int" 0 2>&1 \
            | sed -n 's/.*maxval=\([0-9]*\).*/\1/p')
slack_near=$("$TMP/slack_int" 0x12345677 2>&1 \
             | sed -n 's/.*maxval=\([0-9]*\).*/\1/p')
slack_exact=$("$TMP/slack_int" 0x12345678 2>&1 \
              | sed -n 's/.*maxval=\([0-9]*\).*/\1/p')
if [ "${slack_near:-0}" -gt "${slack_far:-0}" ] && \
   [ "${slack_exact:-0}" -gt "${slack_near:-0}" ]; then
  echo "[+] SLACK int gradient: far=$slack_far near=$slack_near exact=$slack_exact"
else
  echo "[!] SLACK int gradient: far=$slack_far near=$slack_near exact=$slack_exact"
  exit 1
fi

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
"$TMP/fp" 1.0 1.0 2>"$TMP/fperr_eq" >/dev/null
"$TMP/fp" 1.0 1.5 2>"$TMP/fperr_near" >/dev/null
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
printf '\x00\x00\x00\x00' | "$TMP/at" >/dev/null 2>"$TMP/aterr"
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
printf '\x00\x00\x00\x00' | AFL_CMPLOG_DEBUG=1 \
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

AFL_QUIET=1 AFL_LLVM_BUG_ALLOCSIZE_DERIVE=1 \
  "$CC" -I"$AFL_DIR/include" \
  "$SCRIPT_DIR/test-bug-allocsize-derive.c" -o "$TMP/ad_only"
set +e
printf '\x00\x00\x00\x00' | AFL_CMPLOG_DEBUG=1 \
  "$TMP/ad_only" 2>"$TMP/ad_only.err" >/dev/null
ad_only_rc=$?
set -e

if [ "$ad_only_rc" -eq 0 ] && grep -q "size=64 off=" "$TMP/ad_only.err"; then
  echo "[+] ALLOCSIZE_DERIVE-only: implied ALLOCSIZE instrumentation"
else
  echo "[!] ALLOCSIZE_DERIVE-only: rc=$ad_only_rc"
  cat "$TMP/ad_only.err" || true
  exit 1
fi

# --- ALLOCSIZE persistent-state reset ---
if [ -x "$AFL_DIR/afl-fuzz" ]; then

  AFL_QUIET=1 AFL_LLVM_BUG_ALLOCSIZE=1 "$CC" -I"$AFL_DIR/include" \
    "$SCRIPT_DIR/test-bug-allocsize-persistent.c" -o "$TMP/ap"
  mkdir -p "$TMP/ap.in" "$TMP/ap.out"
  printf '\x01' > "$TMP/ap.in/seed"
  marker="$TMP/ap.marker"
  set +e
  AFL_NO_UI=1 AFL_BENCH_UNTIL_CRASH=1 AFL_IGNORE_UNKNOWN_ENVS=1 \
    AFL_BUG_PERSISTENT_RESET_MARKER="$marker" \
    timeout 10 "$AFL_DIR/afl-fuzz" -i "$TMP/ap.in" -o "$TMP/ap.out" \
    -V 5 -- "$TMP/ap" >"$TMP/ap.log" 2>&1
  ap_rc=$?
  set -e
  if { [ "$ap_rc" -eq 0 ] || [ "$ap_rc" -eq 124 ]; } && [ -s "$marker" ]; then
    echo "[+] ALLOCSIZE persistent reset: per-input fields cleared across __AFL_LOOP"
  else
    echo "[!] ALLOCSIZE persistent reset: rc=$ap_rc"
    cat "$TMP/ap.log" 2>/dev/null || true
    exit 1
  fi

else

  echo "[-] ALLOCSIZE persistent reset: afl-fuzz missing; skipping"

fi

# --- calloc overflow ordering (regression for the BLOCKER 6 fix) ---
AFL_QUIET=1 AFL_LLVM_BUG_ALLOCSIZE=1 "$CC" -O0 \
  "$SCRIPT_DIR/test-bug-calloc-overflow.c" -o "$TMP/co"
set +e
printf '' | "$TMP/co" 2>"$TMP/co.err"
co_rc=$?
set -e
if [ "$co_rc" -eq 0 ] && ! grep -q "calloc returned non-NULL" "$TMP/co.err"; then
  echo "[+] calloc overflow: __afl_track_calloc returns NULL cleanly (rc=0)"
else
  echo "[!] calloc overflow: rc=$co_rc"
  cat "$TMP/co.err" || true
  exit 1
fi

# --- realloc semantics: shrink-to-zero / NULL-in / failure (BLOCKER 8 fix) ---
AFL_QUIET=1 AFL_LLVM_BUG_ALLOCSIZE=1 "$CC" \
  "$SCRIPT_DIR/test-bug-realloc-fail.c" -o "$TMP/rf"
set +e
"$TMP/rf" 2>"$TMP/rf.err"
rf_rc=$?
set -e
if [ "$rf_rc" -eq 0 ] && \
   ! grep -q "ALLOCSIZE soft-OOB" "$TMP/rf.err" && \
   grep -q "path-a" "$TMP/rf.err" && grep -q "path-c" "$TMP/rf.err" && \
   grep -qE "path-b-(succ|fail)" "$TMP/rf.err"; then
  pb=$(grep -oE 'path-b-(succ|fail)' "$TMP/rf.err" | head -1)
  echo "[+] realloc semantics: paths a/c covered, $pb (no spurious abort)"
else
  echo "[!] realloc semantics: rc=$rf_rc"
  cat "$TMP/rf.err" || true
  exit 1
fi

# --- __libc_memalign must be rewritten to __afl_track_aligned_alloc ---
cat > "$TMP/lm.c" <<'EOF'
#include <stddef.h>
extern void *__libc_memalign(size_t alignment, size_t size);
int main(void) {
  void *p = __libc_memalign(64, 256);
  return p ? 0 : 1;
}
EOF
AFL_QUIET=1 AFL_LLVM_BUG_ALLOCSIZE=1 "$CC" -S -emit-llvm \
  "$TMP/lm.c" -o "$TMP/lm.ll" 2>/dev/null
if grep -q "call.*__afl_track_aligned_alloc" "$TMP/lm.ll"; then
  echo "[+] __libc_memalign rewritten to __afl_track_aligned_alloc"
else
  echo "[!] __libc_memalign NOT rewritten as expected"
  grep -E "call.*_memalign|call.*__afl_track" "$TMP/lm.ll" | head
  exit 1
fi

# --- AFL_LLVM_BUG_SCALAR_SLICE alone must activate SCALAR ---
# (SCALAR's loop-counter hook always fires; the arithmetic-site hook
# is filtered to memory-size sinks under SLICE, so we look for the
# loop hook as the unambiguous SCALAR signal.)
unset AFL_LLVM_BUG_SCALAR
AFL_QUIET=1 AFL_LLVM_BUG_SCALAR_SLICE=1 "$CC" -S -emit-llvm \
  "$SCRIPT_DIR/test-bug-scalar.c" -o "$TMP/ss.ll" 2>/dev/null
if grep -qE "call.*__afl_bug_(loop_iter_flush|scalar_max)" "$TMP/ss.ll"; then
  echo "[+] SCALAR_SLICE implies SCALAR (loop/scalar hooks present)"
else
  echo "[!] SCALAR_SLICE did NOT activate SCALAR"
  exit 1
fi

# --- SCALAR + C++ -fexceptions: loop body that may throw must still
#     compile without "Instruction does not dominate all uses" or
#     LandingPad-position verifier errors. ---
CXX="$AFL_DIR/afl-clang-fast++"
if [ -x "$CXX" ]; then

  cat > "$TMP/eh.cc" <<'EOF'
#include <cstdio>
#include <cstdlib>
#include <new>
struct Foo { ~Foo() { puts("dtor"); } };
static void mayThrow(int i) { if (i == 13) throw std::bad_alloc(); }
int main(int argc, char **argv) {
  (void)argv;
  int sum = 0;
  try {
    for (int i = 0; i < argc + 4; ++i) {
      Foo f;
      mayThrow(i);
      sum += i;
    }
  } catch (...) { sum = -1; }
  printf("sum=%d\n", sum);
  return 0;
}
EOF
  set +e
  AFL_QUIET=1 AFL_LLVM_BUG_SCALAR=1 "$CXX" -fexceptions -O2 \
    "$TMP/eh.cc" -o "$TMP/eh" 2>"$TMP/eh.err"
  eh_rc=$?
  set -e
  if [ "$eh_rc" -eq 0 ]; then
    echo "[+] SCALAR + C++ -fexceptions: compiled clean (no invalid IR)"
  else
    echo "[!] SCALAR + -fexceptions failed to compile"
    cat "$TMP/eh.err" 2>/dev/null || true
    exit 1
  fi

  AFL_QUIET=1 AFL_LLVM_BUG_ALLOCSIZE=1 "$CXX" -O0 -S -emit-llvm \
    "$SCRIPT_DIR/test-bug-allocsize-nothrow-new.cc" -o "$TMP/ntnew.ll" 2>/dev/null
  ntnew_track=$(grep -c "call.*__afl_track_malloc" "$TMP/ntnew.ll" || true)
  ntnew_raw=$(grep -c "call.*_ZnamRKSt9nothrow_t" "$TMP/ntnew.ll" || true)
  AFL_QUIET=1 AFL_LLVM_BUG_ALLOCSIZE=1 "$CXX" -O0 \
    "$SCRIPT_DIR/test-bug-allocsize-nothrow-new.cc" -o "$TMP/ntnew"
  set +e
  "$TMP/ntnew" 2>"$TMP/ntnew.err"
  ntnew_rc=$?
  set -e
  if [ "${ntnew_track:-0}" -ge 1 ] && [ "${ntnew_raw:-0}" -eq 0 ] && \
     [ "$ntnew_rc" -eq 0 ]; then
    echo "[+] ALLOCSIZE nothrow new: rewritten and runtime clean"
  else
    echo "[!] ALLOCSIZE nothrow new: track=$ntnew_track raw=$ntnew_raw rc=$ntnew_rc"
    grep -E "_ZnamRKSt9nothrow_t|__afl_track_malloc" "$TMP/ntnew.ll" | head
    cat "$TMP/ntnew.err" 2>/dev/null || true
    exit 1
  fi

fi

# Issue: granule-collision in __afl_alloc_unregister.  Two small allocs
# that share a 64-byte shadow granule: the shadow only holds the newer
# alloc's idx, so freeing the older alloc without a fallback scan
# silently leaves its record marked LIVE.  We inspect the record table
# directly to assert no leak.
AFL_QUIET=1 AFL_LLVM_BUG_ALLOCSIZE=1 "$CC" -O0 -I"$AFL_DIR/include" \
  "$SCRIPT_DIR/test-bug-allocsize-granule.c" -o "$TMP/ag2"
set +e
"$TMP/ag2" 2>"$TMP/ag2.err"
ag2_rc=$?
set -e
if [ "$ag2_rc" -eq 0 ] && grep -q "^ok$" "$TMP/ag2.err"; then
  echo "[+] granule unregister: no stale record after granule-shared free"
else
  echo "[!] granule unregister: rc=$ag2_rc"
  cat "$TMP/ag2.err" || true
  exit 1
fi

# Shared-granule oracle fallback: same granule, multiple live records.
AFL_QUIET=1 AFL_LLVM_BUG_ALLOCSIZE=1 "$CC" -O0 -I"$AFL_DIR/include" \
  "$SCRIPT_DIR/test-bug-allocsize-granule-oob.c" -o "$TMP/agog"
AFL_QUIET=1 AFL_LLVM_BUG_ALLOCSIZE=1 "$CC" -O0 -I"$AFL_DIR/include" \
  "$SCRIPT_DIR/test-bug-allocsize-granule-unpaint.c" -o "$TMP/agup"
AFL_QUIET=1 AFL_LLVM_BUG_ALLOCSIZE=1 "$CC" -O0 -I"$AFL_DIR/include" \
  "$SCRIPT_DIR/test-bug-allocsize-granule-inbounds.c" -o "$TMP/agin"
set +e
"$TMP/agog" 2>"$TMP/agog.err"
agog_rc=$?
"$TMP/agup" 2>"$TMP/agup.err"
agup_rc=$?
"$TMP/agin" 2>"$TMP/agin.err"
agin_rc=$?
set -e
if [ "$agog_rc" -ne 0 ] && grep -q "ALLOCSIZE soft-OOB" "$TMP/agog.err" && \
   [ "$agup_rc" -ne 0 ] && grep -q "ALLOCSIZE soft-OOB" "$TMP/agup.err" && \
   [ "$agin_rc" -eq 0 ]; then
  echo "[+] ALLOCSIZE granule oracle: shared-granule OOB caught, inbounds clean"
else
  echo "[!] ALLOCSIZE granule oracle: oob=$agog_rc unpaint=$agup_rc inbounds=$agin_rc"
  cat "$TMP/agog.err" "$TMP/agup.err" "$TMP/agin.err" || true
  exit 1
fi

# --- SCALAR covers UDiv/SDiv/URem/SRem ---
AFL_QUIET=1 AFL_LLVM_BUG_SCALAR=1 "$CC" -S -emit-llvm \
  "$SCRIPT_DIR/test-bug-scalar-div.c" -o "$TMP/sdv.ll" 2>/dev/null
hits=$(awk '/= (udiv|urem|sdiv|srem) i/{op=$0; getline n; if(n~/__afl_bug_scalar_max/) print n}' \
  "$TMP/sdv.ll" | wc -l | tr -d ' ')
if [ "${hits:-0}" -ge 4 ]; then
  echo "[+] SCALAR div/rem: $hits div/rem sites instrumented"
else
  echo "[!] SCALAR div/rem: only $hits sites instrumented (expected >= 4)"
  exit 1
fi

# --- SCALAR ignores AFL-generated coverage-counter arithmetic ---
AFL_QUIET=1 AFL_LLVM_BUG_SCALAR=1 "$CC" -O2 -S -emit-llvm \
  "$SCRIPT_DIR/test-bug-scalar-empty.c" -o "$TMP/sempty.ll" 2>/dev/null
empty_scalar_calls=$(grep -c "call.*__afl_bug_scalar_max" "$TMP/sempty.ll" || true)
if [ "${empty_scalar_calls:-0}" -eq 0 ]; then
  echo "[+] SCALAR internal skip: no hooks on AFL coverage arithmetic"
else
  echo "[!] SCALAR internal skip: found $empty_scalar_calls scalar hook(s)"
  grep -n "__afl_bug_scalar_max" "$TMP/sempty.ll" | head
  exit 1
fi

# --- SCALAR+SLACK keeps comparison-distance guidance ---
printf 'fun: target_scalar_slack\n' > "$TMP/scalar_slack.allow"
AFL_QUIET=1 AFL_LLVM_BUG_SCALAR=1 AFL_LLVM_BUG_SLACK=1 \
  AFL_LLVM_ALLOWLIST="$TMP/scalar_slack.allow" \
  "$CC" -O2 -S -emit-llvm \
  "$SCRIPT_DIR/test-bug-scalar-slack-dedup.c" -o "$TMP/ssd.ll" 2>/dev/null
ssd_scalar=$(grep -c "call.*__afl_bug_scalar_max" "$TMP/ssd.ll" || true)
ssd_slack=$(grep -c "call.*__afl_bug_slack_min" "$TMP/ssd.ll" || true)
if [ "${ssd_scalar:-0}" -ge 1 ] && [ "${ssd_slack:-0}" -ge 1 ]; then
  echo "[+] SCALAR+SLACK: scalar=$ssd_scalar slack=$ssd_slack hooks coexist"
else
  echo "[!] SCALAR+SLACK: scalar=$ssd_scalar slack=$ssd_slack"
  grep -E "__afl_bug_(scalar_max|slack_min)|icmp" "$TMP/ssd.ll" | head
  exit 1
fi

# --- SLACK on SwitchInst (gradient + IR hook count) ---
# As with the integer gradient above, the bug pass ignores AFL_LLVM_ALLOWLIST;
# test-bug-slack-switch.c isolates target_switch's slack slot by
# clearing+snapshotting the bug map around the call.
AFL_QUIET=1 AFL_LLVM_BUG_SLACK=1 \
  "$CC" "$SCRIPT_DIR/test-bug-slack-switch.c" -o "$TMP/slack_sw"
sw_far=$("$TMP/slack_sw" 0          2>&1 | sed -n 's/.*maxval=\([0-9]*\).*/\1/p')
sw_near=$("$TMP/slack_sw" 0x1001    2>&1 | sed -n 's/.*maxval=\([0-9]*\).*/\1/p')
sw_exact=$("$TMP/slack_sw" 0x1000   2>&1 | sed -n 's/.*maxval=\([0-9]*\).*/\1/p')
if [ "${sw_exact:-0}" -gt "${sw_near:-0}" ] && \
   [ "${sw_near:-0}" -gt "${sw_far:-0}" ]; then
  echo "[+] SLACK switch: gradient far=$sw_far near=$sw_near exact=$sw_exact"
else
  echo "[!] SLACK switch: far=$sw_far near=$sw_near exact=$sw_exact"
  exit 1
fi

# --- SIZEFILL accepts uint32_t* out_size on 64-bit ---
AFL_QUIET=1 AFL_LLVM_BUG_SIZEFILL=1 "$CC" -O0 \
  "$SCRIPT_DIR/test-bug-sizefill-u32out.c" -o "$TMP/sfu"
set +e
printf '\x00\x00\x00\x00' | "$TMP/sfu" 2>"$TMP/sfu.err"
sfu_rc=$?
set -e
if [ "$sfu_rc" -ne 0 ] && grep -q "SIZEFILL violation" "$TMP/sfu.err"; then
  echo "[+] SIZEFILL u32 out: caught lying parser (rc=$sfu_rc)"
else
  echo "[!] SIZEFILL u32 out: rc=$sfu_rc"
  cat "$TMP/sfu.err" || true
  exit 1
fi

# --- SIZEFILL accepts 2-arg `parse(buf, *out)` ---
AFL_QUIET=1 AFL_LLVM_BUG_SIZEFILL=1 "$CC" -O0 \
  "$SCRIPT_DIR/test-bug-sizefill-twoarg.c" -o "$TMP/sft"
set +e
printf '\x00\x00\x00\x00' | "$TMP/sft" 2>"$TMP/sft.err"
sft_rc=$?
set -e
if [ "$sft_rc" -ne 0 ] && grep -q "SIZEFILL violation" "$TMP/sft.err"; then
  echo "[+] SIZEFILL 2-arg: caught lying parser (rc=$sft_rc)"
else
  echo "[!] SIZEFILL 2-arg: rc=$sft_rc"
  cat "$TMP/sft.err" || true
  exit 1
fi

# --- SIZEFILL status-return + out-size APIs ---
AFL_QUIET=1 AFL_LLVM_BUG_SIZEFILL=1 "$CC" -O0 \
  "$SCRIPT_DIR/test-bug-sizefill-status-outparam-tp.c" -o "$TMP/sfstatp"
AFL_QUIET=1 AFL_LLVM_BUG_SIZEFILL=1 "$CC" -O0 \
  "$SCRIPT_DIR/test-bug-sizefill-status-outparam-tn.c" -o "$TMP/sfsttn"
set +e
printf '\x00\x00\x00\x00' | "$TMP/sfstatp" 2>"$TMP/sfstatp.err"
sfstatp_rc=$?
printf '\x00\x00\x00\x00' | "$TMP/sfsttn" 2>"$TMP/sfsttn.err"
sfsttn_rc=$?
set -e
if [ "$sfstatp_rc" -ne 0 ] && grep -q "SIZEFILL violation" "$TMP/sfstatp.err" && \
   [ "$sfsttn_rc" -eq 0 ]; then
  echo "[+] SIZEFILL status out-param: TP caught, TN clean"
else
  echo "[!] SIZEFILL status out-param: tp=$sfstatp_rc tn=$sfsttn_rc"
  cat "$TMP/sfstatp.err" "$TMP/sfsttn.err" || true
  exit 1
fi

# --- BUDGET catches `s = call; p += s` at -O0 ---
AFL_QUIET=1 AFL_LLVM_BUG_BUDGET=1 "$CC" -O0 \
  "$SCRIPT_DIR/test-bug-budget-spill.c" -o "$TMP/bsp"
set +e
printf '\x10\x00\x00\x00' | "$TMP/bsp" 2>"$TMP/bsp.err"
bsp_rc=$?
set -e
if [ "$bsp_rc" -ne 0 ] && grep -q "BUDGET violation" "$TMP/bsp.err"; then
  echo "[+] BUDGET spill: caught -O0 spill+reload pattern (rc=$bsp_rc)"
else
  echo "[!] BUDGET spill: rc=$bsp_rc"
  cat "$TMP/bsp.err" || true
  exit 1
fi

# --- BUDGET catches callees with `returned` attribute (-O2) ---
AFL_QUIET=1 AFL_LLVM_BUG_BUDGET=1 "$CC" -O2 \
  "$SCRIPT_DIR/test-bug-budget-returned.c" -o "$TMP/brt"
set +e
"$TMP/brt" a b c 2>"$TMP/brt.err"
brt_rc=$?
set -e
if [ "$brt_rc" -ne 0 ] && grep -q "BUDGET violation" "$TMP/brt.err"; then
  echo "[+] BUDGET returned: caught optimizer-substituted call (rc=$brt_rc)"
else
  echo "[!] BUDGET returned: rc=$brt_rc"
  cat "$TMP/brt.err" || true
  exit 1
fi

# --- SIZEFILL recognizes buffers from AFL_LLVM_BUG_ALLOCSIZE_FUNCS ---
# Verify the IR by counting sf_begin sites: with MyAlloc registered, the
# parse() call against MyAlloc-buffer produces an extra sf_begin (versus
# only the NULL-probe call when unregistered).
AFL_QUIET=1 AFL_LLVM_BUG_SIZEFILL=1 AFL_LLVM_BUG_ALLOCSIZE_FUNCS=MyAlloc \
  "$CC" -O0 -S -emit-llvm \
  "$SCRIPT_DIR/test-bug-sizefill-customalloc.c" -o "$TMP/sfca.ll" 2>/dev/null
n_with=$(grep -c "__afl_bug_sf_begin" "$TMP/sfca.ll")
AFL_QUIET=1 AFL_LLVM_BUG_SIZEFILL=1 \
  "$CC" -O0 -S -emit-llvm \
  "$SCRIPT_DIR/test-bug-sizefill-customalloc.c" -o "$TMP/sfca2.ll" 2>/dev/null
n_without=$(grep -c "__afl_bug_sf_begin" "$TMP/sfca2.ll")
if [ "${n_with:-0}" -gt "${n_without:-0}" ]; then
  echo "[+] SIZEFILL custom alloc: sf_begin sites with=$n_with without=$n_without"
else
  echo "[!] SIZEFILL custom alloc: with=$n_with without=$n_without"
  exit 1
fi

# --- ALLOCSIZE registers anonymous mmap ---
AFL_QUIET=1 AFL_LLVM_BUG_ALLOCSIZE=1 "$CC" \
  "$SCRIPT_DIR/test-bug-allocsize-mmap.c" -o "$TMP/amm"
set +e
printf '\x10\x00\x00\x00' | "$TMP/amm" 2>"$TMP/amm.err"
amm_rc=$?
set -e
if [ "$amm_rc" -ne 0 ] && grep -q "ALLOCSIZE soft-OOB" "$TMP/amm.err"; then
  echo "[+] ALLOCSIZE mmap: caught OOB in anonymous mapping (rc=$amm_rc)"
else
  echo "[!] ALLOCSIZE mmap: rc=$amm_rc"
  cat "$TMP/amm.err" || true
  exit 1
fi

# --- BUDGET out-param: catches `ptr += *out_n` when callee lies about
#     how much it wrote.  Matcher is gated on BUDGET + SIZEFILL both on.
AFL_QUIET=1 AFL_LLVM_BUG_BUDGET=1 AFL_LLVM_BUG_SIZEFILL=1 "$CC" -O0 \
  "$SCRIPT_DIR/test-bug-budget-outparam.c" -o "$TMP/bopa"
set +e
printf '\x00\x00\x00\x00' | "$TMP/bopa" 2>"$TMP/bopa.err"
bopa_rc=$?
set -e
if [ "$bopa_rc" -ne 0 ] && grep -q "BUDGET violation" "$TMP/bopa.err"; then
  echo "[+] BUDGET outparam: caught lying fill_lying (rc=$bopa_rc)"
else
  echo "[!] BUDGET outparam: rc=$bopa_rc"
  cat "$TMP/bopa.err" || true
  exit 1
fi

# TN: honest callee — same shape, accurate *out_n — must NOT trip.
AFL_QUIET=1 AFL_LLVM_BUG_BUDGET=1 AFL_LLVM_BUG_SIZEFILL=1 "$CC" -O0 \
  "$SCRIPT_DIR/test-bug-budget-outparam-honest.c" -o "$TMP/boph"
set +e
printf '\x00\x00\x00\x00' | "$TMP/boph" 2>"$TMP/boph.err"
boph_rc=$?
set -e
if [ "$boph_rc" -eq 0 ]; then
  echo "[+] BUDGET outparam honest: no false positive (rc=$boph_rc)"
else
  echo "[!] BUDGET outparam honest: rc=$boph_rc"
  cat "$TMP/boph.err" || true
  exit 1
fi

# TN: parse(buf, int *err) shape — int* is too narrow for the out-param
# matcher to accept; the static IR must NOT show ws_begin/ws_check_budget
# for the parse_err callee.  We verify rc=0 AND zero new ws_* calls.
AFL_QUIET=1 AFL_LLVM_BUG_BUDGET=1 AFL_LLVM_BUG_SIZEFILL=1 "$CC" -O0 -S -emit-llvm \
  "$SCRIPT_DIR/test-bug-budget-outparam-errcode.c" -o "$TMP/bope.ll" 2>/dev/null
# grep -c returns 1 when count is 0; tolerate that under `set -e`.
bope_ws_check=$(grep -c "call.*__afl_bug_ws_check_budget" "$TMP/bope.ll" || true)
AFL_QUIET=1 AFL_LLVM_BUG_BUDGET=1 AFL_LLVM_BUG_SIZEFILL=1 "$CC" -O0 \
  "$SCRIPT_DIR/test-bug-budget-outparam-errcode.c" -o "$TMP/bope"
set +e
printf '\x00\x00\x00\x00' | "$TMP/bope" 2>"$TMP/bope.err"
bope_rc=$?
set -e
if [ "$bope_rc" -eq 0 ] && [ "${bope_ws_check:-0}" -eq 0 ]; then
  echo "[+] BUDGET outparam errcode: int* err rejected (rc=$bope_rc, ws_check=$bope_ws_check)"
else
  echo "[!] BUDGET outparam errcode: rc=$bope_rc, ws_check=$bope_ws_check"
  cat "$TMP/bope.err" || true
  exit 1
fi

# --- DERIVE slot ring: varied-size allocations from one site spread
#     across multiple cmp_map slots instead of saturating one.
AFL_QUIET=1 AFL_LLVM_BUG=1 "$CC" -I"$AFL_DIR/include" \
  "$SCRIPT_DIR/test-bug-derive-slot-ring.c" -o "$TMP/dsr"
set +e
printf '\x00\x00\x00\x00' | AFL_CMPLOG_DEBUG=1 \
  "$TMP/dsr" 2>"$TMP/dsr.err" >/dev/null
dsr_rc=$?
set -e
if [ "$dsr_rc" -eq 0 ] && grep -q "BUG_DERIVE_SLOT_RING: distinct=" "$TMP/dsr.err"; then
  dsr_distinct=$(grep -o "distinct=[0-9]*" "$TMP/dsr.err" | head -1 | cut -d= -f2)
  echo "[+] DERIVE slot ring: $dsr_distinct/8 distinct size buckets landed in distinct slots"
else
  echo "[!] DERIVE slot ring: rc=$dsr_rc"
  cat "$TMP/dsr.err" || true
  exit 1
fi

# --- ALLOCSIZE multi-window shadow: catches OOB in allocations placed
#     outside the primary 16 GiB window.
AFL_QUIET=1 AFL_LLVM_BUG_ALLOCSIZE=1 "$CC" -I"$AFL_DIR/include" \
  "$SCRIPT_DIR/test-bug-allocsize-multiwindow.c" -o "$TMP/amw"
set +e
printf '\x10\x00\x00\x00' | "$TMP/amw" 2>"$TMP/amw.err"
amw_rc=$?
set -e
# Two acceptable outcomes:
#   (a) Kernel honored MAP_FIXED_NOREPLACE hints and the OOB tripped (rc=134).
#   (b) Kernel refused the hint; test skipped (rc=0 + "skipping" message).
# Anything else is a regression.
if [ "$amw_rc" -eq 134 ] && grep -q "ALLOCSIZE soft-OOB" "$TMP/amw.err"; then
  echo "[+] ALLOCSIZE multi-window: caught OOB in 2nd 16 GiB window (rc=$amw_rc)"
elif [ "$amw_rc" -eq 0 ] && grep -q "skipping" "$TMP/amw.err"; then
  echo "[~] ALLOCSIZE multi-window: kernel refused hinted addresses; skipped"
else
  echo "[!] ALLOCSIZE multi-window: rc=$amw_rc"
  cat "$TMP/amw.err" || true
  exit 1
fi

# --- ALLOCSIZE stack-alloca: catches OOB on stack arrays.  Registers
#     entry-block allocas (size multiple of 64 bytes, alignment 64) so
#     the existing store oracle's shadow lookup finds them.
# -fno-stack-protector: isolate the ALLOCSIZE oracle from the compiler's own
# stack-canary, which (on macOS/arm64, unlike glibc/x86) independently aborts
# on this overflow and would otherwise mask what the oracle does.
AFL_QUIET=1 AFL_LLVM_BUG_ALLOCSIZE=1 "$CC" -O0 -fno-stack-protector \
  "$SCRIPT_DIR/test-bug-allocsize-stack-oob.c" -o "$TMP/aso"
set +e
printf '\x00\x00\x00\x00' | "$TMP/aso" 2>"$TMP/aso.err"
aso_rc=$?
set -e
if [ "$aso_rc" -ne 0 ] && grep -q "ALLOCSIZE soft-OOB" "$TMP/aso.err"; then
  echo "[+] ALLOCSIZE stack OOB: caught 4-byte write past 64-byte stack buffer (rc=$aso_rc)"
else
  echo "[!] ALLOCSIZE stack OOB: rc=$aso_rc"
  cat "$TMP/aso.err" || true
  exit 1
fi

# TN inbounds: same shape, write inside buf — must NOT trip.
AFL_QUIET=1 AFL_LLVM_BUG_ALLOCSIZE=1 "$CC" -O0 \
  "$SCRIPT_DIR/test-bug-allocsize-stack-inbounds.c" -o "$TMP/asi"
set +e
printf '\x00\x00\x00\x00' | "$TMP/asi" 2>"$TMP/asi.err"
asi_rc=$?
set -e
if [ "$asi_rc" -eq 0 ]; then
  echo "[+] ALLOCSIZE stack inbounds: no false positive (rc=$asi_rc)"
else
  echo "[!] ALLOCSIZE stack inbounds: rc=$asi_rc"
  cat "$TMP/asi.err" || true
  exit 1
fi

# TN helper: stack array passed to a noinline helper must register
# EXACTLY ONCE (in the caller).  Verify via static IR count.
AFL_QUIET=1 AFL_LLVM_BUG_ALLOCSIZE=1 "$CC" -O0 -S -emit-llvm \
  "$SCRIPT_DIR/test-bug-allocsize-stack-helper.c" -o "$TMP/ash.ll" 2>/dev/null
ash_regs=$(grep -c "call.*__afl_alloc_register\b" "$TMP/ash.ll" || true)
AFL_QUIET=1 AFL_LLVM_BUG_ALLOCSIZE=1 "$CC" -O0 \
  "$SCRIPT_DIR/test-bug-allocsize-stack-helper.c" -o "$TMP/ash"
set +e
printf '\x00\x00\x00\x00' | "$TMP/ash" 2>"$TMP/ash.err"
ash_rc=$?
set -e
if [ "$ash_rc" -eq 0 ] && [ "${ash_regs:-0}" -eq 1 ]; then
  echo "[+] ALLOCSIZE stack helper: caller registers once, helper passes through (rc=$ash_rc, regs=$ash_regs)"
else
  echo "[!] ALLOCSIZE stack helper: rc=$ash_rc regs=$ash_regs"
  cat "$TMP/ash.err" || true
  exit 1
fi

# TN recursion: recursive function with 64-byte stack alloca, depth 50.
# Record table must not overflow; in-bounds writes must not FP.
AFL_QUIET=1 AFL_LLVM_BUG_ALLOCSIZE=1 "$CC" -O0 \
  "$SCRIPT_DIR/test-bug-allocsize-stack-recursion.c" -o "$TMP/asr"
set +e
printf '\x00\x00\x00\x00' | "$TMP/asr" 2>"$TMP/asr.err"
asr_rc=$?
set -e
if [ "$asr_rc" -eq 0 ]; then
  echo "[+] ALLOCSIZE stack recursion: 50-deep recursion completed cleanly (rc=$asr_rc)"
else
  echo "[!] ALLOCSIZE stack recursion: rc=$asr_rc"
  cat "$TMP/asr.err" || true
  exit 1
fi

# Gating: AFL_LLVM_BUG_ALLOCSIZE_STACK=0 must restore pre-fix behavior.
# Rebuild the TP source with the opt-out; OOB must slip past silently.
# -fno-stack-protector: see the TP build above - without it the stack canary,
# not AFL, aborts the STACK=0 binary on macOS and the opt-out looks broken.
AFL_QUIET=1 AFL_LLVM_BUG_ALLOCSIZE=1 AFL_LLVM_BUG_ALLOCSIZE_STACK=0 "$CC" -O0 -fno-stack-protector \
  "$SCRIPT_DIR/test-bug-allocsize-stack-oob.c" -o "$TMP/aso_off"
set +e
printf '\x00\x00\x00\x00' | "$TMP/aso_off" 2>"$TMP/aso_off.err"
aso_off_rc=$?
set -e
if [ "$aso_off_rc" -eq 0 ]; then
  echo "[+] ALLOCSIZE stack gating: STACK=0 disables instrumentation (rc=$aso_off_rc)"
else
  echo "[!] ALLOCSIZE stack gating: rc=$aso_off_rc"
  cat "$TMP/aso_off.err" || true
  exit 1
fi

# --- BUDGET catches strncpy-based over-writers ---
AFL_QUIET=1 AFL_LLVM_BUG_BUDGET=1 "$CC" -O0 \
  "$SCRIPT_DIR/test-bug-budget-strncpy.c" -o "$TMP/bsn"
set +e
printf '\x10\x00\x00\x00' | "$TMP/bsn" 2>"$TMP/bsn.err"
bsn_rc=$?
set -e
if [ "$bsn_rc" -ne 0 ] && grep -q "BUDGET violation" "$TMP/bsn.err"; then
  echo "[+] BUDGET strncpy: caught 2n-byte strncpy with return n (rc=$bsn_rc)"
else
  echo "[!] BUDGET strncpy: rc=$bsn_rc"
  cat "$TMP/bsn.err" || true
  exit 1
fi

# --- SIZEFILL catches read()-based bounded over-writers ---
AFL_QUIET=1 AFL_LLVM_BUG_SIZEFILL=1 "$CC" -O0 \
  "$SCRIPT_DIR/test-bug-sizefill-read.c" -o "$TMP/sfr"
set +e
# Feed plenty of bytes so the in-callee read() can write past the buf end.
head -c 256 /dev/urandom | "$TMP/sfr" 2>"$TMP/sfr.err"
sfr_rc=$?
set -e
if [ "$sfr_rc" -ne 0 ] && grep -q "SIZEFILL violation" "$TMP/sfr.err"; then
  echo "[+] SIZEFILL read: caught bounded read() overrun (rc=$sfr_rc)"
else
  echo "[!] SIZEFILL read: rc=$sfr_rc"
  cat "$TMP/sfr.err" || true
  exit 1
fi

# --- SCALAR instruments SelectInst with constant arm ---
# Compile at -O1 — clang at -O0 emits branch+PHI for ternaries
# rather than a real `select` instruction.  At -O1+ the (cond ? K1
# : K2) pattern becomes a SelectInst which our SCALAR walker
# instruments.
AFL_QUIET=1 AFL_LLVM_BUG_SCALAR=1 "$CC" -O1 -S -emit-llvm \
  "$SCRIPT_DIR/test-bug-scalar-select.c" -o "$TMP/sel.ll" 2>/dev/null
# Find every `= select iN` line (ignore sancov's pointer-select)
# whose result feeds a `__afl_bug_scalar_max` call within 3 IR
# lines.  Optional intervening zext/trunc is normal.
sel_hits=$(awk '
  /= select i[0-9]+/ {
    # extract SSA result name (token before "=")
    n=split($0,a,"="); name=a[1]; sub(/^[ \t]+/,"",name); sub(/[ \t]+$/,"",name);
    pending[name]=NR+3
  }
  /__afl_bug_scalar_max/ {
    for (k in pending) {
      if (NR <= pending[k] && index($0,k) > 0) { print; break }
    }
    # zext/trunc renames the SSA value; track that too
  }
  /^[ \t]*%[0-9]+ = (zext|trunc|sext) / {
    # Map new SSA to its source if source is in pending
    n=split($0,a,"="); newname=a[1]; sub(/^[ \t]+/,"",newname); sub(/[ \t]+$/,"",newname);
    # last token of the rhs is the source operand
    src=""
    for (i=NF; i>0; --i) { if ($i ~ /^%/) { src=$i; sub(/,/,"",src); break } }
    if (src in pending) pending[newname]=pending[src]
  }
' "$TMP/sel.ll" | wc -l | tr -d ' ')
if [ "${sel_hits:-0}" -ge 1 ]; then
  echo "[+] SCALAR select: $sel_hits select sites instrumented"
else
  echo "[!] SCALAR select: only $sel_hits sites instrumented (expected >= 1)"
  grep -E "select i|__afl_bug_scalar_max" "$TMP/sel.ll" | head
  exit 1
fi

# --- SIZEFILL VLA mul saturates on overflow ---
AFL_QUIET=1 AFL_LLVM_BUG_SIZEFILL=1 "$CC" -O0 -S -emit-llvm \
  "$SCRIPT_DIR/test-bug-sizefill-vla.c" -o "$TMP/svla.ll" 2>/dev/null
if grep -q "umul.with.overflow" "$TMP/svla.ll"; then
  echo "[+] SIZEFILL VLA: saturating umul emitted in IR"
else
  echo "[!] SIZEFILL VLA: no umul.with.overflow in IR"
  exit 1
fi
AFL_QUIET=1 AFL_LLVM_BUG_SIZEFILL=1 "$CC" -O0 \
  "$SCRIPT_DIR/test-bug-sizefill-vla.c" -o "$TMP/svla"
set +e
printf '\x10\x00\x00\x00' | "$TMP/svla" 2>"$TMP/svla.err"
svla_rc=$?
set -e
if [ "$svla_rc" -eq 0 ] && ! grep -q "SIZEFILL violation" "$TMP/svla.err"; then
  echo "[+] SIZEFILL VLA runtime: honest fill survives saturating mul"
else
  echo "[!] SIZEFILL VLA runtime: rc=$svla_rc"
  cat "$TMP/svla.err" || true
  exit 1
fi

# --- SLACK covers overflow flag (index-1 extractvalue) ---
AFL_QUIET=1 AFL_LLVM_BUG_SLACK=1 "$CC" \
  "$SCRIPT_DIR/test-bug-slack-overflow.c" -o "$TMP/sov"
set +e
"$TMP/sov" 2 3 2>"$TMP/sov.no" >/dev/null
"$TMP/sov" 0xffffffffffffffff 2 2>"$TMP/sov.yes" >/dev/null
set -e
# An overflow-only slot must show up in the overflow run that is
# absent (or smaller) in the non-overflow run.
sort "$TMP/sov.no"  | grep -E '^slot' > "$TMP/sov.no.s"  || true
sort "$TMP/sov.yes" | grep -E '^slot' > "$TMP/sov.yes.s" || true
ov_unique=$(comm -13 "$TMP/sov.no.s" "$TMP/sov.yes.s" | wc -l | tr -d ' ')
if [ "${ov_unique:-0}" -ge 1 ]; then
  echo "[+] SLACK overflow flag: overflow input lit $ov_unique unique slot(s)"
else
  echo "[!] SLACK overflow flag: no overflow-unique slot"
  echo "--- no-overflow ---"
  cat "$TMP/sov.no" || true
  echo "--- overflow ---"
  cat "$TMP/sov.yes" || true
  exit 1
fi

# --- AFL_LLVM_BUG_DUMP_SUMMARY emits per-function lines ---
set +e
AFL_LLVM_BUG=1 AFL_LLVM_BUG_DUMP_SUMMARY=1 "$CC" -O0 \
  "$SCRIPT_DIR/test-bug-dump-summary.c" -o "$TMP/dsum" 2>"$TMP/dsum.cerr"
dsum_cc=$?
set -e
sum_lines=$(grep -c "^\[afl-bug-summary\]" "$TMP/dsum.cerr" || true)
sum_has_a=$(grep -c "^\[afl-bug-summary\].*func_a"      "$TMP/dsum.cerr" || true)
sum_has_b=$(grep -c "^\[afl-bug-summary\].*func_b"      "$TMP/dsum.cerr" || true)
if [ "$dsum_cc" -eq 0 ] && [ "${sum_lines:-0}" -ge 2 ] && \
   [ "${sum_has_a:-0}" -ge 1 ] && [ "${sum_has_b:-0}" -ge 1 ]; then
  echo "[+] DUMP_SUMMARY: $sum_lines summary lines (func_a=$sum_has_a func_b=$sum_has_b)"
else
  echo "[!] DUMP_SUMMARY: cc=$dsum_cc lines=$sum_lines a=$sum_has_a b=$sum_has_b"
  cat "$TMP/dsum.cerr" || true
  exit 1
fi

# Without the env, no summary lines should appear.
set +e
AFL_LLVM_BUG=1 "$CC" -O0 \
  "$SCRIPT_DIR/test-bug-dump-summary.c" -o "$TMP/dsum_off" 2>"$TMP/dsum_off.cerr"
dsum_off_cc=$?
set -e
sum_off_lines=$(grep -c "^\[afl-bug-summary\]" "$TMP/dsum_off.cerr" || true)
if [ "$dsum_off_cc" -eq 0 ] && [ "${sum_off_lines:-0}" -eq 0 ]; then
  echo "[+] DUMP_SUMMARY: silent without env"
else
  echo "[!] DUMP_SUMMARY: leaked summary lines without env ($sum_off_lines)"
  exit 1
fi

echo "[+] all bug-pass tests passed"
