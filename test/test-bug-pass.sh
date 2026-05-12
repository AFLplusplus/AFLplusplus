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
printf 'fun: target_cmp\n' > "$TMP/slack.allow"
AFL_QUIET=1 AFL_LLVM_BUG_SLACK=1 AFL_LLVM_ALLOWLIST="$TMP/slack.allow" \
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

fi

echo "[+] all bug-pass tests passed"
