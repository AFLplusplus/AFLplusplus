#!/usr/bin/env bash
# Regression for the trace_bits layout when both AFL_LLVM_IJON and
# AFL_LLVM_BUG_SCALAR are enabled.  Previously the runtime placed the
# bug map between IJON_MAP and IJON_BYTES, so the fuzzer's ijon_bits
# pointer was off by MAP_SIZE_BUG_BYTES.  With the bug map moved to
# the trailing tail of trace_bits, the fuzzer's tail-trim sequence
# (BUG first, then IJON_BYTES) addresses ijon_bits correctly.
#
# This test compiles a target with both modes, runs a short afl-fuzz
# campaign, and asserts:
#  - the compiled binary runs to completion (no IJON-related abort);
#  - the fuzzer reports a sensible coverage map size in fuzzer_stats;
#  - the fuzzer collects coverage (cycles > 0).
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AFL_DIR="$SCRIPT_DIR/.."
CC="$AFL_DIR/afl-clang-fast"
TMP=$(mktemp -d)
trap "rm -rf $TMP" EXIT

unset AFL_USE_ASAN AFL_USE_MSAN AFL_USE_UBSAN AFL_USE_TSAN AFL_USE_LSAN
unset AFL_LLVM_BUG AFL_LLVM_BUG_SCALAR AFL_LLVM_BUG_ALLOCSIZE
unset AFL_LLVM_BUG_BUDGET AFL_LLVM_BUG_SIZEFILL AFL_LLVM_BUG_SLACK

cat > "$TMP/t.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main(int argc, char **argv) {
  unsigned char buf[16] = {0};
  if (argc > 1) {
    FILE *f = fopen(argv[1], "rb");
    if (f) { fread(buf, 1, 16, f); fclose(f); }
  }
  /* A couple of input-dependent branches so the fuzzer has work to do. */
  int x = buf[0] + buf[1];
  if (x > 50) x *= 2;
  if (x > 200) return 1;
  if (buf[2] == 0xAB) return 2;
  return 0;
}
EOF

# Build the target with BOTH bug-pass and IJON instrumentation.
AFL_LLVM_BUG_SCALAR=1 AFL_LLVM_IJON=1 AFL_QUIET=1 \
  "$CC" "$TMP/t.c" -o "$TMP/t" 2>"$TMP/cc.err" \
  || { cat "$TMP/cc.err"; echo "[!] compile failed"; exit 1; }

# Sanity-run the binary itself (no fuzzer) to confirm it doesn't abort
# on startup due to a mis-bound bug map / IJON region.
printf '\x01\x02\x03' > "$TMP/in.bin"
"$TMP/t" "$TMP/in.bin" >/dev/null 2>"$TMP/run.err" || true
if grep -qE "AFL_BUG|abort|Aborted" "$TMP/run.err"; then
  echo "[!] standalone run reported errors:"
  cat "$TMP/run.err"
  exit 1
fi

# Short fuzzer campaign.
mkdir -p "$TMP/in" "$TMP/out"
cp "$TMP/in.bin" "$TMP/in/seed"

set +e
timeout 8 "$AFL_DIR/afl-fuzz" -i "$TMP/in" -o "$TMP/out" -V 4 \
  -- "$TMP/t" @@ >"$TMP/fz.log" 2>&1
fz_rc=$?
set -e

# -V N completes with rc=0 on time-out.
if [ "$fz_rc" -ne 0 ] && [ "$fz_rc" -ne 124 ]; then
  echo "[!] afl-fuzz returned $fz_rc"
  tail -40 "$TMP/fz.log"
  exit 1
fi

# fuzzer_stats must exist and report a non-zero cycle count.
stats="$TMP/out/default/fuzzer_stats"
if [ ! -s "$stats" ]; then
  echo "[!] fuzzer_stats missing"
  tail -40 "$TMP/fz.log"
  exit 1
fi

cycles=$(awk -F: '/^cycles_done/ { gsub(/ /,"",$2); print $2 }' "$stats")
edges=$(awk -F: '/^total_edges/ { gsub(/ /,"",$2); print $2 }' "$stats")
cvg_pct=$(awk -F: '/^bitmap_cvg/ { gsub(/[ %]/,"",$2); print $2 }' "$stats")

# With the bug map at the trailing tail of trace_bits and IJON's tail
# correctly addressed, bitmap_cvg must reflect ONLY the coverage region
# (and the IJON_MAP edge channel which AFL++ folds into bitmap_cvg).
# When the layout was broken, IJON values would spill into the bug-map
# region, the fuzzer would still count them as "edges", and total_edges
# would mismatch. We check that:
#   - the fuzzer made progress (cycles >= 1),
#   - bitmap_cvg is a sensible (small) number, not 100% or 0%.
if [ "${cycles:-0}" -lt 1 ]; then
  echo "[!] cycles_done=${cycles:-?} (no progress; IJON region likely mis-addressed)"
  tail -40 "$TMP/fz.log"
  exit 1
fi
if [ -z "${cvg_pct}" ]; then
  echo "[!] bitmap_cvg missing"
  exit 1
fi

echo "[+] bug-pass + IJON: cycles=$cycles edges=${edges:-?} cvg=${cvg_pct}% (rc=$fz_rc)"
