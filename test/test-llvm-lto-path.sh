#!/bin/bash
#
# Test for LTO PATH (Ball-Larus path) coverage in
# instrumentation/SanitizerCoverageLTO.so.cc.
#
# Modes compared:
#   plain   : LTO, no extras
#   ctx     : AFL_LLVM_LTO_CALLER=1
#   path    : AFL_LLVM_LTO_PATH=1
#   alias_a : AFL_LLVM_PATH=1            (must equal path)
#   alias_b : AFL_LLVM_PATH_MODE=1       (must equal path)
#   ctxpath : AFL_LLVM_LTO_CALLER=1 AFL_LLVM_LTO_PATH=1
#
# Oracle: the OKF banner reports "Instrumented N locations ... with K
# extra map entries for ...".  We sum N + K to get the total reservation.
#   plain.total <= ctx.total
#   path.total > plain.total                (paths reserve extra slots)
#   ctxpath.total >= path.total + ctx.total - plain.total
#   alias_a.total == path.total == alias_b.total
#
# Bigly_paths must trigger a "skipping path instrumentation" warning.
# All produced binaries must run and emit non-empty showmaps.

# Note: do not source test-pre.sh -- its `printf %b \101` sanity check
# fails in zsh (where %b does not interpret octal escapes) and the
# resulting `exit 1` from a sourced file would terminate this script too.
# This script has its own ok/ko framework and uses ../ paths directly,
# so it does not need anything from test-pre.sh.

PASS=0
FAIL=0
ok()  { echo "[+] $*"; PASS=$((PASS+1)); }
ko()  { echo "[-] $*"; FAIL=$((FAIL+1)); }
note(){ echo "[*] $*"; }

if ! [ -x ../afl-clang-lto -a -e ../SanitizerCoverageLTO.so ]; then
  note "afl-clang-lto / SanitizerCoverageLTO.so not present — skipping"
  exit 0
fi

# Compile and return the total reservation parsed from the OKF line.
# Args: outbin logfile env...
# Stdout: an integer (n + extra), or empty on failure.
compile_total() {
  local outbin="$1"; shift
  local logfile="$1"; shift
  rm -f "$outbin"
  env "$@" AFL_DEBUG=1 ../afl-clang-lto -O0 -o "$outbin" \
        test-llvm-lto-path.c > "$logfile" 2>&1
  local rv=$?
  if [ $rv -ne 0 ]; then return $rv; fi
  local line
  line=$(grep -E 'Instrumented [0-9]+ locations' "$logfile" | tail -n1)
  local n
  n=$(echo "$line" | sed -E 's/.*Instrumented ([0-9]+) locations.*/\1/')
  # Sum every "with K extra map entries" segment (CTX, PATH, etc.).
  local extra
  extra=$(echo "$line" | grep -oE 'with [0-9]+ extra map entries' \
                       | grep -oE '[0-9]+' \
                       | awk '{s+=$1} END{print s+0}')
  echo $((n + extra))
}

# 1. plain LTO
N_PLAIN=$(compile_total plain.bin plain.log)
[ -z "$N_PLAIN" ] && { ko "plain LTO compile failed"; cat plain.log; exit 1; }
ok "plain LTO total = $N_PLAIN"

# 2. CTX only
N_CTX=$(compile_total ctx.bin ctx.log AFL_LLVM_LTO_CALLER=1)
[ -z "$N_CTX" ] && { ko "CTX-only compile failed"; cat ctx.log; exit 1; }
ok "CTX-only total = $N_CTX"

# 3. PATH only
N_PATH=$(compile_total path.bin path.log AFL_LLVM_LTO_PATH=1)
[ -z "$N_PATH" ] && { ko "PATH-only compile failed"; cat path.log; exit 1; }
ok "PATH-only total = $N_PATH"

# 4. Aliases
N_A=$(compile_total alias_a.bin alias_a.log AFL_LLVM_PATH=1)
[ -z "$N_A" ] && { ko "AFL_LLVM_PATH alias compile failed"; cat alias_a.log; exit 1; }
N_B=$(compile_total alias_b.bin alias_b.log AFL_LLVM_PATH_MODE=1)
[ -z "$N_B" ] && { ko "AFL_LLVM_PATH_MODE alias compile failed"; cat alias_b.log; exit 1; }

# 5. CTX + PATH
N_CP=$(compile_total ctxpath.bin ctxpath.log AFL_LLVM_LTO_CALLER=1 AFL_LLVM_LTO_PATH=1)
[ -z "$N_CP" ] && { ko "CTX+PATH compile failed"; cat ctxpath.log; exit 1; }
ok "CTX+PATH total = $N_CP"

# 5b. PATH=2 (restricted: collapse 2-successor guard-only BBs)
N_R=$(compile_total restrict.bin restrict.log AFL_LLVM_LTO_PATH=2)
[ -z "$N_R" ] && { ko "PATH=2 compile failed"; cat restrict.log; exit 1; }
ok "PATH=2 (restricted) total = $N_R"

# 5c. PATH=3 (strict Ball-Larus)
N_S=$(compile_total strict.bin strict.log AFL_LLVM_LTO_PATH=3)
[ -z "$N_S" ] && { ko "PATH=3 compile failed"; cat strict.log; exit 1; }
ok "PATH=3 (strict) total = $N_S"

# 5d. PATH=4 (invalid value)
if env AFL_LLVM_LTO_PATH=4 ../afl-clang-lto -O0 -o invalid.bin \
       test-llvm-lto-path.c > invalid.log 2>&1; then
  ko "AFL_LLVM_LTO_PATH=4 should fail"
else
  if grep -qE 'accepts|"3"|"2"|"1"|"0"|relax|strict|restrict' invalid.log; then
    ok "AFL_LLVM_LTO_PATH=4 fails with informative message"
  else
    ko "AFL_LLVM_LTO_PATH=4 failed but message did not mention valid values"
    tail -5 invalid.log
  fi
fi
rm -f invalid.bin invalid.log

# Relations
[ "$N_PATH" -gt "$N_PLAIN" ] && ok "PATH > plain ($N_PATH > $N_PLAIN)" \
                              || ko "PATH should be > plain ($N_PATH vs $N_PLAIN)"

[ "$N_CTX" -ge "$N_PLAIN" ] && ok "CTX >= plain ($N_CTX >= $N_PLAIN)" \
                             || ko "CTX should be >= plain ($N_CTX vs $N_PLAIN)"

[ "$N_CP" -gt "$N_PATH" ] && ok "CTX+PATH > PATH ($N_CP > $N_PATH)" \
                           || ko "CTX+PATH should be > PATH ($N_CP vs $N_PATH)"

[ "$N_CP" -gt "$N_CTX" ] && ok "CTX+PATH > CTX ($N_CP > $N_CTX)" \
                          || ko "CTX+PATH should be > CTX ($N_CP vs $N_CTX)"

[ "$N_A" = "$N_PATH" ] && ok "AFL_LLVM_PATH alias == AFL_LLVM_LTO_PATH ($N_A)" \
                        || ko "AFL_LLVM_PATH alias mismatch ($N_A vs $N_PATH)"
[ "$N_B" = "$N_PATH" ] && ok "AFL_LLVM_PATH_MODE alias == AFL_LLVM_LTO_PATH ($N_B)" \
                        || ko "AFL_LLVM_PATH_MODE alias mismatch ($N_B vs $N_PATH)"

# Ordering by aggressiveness: PATH=1 (relaxed) < PATH=2 (restricted) < PATH=3 (strict).
[ "$N_PATH" -le "$N_R" ] && ok "PATH=1 <= PATH=2 ($N_PATH <= $N_R)" \
                          || ko "PATH=1 should be <= PATH=2 ($N_PATH vs $N_R)"
[ "$N_R" -le "$N_S" ] && ok "PATH=2 <= PATH=3 ($N_R <= $N_S)" \
                       || ko "PATH=2 should be <= PATH=3 ($N_R vs $N_S)"
[ "$N_PATH" -gt "$N_PLAIN" ] && ok "PATH=1 > plain ($N_PATH > $N_PLAIN)" \
                              || ko "PATH=1 should be > plain ($N_PATH vs $N_PLAIN)"
[ "$N_S" -gt "$N_R" ] && ok "PATH=3 > PATH=2 ($N_S > $N_R)" \
                       || ko "PATH=3 should be strictly > PATH=2 ($N_S vs $N_R)"

# 6. bigly_paths warning
if grep -qiE 'bigly|skip.*path|too many.*paths|path.*too' path.log; then
  ok "bigly_paths skip warning present"
else
  ko "expected a 'too many paths' / skip warning for bigly_paths in path.log"
fi

# 7. Each produced binary must run and emit a non-empty showmap.
for bin in plain.bin ctx.bin path.bin alias_a.bin alias_b.bin ctxpath.bin \
           restrict.bin strict.bin; do
  rm -f "$bin.map"
  printf 'A' | AFL_QUIET=1 ../afl-showmap -m none -o "$bin.map" -q -- \
                "./$bin" >/dev/null 2>&1
  if [ -s "$bin.map" ]; then ok "$bin produces non-empty coverage map";
  else ko "$bin produced no coverage"; fi
done

# 8. PATH coverage actually differentiates paths in if_chain.
# Different inputs flip different bits — should hit different path IDs.
# `printf '%b'` (unlike '%c') interprets backslash escapes so '\\001'..'\\007'
# emit distinct bytes. The buggy original used '%c' which fed the same '\\' byte
# to every iteration.
emit_byte() {
  printf '%b' "$(printf '\\%03o' "$1")"
}
for v in 0 1 2 3 4 5 6 7; do
  emit_byte "$v" | \
    AFL_QUIET=1 ../afl-showmap -m none -o "/tmp/pathmap.$v" -q -- \
      ./path.bin >/dev/null 2>&1
  emit_byte "$v" | \
    AFL_QUIET=1 ../afl-showmap -m none -o "/tmp/plainmap.$v" -q -- \
      ./plain.bin >/dev/null 2>&1
done
SRC_UNIQ=$(for v in 0 1 2 3 4 5 6 7; do emit_byte "$v" | od -An -tx1; done \
             | sort -u | wc -l | tr -d ' ')
if [ "$SRC_UNIQ" -lt 8 ]; then
  ko "test fed only $SRC_UNIQ unique bytes (need 8) — oracle would not probe path differentiation"
fi
UNIQ_PATH=$(cat /tmp/pathmap.* 2>/dev/null | sort -u | wc -l)
UNIQ_PLAIN=$(cat /tmp/plainmap.* 2>/dev/null | sort -u | wc -l)
if [ "$UNIQ_PATH" -gt "$UNIQ_PLAIN" ]; then
  ok "PATH expands distinct slots across inputs ($UNIQ_PATH > $UNIQ_PLAIN)"
else
  ko "PATH should expand distinct slots ($UNIQ_PATH vs $UNIQ_PLAIN)"
fi

# 9. CTX_DEPTH > 1 + PATH must FATAL: cid * NumPaths assumes
# cid ∈ [0, call_counter); at depth > 1 AFLContext is an XOR-stack and
# cannot be guaranteed in range. The compiler must reject the combination
# instead of silently producing out-of-bounds bitmap writes.
if env AFL_LLVM_LTO_CALLER=1 AFL_LLVM_CTX_DEPTH=2 AFL_LLVM_LTO_PATH=1 \
       ../afl-clang-lto -O0 -o ctxdepth.bin test-llvm-lto-path.c \
       > ctxdepth.log 2>&1; then
  ko "CTX_DEPTH=2 + PATH should be rejected"
else
  if grep -qiE 'depth|CTX|caller' ctxdepth.log; then
    ok "CTX_DEPTH>1 + PATH rejected with informative message"
  else
    ko "CTX_DEPTH>1 + PATH rejected but message did not mention depth/CTX/caller"
    tail -5 ctxdepth.log
  fi
fi
rm -f ctxdepth.bin ctxdepth.log

# 10. AFL_LLVM_PATH_MAX_PATHS lowers the 100k cap. With a tiny cap most
# functions should be skipped — the total reservation must shrink.
N_LOWCAP=$(compile_total lowcap.bin lowcap.log \
              AFL_LLVM_LTO_PATH=3 AFL_LLVM_PATH_MAX_PATHS=4)
if [ -z "$N_LOWCAP" ]; then
  ko "AFL_LLVM_PATH_MAX_PATHS=4 compile failed"
  cat lowcap.log
else
  if grep -qiE 'too many.*paths|skip.*path' lowcap.log; then
    ok "AFL_LLVM_PATH_MAX_PATHS=4 triggers skip for functions over the cap"
  else
    ko "AFL_LLVM_PATH_MAX_PATHS=4 produced no skip warnings"
  fi
  if [ "$N_LOWCAP" -lt "$N_S" ]; then
    ok "lowered cap shrinks total ($N_LOWCAP < $N_S)"
  else
    ko "lowered cap should shrink total ($N_LOWCAP vs $N_S)"
  fi
fi
rm -f lowcap.bin lowcap.log

# 11. Threadsafe counters at exit must compile and produce a coverage map.
N_TSAFE=$(compile_total tsafe.bin tsafe.log \
            AFL_LLVM_LTO_PATH=1 AFL_LLVM_THREADSAFE_INST=1)
if [ -z "$N_TSAFE" ]; then
  ko "threadsafe+PATH compile failed"
  tail -10 tsafe.log
else
  ok "threadsafe+PATH compiles (total = $N_TSAFE)"
  emit_byte 1 | AFL_QUIET=1 ../afl-showmap -m none -o tsafe.map -q -- \
      ./tsafe.bin >/dev/null 2>&1
  if [ -s tsafe.map ]; then
    ok "threadsafe+PATH binary produces coverage"
  else
    ko "threadsafe+PATH binary produced no coverage"
  fi
fi
rm -f tsafe.bin tsafe.log tsafe.map

# 12. AFL_DUMP_MAP_SIZE on the LTO-built path.bin must reflect a map size
# that includes the PATH slots — the macOS-targeted __afl_final_loc
# static-init fix exercises this path.
N_PATH_FOR_DUMP=$(compile_total dump.bin dump.log AFL_LLVM_LTO_PATH=1)
if [ -n "$N_PATH_FOR_DUMP" ]; then
  AFL_DUMP_MAP_SIZE=1 ./dump.bin > dumpmap.out 2>&1 || true
  DUMP=$(grep -oE '[0-9]+' dumpmap.out | head -1)
  if [ -n "$DUMP" ] && [ "$DUMP" -gt 0 ]; then
    ok "AFL_DUMP_MAP_SIZE prints a positive integer ($DUMP)"
    if [ "$DUMP" -ge "$N_PATH_FOR_DUMP" ]; then
      ok "AFL_DUMP_MAP_SIZE >= reported PATH reservation ($DUMP >= $N_PATH_FOR_DUMP)"
    else
      ko "AFL_DUMP_MAP_SIZE ($DUMP) smaller than reported reservation ($N_PATH_FOR_DUMP)"
    fi
  else
    ko "AFL_DUMP_MAP_SIZE printed no numeric value"
    cat dumpmap.out
  fi
fi
rm -f dump.bin dump.log dumpmap.out

# 13. Empty AFL_LLVM_PATH= must be rejected — not silently enable level 1.
if env AFL_LLVM_PATH= ../afl-clang-lto -O0 -o empty.bin test-llvm-lto-path.c \
     > empty.log 2>&1; then
  ko "AFL_LLVM_PATH= (empty) should be rejected"
else
  ok "AFL_LLVM_PATH= (empty) rejected"
fi
rm -f empty.bin empty.log

# Cleanup
rm -f plain.bin plain.log ctx.bin ctx.log path.bin path.log \
      alias_a.bin alias_a.log alias_b.bin alias_b.log \
      ctxpath.bin ctxpath.log restrict.bin restrict.log \
      strict.bin strict.log \
      plain.bin.map ctx.bin.map path.bin.map alias_a.bin.map \
      alias_b.bin.map ctxpath.bin.map restrict.bin.map strict.bin.map \
      /tmp/pathmap.* /tmp/plainmap.*

echo "[+] passed: $PASS"
echo "[-] failed: $FAIL"
test "$FAIL" = 0
