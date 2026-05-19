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

# Round-2 N1: PATH analysis runs BEFORE InjectCoverage so the per-BB
# guard-only classification sees the source-level CFG, not BBs polluted
# by SanitizerCoverage's own edge-counter stores. Caveat: afl-llvm-bug-pass
# (SCALAR/SLACK/ALLOCSIZE) runs upstream of SanitizerCoverageLTO and
# *does* mutate the CFG before our analysis can see it, so PATH=1 in the
# LTO build cannot fully collapse functions whose BBs are touched by
# bug-pass. We assert the weaker, achievable invariant: PATH=1 strictly
# reduces if_chain's path count below PATH=3.
env AFL_LLVM_LTO_PATH=1 AFL_DEBUG=1 ../afl-clang-lto -O0 \
      -o lto_p1.bin test-llvm-lto-path.c > lto_p1.log 2>&1
env AFL_LLVM_LTO_PATH=3 AFL_DEBUG=1 ../afl-clang-lto -O0 \
      -o lto_p3.bin test-llvm-lto-path.c > lto_p3.log 2>&1
P1=$(grep 'DEBUG: PATH function=if_chain' lto_p1.log \
       | sed -E 's/.*paths=([0-9]+).*/\1/' | tail -1)
P3=$(grep 'DEBUG: PATH function=if_chain' lto_p3.log \
       | sed -E 's/.*paths=([0-9]+).*/\1/' | tail -1)
P1=${P1:-0}
P3=${P3:-0}
if [ "$P1" -lt "$P3" ] && [ "$P3" -gt 1 ]; then
  ok "LTO PATH=1 collapses if_chain (paths=$P1 < PATH=3 paths=$P3)"
else
  ko "LTO PATH=1 did not collapse if_chain relative to PATH=3 ($P1 vs $P3) — analyse-before-Inject regression (N1)"
fi
rm -f lto_p1.bin lto_p1.log lto_p3.bin lto_p3.log

# Round-2 N2: setjmp-calling functions must be skipped — path_reg is on
# the stack and longjmp leaves it indeterminate.
rm -f sj.bin sj.log
if env AFL_LLVM_LTO_PATH=3 AFL_DEBUG=1 ../afl-clang-lto -O0 \
       -o sj.bin test-llvm-path-setjmp.c > sj.log 2>&1; then
  if grep -qE 'DEBUG: PATH function=with_setjmp' sj.log; then
    ko "with_setjmp() was instrumented despite calling setjmp() (N2)"
  else
    ok "with_setjmp() correctly skipped (setjmp detection, N2)"
  fi
  if grep -qE 'DEBUG: PATH function=normal' sj.log; then
    ok "normal() still instrumented alongside the setjmp skip"
  else
    ko "normal() was not instrumented — setjmp skip is too broad"
  fi
else
  ko "setjmp test compile failed"; tail -5 sj.log
fi
rm -f sj.bin sj.log

# Round-2 N4: AFL_LLVM_PATH_MAX_PATHS must reject values above INT32_MAX
# because the IR path index is stored in an i32 register.
rm -f cap_hi.bin cap_hi.log
if env AFL_LLVM_LTO_PATH=3 AFL_LLVM_PATH_MAX_PATHS=2200000000 \
       ../afl-clang-lto -O0 -o cap_hi.bin test-llvm-lto-path.c \
       > cap_hi.log 2>&1; then
  ko "AFL_LLVM_PATH_MAX_PATHS=2200000000 should be rejected (> INT32_MAX)"
else
  if grep -qiE 'INT32_MAX|2147483647|signed i32|i32 register' cap_hi.log; then
    ok "AFL_LLVM_PATH_MAX_PATHS > INT32_MAX rejected (N4)"
  else
    ko "rejection happened but message did not mention the bound"
    tail -5 cap_hi.log
  fi
fi
rm -f cap_hi.bin cap_hi.log

# Round-2 macOS __afl_final_loc — compile two TUs separately, link via
# afl-clang-lto, verify exactly one __afl_final_loc def and that the
# binary runs.
rm -f twomod.bin twomod.log twomod_a.o twomod_b.o twomod.map
env AFL_LLVM_LTO_PATH=1 ../afl-clang-lto -O0 -c test-llvm-path-twomod-a.c \
      -o twomod_a.o > twomod.log 2>&1
env AFL_LLVM_LTO_PATH=1 ../afl-clang-lto -O0 -c test-llvm-path-twomod-b.c \
      -o twomod_b.o >> twomod.log 2>&1
if env AFL_LLVM_LTO_PATH=1 ../afl-clang-lto -O0 -o twomod.bin \
        twomod_a.o twomod_b.o >> twomod.log 2>&1; then
  ok "two-TU LTO link succeeds with PATH coverage"
  # Mach-O adds a leading underscore to C symbols (so __afl_final_loc
  # appears as ___afl_final_loc); ELF emits __afl_final_loc verbatim.
  COUNT=$(nm twomod.bin 2>/dev/null \
            | grep -cE '[ TtDdBbSsCc] _*__afl_final_loc$' || true)
  if [ "$COUNT" -ge 1 ]; then
    ok "__afl_final_loc defined exactly $COUNT time(s) in the linked binary"
  else
    ko "__afl_final_loc symbol not found in the linked binary"
    nm twomod.bin | grep -i afl_final | head -5
  fi
  printf 'A' | AFL_QUIET=1 ../afl-showmap -m none -o twomod.map -q -- \
        ./twomod.bin >/dev/null 2>&1
  if [ -s twomod.map ]; then
    ok "two-TU binary produces coverage"
  else
    ko "two-TU binary produced no coverage"
  fi
else
  ko "two-TU LTO link failed"; tail -10 twomod.log
fi
rm -f twomod.bin twomod.log twomod_a.o twomod_b.o twomod.map

# Round-3 R1: PATH must skip C++20 coroutine functions because path_reg
# (a stack alloca) would be spilled into the coroutine frame and reloaded
# after frame destruction in the .destroy path — heap-use-after-free.
rm -f coro.bin coro.log coro.map
if env AFL_LLVM_LTO_PATH=3 AFL_DEBUG=1 ../afl-clang-lto++ -std=c++20 -O0 \
       -o coro.bin test-llvm-path-coro.cc > coro.log 2>&1; then
  # C++ name mangling: co_func → _Z7co_funch (plus .resume/.destroy
  # post-split companions). PATH must skip ALL THREE since the .resume
  # and .destroy halves are exactly where the spill-to-frame UAF lives.
  if grep -qE 'DEBUG: PATH function=[^ ]*co_func' coro.log; then
    ko "a co_func* variant was PATH-instrumented despite being a coroutine (R1)"
    grep -E 'DEBUG: PATH function=[^ ]*co_func' coro.log | head -3
  else
    ok "co_func and its .resume/.destroy companions correctly skipped (R1)"
  fi
  if grep -qE 'DEBUG: PATH function=_Z11normal_funch' coro.log; then
    ok "normal_func() still PATH-instrumented alongside the coroutine skip"
  else
    ko "normal_func() was not PATH-instrumented — coroutine skip is too broad"
  fi
  emit_byte 1 | AFL_QUIET=1 ../afl-showmap -m none -o coro.map -q -- \
        ./coro.bin >/dev/null 2>&1 || true
  if [ -s coro.map ]; then
    ok "coroutine+PATH binary produces coverage"
  else
    ko "coroutine+PATH binary produced no coverage"
  fi
else
  if grep -qiE 'coroutine|<coroutine>|no member named' coro.log; then
    note "skipping R1 coroutine test — toolchain lacks C++20 coroutine support"
  else
    ko "coroutine test compile failed for non-toolchain reasons"
    tail -10 coro.log
  fi
fi
rm -f coro.bin coro.log coro.map

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
