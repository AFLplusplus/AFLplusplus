#!/bin/bash
#
# Test PCGUARD AFL_LLVM_PATH (Ball-Larus path coverage) ported from the
# LTO version.  Uses test-llvm-lto-path.c as a target — its functions all
# work fine without any LTO-specific assumptions.
#
# Modes compared:
#   plain     : afl-clang-fast, no extras
#   path=1    : relaxed (collapse all guard-only BBs)
#   path=2    : restricted (collapse only 2-successor guard-only BBs)
#   path=3    : strict Ball-Larus
#   alias     : AFL_LLVM_LTO_PATH=1 / AFL_LLVM_PATH_MODE=1 (same as path=1)
#
# Note: AFL_LLVM_LTO_PATH is recognised by afl-clang-fast too — same
# parser code is shared.

PASS=0
FAIL=0
ok()  { echo "[+] $*"; PASS=$((PASS+1)); }
ko()  { echo "[-] $*"; FAIL=$((FAIL+1)); }
note(){ echo "[*] $*"; }

if ! [ -x ../afl-clang-fast -a -e ../SanitizerCoveragePCGUARD.so ]; then
  note "afl-clang-fast / SanitizerCoveragePCGUARD.so not present — skipping"
  exit 0
fi

compile_total() {
  local outbin="$1"; shift
  local logfile="$1"; shift
  rm -f "$outbin"
  env "$@" AFL_DEBUG=1 ../afl-clang-fast -O0 -o "$outbin" \
        test-llvm-lto-path.c > "$logfile" 2>&1
  local rv=$?
  if [ $rv -ne 0 ]; then return $rv; fi
  local line
  line=$(grep -E 'Instrumented [0-9]+ locations' "$logfile" | tail -n1)
  local n
  n=$(echo "$line" | sed -E 's/.*Instrumented ([0-9]+) locations.*/\1/')
  # PCGUARD reports edge slots in N and PATH slots separately in the
  # "X extra map entries for PATH" suffix — sum them.
  local extra
  extra=$(echo "$line" | grep -oE '[0-9]+ extra map entries' \
                       | grep -oE '^[0-9]+' \
                       | awk '{s+=$1} END{print s+0}')
  echo $((n + extra))
}

# 1. plain
N_PLAIN=$(compile_total plain.bin plain.log)
[ -z "$N_PLAIN" ] && { ko "plain compile failed"; cat plain.log; exit 1; }
ok "plain total = $N_PLAIN"

# 2. path=1
N1=$(compile_total p1.bin p1.log AFL_LLVM_PATH=1)
[ -z "$N1" ] && { ko "PATH=1 compile failed"; cat p1.log; exit 1; }
ok "PATH=1 (relaxed) total = $N1"

# 3. path=2
N2=$(compile_total p2.bin p2.log AFL_LLVM_PATH=2)
[ -z "$N2" ] && { ko "PATH=2 compile failed"; cat p2.log; exit 1; }
ok "PATH=2 (restricted) total = $N2"

# 4. path=3
N3=$(compile_total p3.bin p3.log AFL_LLVM_PATH=3)
[ -z "$N3" ] && { ko "PATH=3 compile failed"; cat p3.log; exit 1; }
ok "PATH=3 (strict) total = $N3"

# 5. aliases
NA=$(compile_total a1.bin a1.log AFL_LLVM_LTO_PATH=1)
[ -z "$NA" ] && { ko "AFL_LLVM_LTO_PATH alias failed"; cat a1.log; exit 1; }
NB=$(compile_total a2.bin a2.log AFL_LLVM_PATH_MODE=1)
[ -z "$NB" ] && { ko "AFL_LLVM_PATH_MODE alias failed"; cat a2.log; exit 1; }

# 6. invalid value
if env AFL_LLVM_PATH=4 ../afl-clang-fast -O0 -o invalid.bin \
       test-llvm-lto-path.c > invalid.log 2>&1; then
  ko "AFL_LLVM_PATH=4 should fail"
else
  if grep -qE 'accepts|"3"|"2"|"1"|"0"|relax|strict|restrict' invalid.log; then
    ok "AFL_LLVM_PATH=4 fails with informative message"
  else
    ko "AFL_LLVM_PATH=4 failed but message did not mention valid values"
    tail -5 invalid.log
  fi
fi
rm -f invalid.bin invalid.log

# 7. bigly_paths warning
if grep -qiE 'bigly|skip.*path|too many.*paths|path.*too' p3.log; then
  ok "bigly_paths skip warning present (in PATH=3 log)"
else
  ko "expected a 'too many paths' / skip warning for bigly_paths"
fi

# Ordering: path=1 <= path=2 <= path=3, all > plain.
[ "$N1" -gt "$N_PLAIN" ] && ok "PATH=1 > plain ($N1 > $N_PLAIN)" \
                          || ko "PATH=1 should be > plain ($N1 vs $N_PLAIN)"
[ "$N1" -le "$N2" ] && ok "PATH=1 <= PATH=2 ($N1 <= $N2)" \
                     || ko "PATH=1 should be <= PATH=2 ($N1 vs $N2)"
[ "$N2" -le "$N3" ] && ok "PATH=2 <= PATH=3 ($N2 <= $N3)" \
                     || ko "PATH=2 should be <= PATH=3 ($N2 vs $N3)"
[ "$N3" -gt "$N2" ] && ok "PATH=3 > PATH=2 ($N3 > $N2)" \
                     || ko "PATH=3 should be strictly > PATH=2 ($N3 vs $N2)"
[ "$NA" = "$N1" ] && ok "AFL_LLVM_LTO_PATH alias == AFL_LLVM_PATH ($NA)" \
                   || ko "AFL_LLVM_LTO_PATH alias mismatch ($NA vs $N1)"
[ "$NB" = "$N1" ] && ok "AFL_LLVM_PATH_MODE alias == AFL_LLVM_PATH ($NB)" \
                   || ko "AFL_LLVM_PATH_MODE alias mismatch ($NB vs $N1)"

# Per-binary run + showmap.
for bin in plain.bin p1.bin p2.bin p3.bin a1.bin a2.bin; do
  rm -f "$bin.map"
  printf 'A' | AFL_QUIET=1 ../afl-showmap -m none -o "$bin.map" -q -- \
                "./$bin" >/dev/null 2>&1
  if [ -s "$bin.map" ]; then ok "$bin produces non-empty coverage map";
  else ko "$bin produced no coverage"; fi
done

# PATH should differentiate paths in if_chain across inputs.
# `printf '%b'` (unlike '%c') interprets backslash escapes so '\\001'..'\\007'
# emit distinct bytes.
emit_byte() {
  printf '%b' "$(printf '\\%03o' "$1")"
}
for v in 0 1 2 3 4 5 6 7; do
  emit_byte "$v" | \
    AFL_QUIET=1 ../afl-showmap -m none -o "/tmp/pcg_pathmap.$v" -q -- \
      ./p3.bin >/dev/null 2>&1
  emit_byte "$v" | \
    AFL_QUIET=1 ../afl-showmap -m none -o "/tmp/pcg_plainmap.$v" -q -- \
      ./plain.bin >/dev/null 2>&1
done
SRC_UNIQ=$(for v in 0 1 2 3 4 5 6 7; do emit_byte "$v" | od -An -tx1; done \
             | sort -u | wc -l | tr -d ' ')
if [ "$SRC_UNIQ" -lt 8 ]; then
  ko "test fed only $SRC_UNIQ unique bytes (need 8) — oracle would not probe path differentiation"
fi
UNIQ_P=$(cat /tmp/pcg_pathmap.* 2>/dev/null | sort -u | wc -l)
UNIQ_PLAIN=$(cat /tmp/pcg_plainmap.* 2>/dev/null | sort -u | wc -l)
if [ "$UNIQ_P" -gt "$UNIQ_PLAIN" ]; then
  ok "PATH=3 expands distinct slots across inputs ($UNIQ_P > $UNIQ_PLAIN)"
else
  ko "PATH=3 should expand distinct slots ($UNIQ_P vs $UNIQ_PLAIN)"
fi

# IJON-with-PATH must compile and produce a map.
N_IJON=$(compile_total ijon.bin ijon.log AFL_LLVM_PATH=1 AFL_LLVM_IJON=1)
if [ -z "$N_IJON" ]; then
  ko "IJON+PATH compile failed"
  tail -10 ijon.log
else
  ok "IJON+PATH compiles (total = $N_IJON)"
  emit_byte 1 | AFL_QUIET=1 ../afl-showmap -m none -o ijon.map -q -- \
      ./ijon.bin >/dev/null 2>&1
  if [ -s ijon.map ]; then
    ok "IJON+PATH binary produces coverage"
  else
    ko "IJON+PATH binary produced no coverage"
  fi
fi
rm -f ijon.bin ijon.log ijon.map

# AFL_LLVM_PATH_MAX_PATHS lowers the 100k cap.
N_LOWCAP=$(compile_total lowcap.bin lowcap.log \
              AFL_LLVM_PATH=3 AFL_LLVM_PATH_MAX_PATHS=4)
if [ -z "$N_LOWCAP" ]; then
  ko "AFL_LLVM_PATH_MAX_PATHS=4 compile failed"
  cat lowcap.log
else
  if grep -qiE 'too many.*paths|skip.*path' lowcap.log; then
    ok "AFL_LLVM_PATH_MAX_PATHS=4 triggers skip for functions over the cap"
  else
    ko "AFL_LLVM_PATH_MAX_PATHS=4 produced no skip warnings"
  fi
  if [ "$N_LOWCAP" -lt "$N3" ]; then
    ok "lowered cap shrinks total ($N_LOWCAP < $N3)"
  else
    ko "lowered cap should shrink total ($N_LOWCAP vs $N3)"
  fi
fi
rm -f lowcap.bin lowcap.log

# Empty AFL_LLVM_PATH= must be rejected.
if env AFL_LLVM_PATH= ../afl-clang-fast -O0 -o empty.bin test-llvm-lto-path.c \
     > empty.log 2>&1; then
  ko "AFL_LLVM_PATH= (empty) should be rejected"
else
  ok "AFL_LLVM_PATH= (empty) rejected"
fi
rm -f empty.bin empty.log

# Round-2 N2: setjmp-calling functions must be skipped — confirm by
# building, running, and checking the binary produces coverage.
rm -f sj.bin sj.log sj.map
if env AFL_LLVM_PATH=3 AFL_DEBUG=1 ../afl-clang-fast -O0 \
       -o sj.bin test-llvm-path-setjmp.c > sj.log 2>&1; then
  emit_byte 1 | AFL_QUIET=1 ../afl-showmap -m none -o sj.map -q -- \
      ./sj.bin >/dev/null 2>&1
  if [ -s sj.map ]; then
    ok "PCGUARD setjmp+PATH binary builds and runs (N2)"
  else
    ko "PCGUARD setjmp+PATH binary produced no coverage"
  fi
else
  ko "PCGUARD setjmp test compile failed"; tail -5 sj.log
fi
rm -f sj.bin sj.log sj.map

# Round-2 N4: PATH_MAX_PATHS upper bound (INT32_MAX).
rm -f cap_hi.bin cap_hi.log
if env AFL_LLVM_PATH=3 AFL_LLVM_PATH_MAX_PATHS=2200000000 \
       ../afl-clang-fast -O0 -o cap_hi.bin test-llvm-lto-path.c \
       > cap_hi.log 2>&1; then
  ko "AFL_LLVM_PATH_MAX_PATHS=2200000000 should be rejected (> INT32_MAX)"
else
  if grep -qiE 'INT32_MAX|2147483647|signed i32|i32 register' cap_hi.log; then
    ok "PCGUARD AFL_LLVM_PATH_MAX_PATHS > INT32_MAX rejected (N4)"
  else
    ko "PCGUARD rejection missing INT32_MAX hint"; tail -5 cap_hi.log
  fi
fi
rm -f cap_hi.bin cap_hi.log

# Round-3 R1 — coroutine skip on PCGUARD (smoke: build, run, coverage).
rm -f coro.bin coro.log coro.map
if env AFL_LLVM_PATH=3 AFL_DEBUG=1 ../afl-clang-fast++ -std=c++20 -O0 \
       -o coro.bin test-llvm-path-coro.cc > coro.log 2>&1; then
  emit_byte 1 | AFL_QUIET=1 ../afl-showmap -m none -o coro.map -q -- \
        ./coro.bin >/dev/null 2>&1 || true
  if [ -s coro.map ]; then
    ok "PCGUARD coroutine+PATH binary builds and runs (R1)"
  else
    ko "PCGUARD coroutine+PATH binary produced no coverage"
  fi
else
  if grep -qiE 'coroutine|<coroutine>|no member named' coro.log; then
    note "skipping R1 coroutine test — toolchain lacks C++20 coroutine support"
  else
    ko "PCGUARD coroutine test compile failed for non-toolchain reasons"
    tail -10 coro.log
  fi
fi
rm -f coro.bin coro.log coro.map

# Cleanup
rm -f plain.bin plain.log p1.bin p1.log p2.bin p2.log p3.bin p3.log \
      a1.bin a1.log a2.bin a2.log \
      plain.bin.map p1.bin.map p2.bin.map p3.bin.map a1.bin.map a2.bin.map \
      /tmp/pcg_pathmap.* /tmp/pcg_plainmap.*

echo "[+] passed: $PASS"
echo "[-] failed: $FAIL"
test "$FAIL" = 0
