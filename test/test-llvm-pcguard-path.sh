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
  # If banner says "X extra map entries for PATH", that count is already
  # included in N (the PCGUARD banner reports total instr).
  echo "$n"
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
for v in 0 1 2 3 4 5 6 7; do
  printf '%c' "$(printf '\\%03o' "$v")" | \
    AFL_QUIET=1 ../afl-showmap -m none -o "/tmp/pcg_pathmap.$v" -q -- \
      ./p3.bin >/dev/null 2>&1
  printf '%c' "$(printf '\\%03o' "$v")" | \
    AFL_QUIET=1 ../afl-showmap -m none -o "/tmp/pcg_plainmap.$v" -q -- \
      ./plain.bin >/dev/null 2>&1
done
UNIQ_P=$(cat /tmp/pcg_pathmap.* 2>/dev/null | sort -u | wc -l)
UNIQ_PLAIN=$(cat /tmp/pcg_plainmap.* 2>/dev/null | sort -u | wc -l)
if [ "$UNIQ_P" -gt "$UNIQ_PLAIN" ]; then
  ok "PATH=3 expands distinct slots across inputs ($UNIQ_P > $UNIQ_PLAIN)"
else
  ko "PATH=3 should expand distinct slots ($UNIQ_P vs $UNIQ_PLAIN)"
fi

# Cleanup
rm -f plain.bin plain.log p1.bin p1.log p2.bin p2.log p3.bin p3.log \
      a1.bin a1.log a2.bin a2.log \
      plain.bin.map p1.bin.map p2.bin.map p3.bin.map a1.bin.map a2.bin.map \
      /tmp/pcg_pathmap.* /tmp/pcg_plainmap.*

echo "[+] passed: $PASS"
echo "[-] failed: $FAIL"
test "$FAIL" = 0
