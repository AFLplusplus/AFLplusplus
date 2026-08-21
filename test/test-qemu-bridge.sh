#!/bin/sh

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$HERE/.." && pwd)
BRIDGE_DIR="$ROOT/qemu_bridge"
BRIDGE="$ROOT/afl-qemu-bridge"
SHOWMAP="$ROOT/afl-showmap"
FUZZ="$ROOT/afl-fuzz"
LIBQASAN="$ROOT/libqasan.so"
LEGACY_TRACE="$ROOT/qemu_mode/afl-qemu-trace"

export AFL_PATH="$ROOT"
export AFL_QEMU_MODE=bridge
export AFL_NO_AFFINITY=1
export AFL_SKIP_CPUFREQ=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_NO_UI=1
unset AFL_INST_LIBS AFL_COMPCOV_LEVEL AFL_QEMU_COMPCOV AFL_USE_QASAN
unset AFL_QEMU_PERSISTENT_ADDR AFL_QEMU_PERSISTENT_GPR AFL_QEMU_PERSISTENT_EXITS
unset AFL_QEMU_BACKEND AFL_PRELOAD AFL_MAP_SIZE

PASS=0
FAIL=0
SKIP=0
SUMMARY=""

WORK=$(mktemp -d "${TMPDIR:-/tmp}/aflqb.XXXXXX") || { echo "[-] cannot create temp dir"; exit 1; }

cleanup() {
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

record() {
  STATUS="$1"
  NAME="$2"
  DETAIL="$3"
  case "$STATUS" in
    PASS) PASS=$((PASS + 1)); echo "[+] PASS  $NAME  $DETAIL" ;;
    FAIL) FAIL=$((FAIL + 1)); echo "[-] FAIL  $NAME  $DETAIL" ;;
    SKIP) SKIP=$((SKIP + 1)); echo "[*] SKIP  $NAME  $DETAIL" ;;
  esac
  SUMMARY="$SUMMARY
$STATUS|$NAME|$DETAIL"
}

CC=${CC:-cc}
command -v "$CC" >/dev/null 2>&1 || { echo "[-] no C compiler ($CC) found"; exit 1; }

NOPIE=""
if echo "int main(void){return 0;}" | "$CC" -no-pie -fno-pie -x c -o "$WORK/_nopie" - >/dev/null 2>&1; then
  NOPIE="-no-pie -fno-pie"
fi

SYS=$(uname -m)
HAVE_COMPCOV=0
case "$SYS" in
  x86_64|amd64|i686|i386|i86pc|aarch64|arm*|mips*|powerpc*|ppc*) HAVE_COMPCOV=1 ;;
esac

echo "[*] AFL++ QEMU bridge acceptance harness"
echo "[*] root=$ROOT arch=$SYS work=$WORK"

if [ ! -x "$BRIDGE" ]; then
  $ECHO "$YELLOW[-] qemu_bridge not compiled, cannot test"
  INCOMPLETE=1
  exit 0
fi

for b in "$BRIDGE" "$SHOWMAP" "$FUZZ"; do
  if [ ! -x "$b" ]; then
    echo "[-] required binary missing: $b (build AFL++ first)"
    exit 1
  fi
done

cat > "$WORK/instr.c" <<'EOF'
#include <stdio.h>
#include <unistd.h>
int main(void) {
  char b[16];
  int n = read(0, b, 15);
  if (n < 1) return 1;
  b[n] = 0;
  switch (b[0]) {
    case '0': puts("zero"); break;
    case '1': puts("one"); break;
    default:  puts("other"); break;
  }
  return 0;
}
EOF

cat > "$WORK/pers.c" <<'EOF'
#include <stdio.h>
#include <unistd.h>
int target(char *b, int n) {
  if (n > 0 && b[0] == 'X') return 1;
  return 0;
}
int main(void) {
  char b[64];
  int n = read(0, b, 63);
  if (n < 0) n = 0;
  b[n] = 0;
  return target(b, n);
}
EOF

cat > "$WORK/compcov.c" <<'EOF'
#include <stdio.h>
#include <unistd.h>
int main(void) {
  unsigned char b[8];
  int n = read(0, b, 4);
  if (n < 4) return 1;
  unsigned int x = (unsigned int)b[0] | ((unsigned int)b[1] << 8) |
                   ((unsigned int)b[2] << 16) | ((unsigned int)b[3] << 24);
  if (x == 0xabadcafeU) puts("match");
  else puts("no");
  return 0;
}
EOF

cat > "$WORK/cmplog.c" <<'EOF'
#include <stdio.h>
#include <unistd.h>
int main(void) {
  unsigned char b[8];
  int n = read(0, b, 4);
  if (n < 4) return 1;
  unsigned int x = (unsigned int)b[0] | ((unsigned int)b[1] << 8) |
                   ((unsigned int)b[2] << 16) | ((unsigned int)b[3] << 24);
  if (x == 0xdeadbeefU) { puts("win"); return 2; }
  puts("no");
  return 0;
}
EOF

cat > "$WORK/oob.c" <<'EOF'
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main(void) {
  unsigned char b[64];
  int n = read(0, b, 63);
  if (n < 1) return 1;
  char *p = malloc(8);
  memcpy(p, b, (size_t)n);
  int s = 0;
  int i;
  for (i = 0; i < 8; i++) s += p[i];
  free(p);
  return s & 1;
}
EOF

"$CC" -O0 -o "$WORK/instr" "$WORK/instr.c" >/dev/null 2>&1 || { echo "[-] cannot compile instr target"; exit 1; }
"$CC" $NOPIE -O0 -o "$WORK/pers" "$WORK/pers.c" >/dev/null 2>&1
"$CC" $NOPIE -O0 -o "$WORK/compcov" "$WORK/compcov.c" >/dev/null 2>&1
"$CC" $NOPIE -O0 -o "$WORK/cmplog" "$WORK/cmplog.c" >/dev/null 2>&1
"$CC" $NOPIE -O0 -o "$WORK/oob" "$WORK/oob.c" >/dev/null 2>&1

map_lines() {
  "$SHOWMAP" -Q -o "$2" -- "$1" < "$3" >/dev/null 2>&1
  if [ -f "$2" ]; then wc -l < "$2" | tr -d ' '; else echo 0; fi
}

persistent_addr() {
  ADDR=$(nm "$1" 2>/dev/null | awk '$3=="target"{print $1}' | head -1)
  [ -z "$ADDR" ] && return 1
  if file "$1" | grep -q 'statically linked'; then
    echo "0x$ADDR"
    return 0
  fi
  if file "$1" | grep -q 'pie executable'; then
    if file "$1" | grep -q "32-bit"; then
      echo "0x4$(echo "$ADDR" | sed 's/^.//')"
    elif [ "$SYS" = "aarch64" ]; then
      echo "0x55$(echo "$ADDR" | sed 's/^........//')"
    else
      echo "0x4$(echo "$ADDR" | sed 's/^.......//')"
    fi
    return 0
  fi
  echo "0x$ADDR"
  return 0
}

stat_field() {
  grep -m1 "$2" "$1/default/fuzzer_stats" 2>/dev/null | awk -F: '{gsub(/[ %]/,"",$2); print $2}'
}

printf '0' > "$WORK/in0"
printf '1' > "$WORK/in1"

echo
echo "[*] Test 1: coverage self-test + determinism"
L0=$(map_lines "$WORK/instr" "$WORK/m0" "$WORK/in0")
L1=$(map_lines "$WORK/instr" "$WORK/m1" "$WORK/in1")
L0B=$(map_lines "$WORK/instr" "$WORK/m0b" "$WORK/in0")
if [ "$L0" -gt 0 ] && [ "$L1" -gt 0 ] && ! diff -q "$WORK/m0" "$WORK/m1" >/dev/null 2>&1 && diff -q "$WORK/m0" "$WORK/m0b" >/dev/null 2>&1; then
  record PASS "coverage" "input0=$L0 input1=$L1 tuples differ, rerun deterministic"
else
  record FAIL "coverage" "input0=$L0 input1=$L1 differ/determinism check failed"
fi

echo
echo "[*] Test 2: range filtering (default vs AFL_INST_LIBS=1)"
DEF=$(map_lines "$WORK/instr" "$WORK/rdef" "$WORK/in0")
AFL_INST_LIBS=1 "$SHOWMAP" -Q -o "$WORK/rall" -- "$WORK/instr" < "$WORK/in0" >/dev/null 2>&1
ALL=$( [ -f "$WORK/rall" ] && wc -l < "$WORK/rall" | tr -d ' ' || echo 0)
if [ "$DEF" -gt 0 ] && [ "$ALL" -gt $((DEF * 4)) ]; then
  record PASS "range-filter" "default=$DEF inst_libs=$ALL"
else
  record FAIL "range-filter" "default=$DEF inst_libs=$ALL (expected inst_libs >> default)"
fi

echo
echo "[*] Test 3: persistent throughput + stability"
if [ ! -x "$WORK/pers" ]; then
  record SKIP "persistent" "could not compile persistent target"
else
  PADDR=$(persistent_addr "$WORK/pers")
  if [ -z "$PADDR" ]; then
    record SKIP "persistent" "could not resolve target() address"
  else
    mkdir -p "$WORK/pin"
    printf 'hello' > "$WORK/pin/seed"
    timeout 15 "$FUZZ" -Q -m none -i "$WORK/pin" -o "$WORK/np" -- "$WORK/pers" >/dev/null 2>&1
    NP=$(stat_field "$WORK/np" execs_per_sec)
    AFL_QEMU_PERSISTENT_ADDR="$PADDR" AFL_QEMU_PERSISTENT_GPR=1 timeout 15 "$FUZZ" -Q -m none -i "$WORK/pin" -o "$WORK/p" -- "$WORK/pers" >/dev/null 2>&1
    PS=$(stat_field "$WORK/p" execs_per_sec)
    STAB=$(stat_field "$WORK/p" stability)
    NPI=$(printf '%.0f' "${NP:-0}" 2>/dev/null); NPI=${NPI:-0}
    PSI=$(printf '%.0f' "${PS:-0}" 2>/dev/null); PSI=${PSI:-0}
    STABI=$(printf '%.0f' "${STAB:-0}" 2>/dev/null); STABI=${STABI:-0}
    if [ "$NPI" -gt 0 ] && [ "$PSI" -ge $((NPI * 3)) ] && [ "$STABI" -ge 99 ]; then
      record PASS "persistent" "addr=$PADDR non-persist=${NP}/s persist=${PS}/s (>=3x) stability=${STAB}%"
    else
      record FAIL "persistent" "addr=$PADDR non-persist=${NP}/s persist=${PS}/s stability=${STAB}% (need >=3x and >=99% stability)"
    fi
  fi
fi

echo
echo "[*] Test 4: CompCov gradient (AFL_COMPCOV_LEVEL=2)"
if [ "$HAVE_COMPCOV" != "1" ]; then
  record SKIP "compcov" "arch $SYS not supported for compcov"
elif [ ! -x "$WORK/compcov" ]; then
  record SKIP "compcov" "could not compile compcov target"
else
  printf '\000\000\000\000' > "$WORK/c0"
  printf '\000\000\000\253' > "$WORK/c1"
  printf '\000\000\255\253' > "$WORK/c2"
  printf '\000\312\255\253' > "$WORK/c3"
  BU=$(mktemp "$WORK/bu.XXXXXX")
  CU=$(mktemp "$WORK/cu.XXXXXX")
  : > "$BU"; : > "$CU"
  for f in c0 c1 c2 c3; do
    "$SHOWMAP" -Q -o "$WORK/cb_$f" -- "$WORK/compcov" < "$WORK/$f" >/dev/null 2>&1
    [ -f "$WORK/cb_$f" ] && cat "$WORK/cb_$f" >> "$BU"
    AFL_QEMU_COMPCOV=1 AFL_COMPCOV_LEVEL=2 "$SHOWMAP" -Q -o "$WORK/cc_$f" -- "$WORK/compcov" < "$WORK/$f" >/dev/null 2>&1
    [ -f "$WORK/cc_$f" ] && cat "$WORK/cc_$f" >> "$CU"
  done
  BASEU=$(sort -u "$BU" | wc -l | tr -d ' ')
  COMPU=$(sort -u "$CU" | wc -l | tr -d ' ')
  if [ "$COMPU" -gt "$BASEU" ]; then
    record PASS "compcov" "baseline-union=$BASEU compcov-union=$COMPU"
  else
    record FAIL "compcov" "baseline-union=$BASEU compcov-union=$COMPU (expected compcov > baseline)"
  fi
fi

echo
echo "[*] Test 5: CmpLog forkserver (afl-fuzz -Q -c 0)"
if [ ! -x "$WORK/cmplog" ]; then
  record SKIP "cmplog" "could not compile cmplog target"
else
  mkdir -p "$WORK/clin"
  printf 'AAAA' > "$WORK/clin/seed"
  timeout 15 "$FUZZ" -Q -c 0 -m none -i "$WORK/clin" -o "$WORK/clout" -- "$WORK/cmplog" > "$WORK/cllog" 2>&1
  if grep -qi "CMPLOG forkserver successfully started" "$WORK/cllog" && grep -qi "All set and ready to roll\|forkserver successfully started" "$WORK/cllog" && ! grep -qi "OLD_CMPLOG\|cmplog.*error\|failed to start" "$WORK/cllog"; then
    record PASS "cmplog" "both forkservers started, no OLD_CMPLOG error"
  else
    record FAIL "cmplog" "cmplog forkserver did not start cleanly (see log)"
    grep -iE "cmplog|forkserver|error" "$WORK/cllog" | head -5
  fi
fi

echo
echo "[*] Test 6: QASan heap-buffer-overflow detection"
if [ ! -x "$WORK/oob" ]; then
  record SKIP "qasan" "could not compile overflow target"
elif [ ! -f "$LIBQASAN" ]; then
  record SKIP "qasan" "libqasan.so not present"
else
  printf 'AAAA' > "$WORK/qsmall"
  printf 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' > "$WORK/qbig"
  AFL_USE_QASAN=1 "$BRIDGE" "$WORK/oob" < "$WORK/qsmall" > "$WORK/q_clean" 2>&1
  CLEAN_RC=$?
  AFL_USE_QASAN=1 "$BRIDGE" "$WORK/oob" < "$WORK/qbig" > "$WORK/q_oob" 2>&1
  OOB_RC=$?
  if [ "$CLEAN_RC" -lt 128 ] && ! grep -qi "heap-buffer-overflow" "$WORK/q_clean" && [ "$OOB_RC" -ge 128 ] && grep -qi "heap-buffer-overflow" "$WORK/q_oob"; then
    record PASS "qasan" "in-bound clean(rc=$CLEAN_RC), oob detected(rc=$OOB_RC heap-buffer-overflow)"
  else
    record FAIL "qasan" "clean_rc=$CLEAN_RC oob_rc=$OOB_RC (expected clean<128 no-report, oob>=128 with report)"
  fi
fi

echo
echo "[*] Test 7: legacy qemuafl A/B parity (optional)"
if [ ! -x "$LEGACY_TRACE" ]; then
  record SKIP "legacy-ab" "legacy qemuafl not built (qemu_mode/afl-qemu-trace absent)"
else
  BRIDGE_AB=$(map_lines "$WORK/instr" "$WORK/ab_bridge" "$WORK/in1")
  AFL_QEMU_MODE=trace AFL_QEMU_BACKEND=legacy AFL_PATH="$ROOT/qemu_mode" "$SHOWMAP" -Q -o "$WORK/ab_legacy" -- "$WORK/instr" < "$WORK/in1" >/dev/null 2>&1
  LEG_AB=$( [ -f "$WORK/ab_legacy" ] && wc -l < "$WORK/ab_legacy" | tr -d ' ' || echo 0)
  if [ "$BRIDGE_AB" -gt 0 ] && [ "$LEG_AB" -gt 0 ] && [ "$BRIDGE_AB" -ge "$LEG_AB" ]; then
    record PASS "legacy-ab" "bridge=$BRIDGE_AB legacy=$LEG_AB (bridge >= legacy)"
  else
    record FAIL "legacy-ab" "bridge=$BRIDGE_AB legacy=$LEG_AB"
  fi
fi

echo
echo "==================== SUMMARY ===================="
printf '%-6s %-14s %s\n' "RESULT" "TEST" "DETAIL"
printf '%-6s %-14s %s\n' "------" "----" "------"
echo "$SUMMARY" | while IFS='|' read -r st nm dt; do
  [ -z "$st" ] && continue
  printf '%-6s %-14s %s\n' "$st" "$nm" "$dt"
done
echo "================================================="
echo "PASS=$PASS FAIL=$FAIL SKIP=$SKIP"

if [ "$FAIL" -gt 0 ]; then
  echo "[-] acceptance suite FAILED"
  exit 1
fi
echo "[+] acceptance suite PASSED"
exit 0
