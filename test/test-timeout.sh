#!/bin/bash
# test/test-timeout.sh — contract tests for the -t <msec>+ adaptive timeout
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AFL_DIR="$SCRIPT_DIR/.."
CC="$AFL_DIR/afl-clang-fast"
FUZZ="$AFL_DIR/afl-fuzz"

if [ ! -x "$CC" ] || [ ! -x "$FUZZ" ]; then
  echo "[-] afl-clang-fast or afl-fuzz not built; skipping"
  exit 0
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

unset AFL_HANG_TMOUT AFL_KEEP_TIMEOUTS AFL_IGNORE_TIMEOUTS AFL_MAP_SIZE
unset AFL_CRASH_EXITCODE
export AFL_NO_UI=1 AFL_ALLOW_TMP=1 AFL_QUIET=1 AFL_IGNORE_SEED_PROBLEMS=1
export AFL_NO_AFFINITY=1

TARGET="$TMP/target"

if ! "$CC" -o "$TARGET" "$SCRIPT_DIR/test-timeout-target.c" \
     2>"$TMP/build.log"; then
  echo "[-] could not build the test target; skipping"
  cat "$TMP/build.log"
  exit 0
fi

mkdir -p "$TMP/in"
printf 'a' > "$TMP/in/1"
printf 'b' > "$TMP/in/2"
printf 'c' > "$TMP/in/3"

mkdir -p "$TMP/in-crash"
printf 'a' > "$TMP/in-crash/1"

mkdir -p "$TMP/in-slowcrash"
printf 'F' > "$TMP/in-slowcrash/1"

mkdir -p "$TMP/in-hang"
printf 'HA' > "$TMP/in-hang/1"

CODE=0
WALL_MS=0

fail() {

  echo "[-] FAIL: $*"
  CODE=1

}

pass() {

  echo "[+] PASS: $*"

}

sync_dir() {

  if [ -d "$1/default" ]; then echo "$1/default"; else echo "$1"; fi

}

stat_of() {

  local stats
  stats="$(sync_dir "$1")/fuzzer_stats"
  [ -f "$stats" ] || return 0
  awk -v key="$2" '$1 == key { print $3 }' "$stats"

}

# counts the files in "<out dir>/$2" whose first byte is the character "$3"
count_starting_with() {

  local d f n=0
  d="$(sync_dir "$1")/$2"
  for f in "$d"/*; do
    [ -f "$f" ] || continue
    if [ "$(dd if="$f" bs=1 count=1 2>/dev/null)" = "$3" ]; then n=$((n + 1)); fi
  done
  echo "$n"

}

# run_fuzz <out dir> <-V seconds> <input dir> [extra afl-fuzz options...]
# fails the test run when afl-fuzz does not exit cleanly and records the wall
# clock time of the campaign in WALL_MS
run_fuzz() {

  local out="$1" secs="$2" indir="$3" rc start
  shift 3
  rm -rf "$out"
  start=$(date +%s%N)
  "$FUZZ" -i "$indir" -o "$out" "$@" -V "$secs" -- "$TARGET" @@ \
      >"$out.log" 2>&1
  rc=$?
  WALL_MS=$((($(date +%s%N) - start) / 1000000))
  if [ "$rc" -ne 0 ]; then

    fail "afl-fuzz exited with status $rc"
    tail -20 "$out.log"
    return 1

  fi
  return 0

}

echo "[*] test 1: -t 1000+ does not collapse to the 5 ms floor"
if run_fuzz "$TMP/o1" 5 "$TMP/in" -t 1000+; then
  T1=$(sed -n 's/.*starting with an exec timeout of \([0-9]*\) ms.*/\1/p' \
       "$TMP/o1.log" | head -1)
  if [ -z "$T1" ] || [ "$T1" -lt 20 ]; then
    fail "startup exec_timeout is '$T1', expected >= 20"
  else
    pass "startup exec_timeout = $T1"
  fi
fi

echo "[*] test 2: plain -t 1000 stays pinned"
if run_fuzz "$TMP/o2" 5 "$TMP/in" -t 1000; then
  T2=$(stat_of "$TMP/o2" exec_timeout)
  if [ "$T2" != "1000" ]; then
    fail "plain -t exec_timeout is '$T2', expected 1000"
  else
    pass "plain -t exec_timeout = $T2"
  fi
fi

echo "[*] test 3: -t 1000+ ratchets up when a slow path is reachable"
if run_fuzz "$TMP/o3" 15 "$TMP/in" -t 1000+; then
  T3=$(stat_of "$TMP/o3" exec_timeout)
  N3=$(count_starting_with "$TMP/o3" queue S)
  if [ -z "$T3" ] || [ "$T3" -lt 100 ]; then
    fail "ratcheted exec_timeout is '$T3', expected >= 100"
  elif [ "$N3" -lt 1 ]; then
    fail "the slow input was not added to the queue"
  else
    pass "ratcheted exec_timeout = $T3, slow input queued"
  fi
fi

echo "[*] test 4: -t 100+ never queues an input slower than the ceiling"
if run_fuzz "$TMP/o4" 15 "$TMP/in" -t 100+; then
  T4=$(stat_of "$TMP/o4" exec_timeout)
  N4=$(count_starting_with "$TMP/o4" queue S)
  if [ -z "$T4" ] || [ "$T4" -gt 100 ]; then
    fail "exec_timeout is '$T4', expected <= 100"
  elif [ "$N4" -ne 0 ]; then
    fail "$N4 input(s) needing 200 ms were queued below a 100 ms ceiling"
  else
    pass "ceiling honoured, exec_timeout = $T4"
  fi
fi

echo "[*] test 5: -C mode never queues a non-crashing input"
export AFL_CRASH_EXITCODE=4
if run_fuzz "$TMP/o5" 15 "$TMP/in-crash" -t 1000+ -C; then
  N5=$(count_starting_with "$TMP/o5" queue S)
  H5=$(count_starting_with "$TMP/o5" hangs S)
  if [ "$N5" -ne 0 ]; then
    fail "$N5 non-crashing input(s) were queued in -C mode"
  elif [ "$H5" -ne 0 ]; then
    fail "a merely slow input was saved as a hang"
  else
    pass "-C mode rejected the non-crashing slow input"
  fi
fi
unset AFL_CRASH_EXITCODE

echo "[*] test 6: -C mode ratchets on a slow crashing input"
export AFL_CRASH_EXITCODE=2
if run_fuzz "$TMP/o6" 15 "$TMP/in-slowcrash" -t 1000+ -C; then
  T6=$(stat_of "$TMP/o6" exec_timeout)
  N6=$(count_starting_with "$TMP/o6" queue S)
  H6=$(count_starting_with "$TMP/o6" hangs S)
  if [ -z "$T6" ] || [ "$T6" -lt 100 ]; then
    fail "ratcheted exec_timeout is '$T6', expected >= 100"
  elif [ "$N6" -lt 1 ]; then
    fail "the slow crashing input was not added to the queue"
  elif [ "$H6" -ne 0 ]; then
    fail "the slow crashing input was also saved as a hang"
  else
    pass "-C mode ratcheted to $T6 and queued the slow crash"
  fi
fi
unset AFL_CRASH_EXITCODE

echo "[*] test 7: a genuine hang is confirmed without waiting for the ceiling"
if run_fuzz "$TMP/o7" 5 "$TMP/in-hang" -t 60000+; then
  H7=$(stat_of "$TMP/o7" saved_hangs)
  if [ "$WALL_MS" -gt 20000 ]; then
    fail "a 5 s campaign with a 60000 ms ceiling took $WALL_MS ms"
  elif [ -z "$H7" ] || [ "$H7" -lt 1 ]; then
    fail "no hang was saved, so the confirmation path was not exercised"
  else
    pass "hang confirmed in $WALL_MS ms, saved_hangs = $H7"
  fi
fi

echo "[*] test 8: coverage of an entry that failed calibration is handed back"
export AFL_CRASH_EXITCODE=9
if run_fuzz "$TMP/o8" 20 "$TMP/in" -t 100; then
  N8=$(count_starting_with "$TMP/o8" queue Q)
  if [ "$N8" -lt 2 ]; then
    fail "the Q path was queued $N8 time(s), its coverage was not handed back"
  elif [ "$N8" -gt 10 ]; then
    fail "the Q path was requeued $N8 times, the handback is not bounded"
  else
    pass "Q path requeued $N8 times, bounded by CAL_RECLAIM_MAX"
  fi
fi
unset AFL_CRASH_EXITCODE

exit $CODE
