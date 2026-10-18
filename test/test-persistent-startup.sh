#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# A slow persistent child startup must not turn every restart into a timeout.

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
AFL_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
CC="$AFL_DIR/afl-clang-fast"
FUZZ="$AFL_DIR/afl-fuzz"

if [ ! -x "$CC" ] || [ ! -x "$FUZZ" ]; then
  echo "[-] afl-clang-fast or afl-fuzz not built; skipping"
  exit 0
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

unset AFL_NO_STARTUP_CALIBRATION AFL_SKIP_BIN_CHECK AFL_NO_FORKSRV
unset AFL_EXIT_WHEN_DONE AFL_EXIT_ON_TIME AFL_IGNORE_TIMEOUTS AFL_KEEP_TIMEOUTS
unset AFL_NO_FASTRESUME AFL_FORCE_FASTRESUME AFL_CRASH_EXITCODE
export AFL_NO_UI=1 AFL_NO_AFFINITY=1 AFL_SKIP_CPUFREQ=1 AFL_ALLOW_TMP=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_HANG_TMOUT=100

cat > "$TMP/target.c" <<'EOF'
/* SPDX-License-Identifier: AGPL-3.0-or-later */

#include <fcntl.h>
#include <signal.h>
#include <unistd.h>

int main(int argc, char **argv) {

  if (argc != 3) { return 1; }

  __AFL_INIT();

  /* Repeated for every new child, but not for resumed loop iterations. */
  usleep(300000);

  int fd = open(argv[1], O_WRONLY | O_CREAT | O_APPEND, 0600);
  if (fd < 0) { return 1; }
  int restarted = lseek(fd, 0, SEEK_END) > 0;
  if (restarted && argv[2][0] == 'l') { usleep(200000); }
  if (write(fd, ".", 1) != 1) { return 1; }
  close(fd);

  unsigned int iteration = 0;
  while (__AFL_LOOP(8)) {

    unsigned char buf[32];
    if (read(0, buf, sizeof(buf)) < 0) { return 1; }

    /* This valid input needs its normal budget in addition to startup time. */
    if (restarted && argv[2][0] == 's') { usleep(100000); }

    /* Calibration finishes before the sixth iteration. A slow warm iteration
       must still time out, and the next child must recover after either fault.
     */
    if (++iteration == 6) {

      if (argv[2][0] == 'h') { usleep(300000); }
      if (argv[2][0] == 'c') { raise(SIGABRT); }

    }

  }

  return 0;

}
EOF

"$CC" -O2 "$TMP/target.c" -o "$TMP/target"
mkdir "$TMP/in"
printf 'seed' > "$TMP/in/seed"

stat_of() {
  awk -v key="$2" '$1 == key { print $3 }' "$TMP/$1/default/fuzzer_stats"
}

fail() {
  echo "[-] FAIL: $name: $*"
  cat "$TMP/$name.log"
  exit 1
}

run_case() {
  name=$1
  scenario=$2
  input=$3
  expected=$4
  shift 4
  seconds=2
  if [ "$scenario" = slow ]; then seconds=3; fi

  before=0
  if [ -f "$TMP/$name.children" ]; then
    before=$(wc -c < "$TMP/$name.children")
  fi

  if ! "$FUZZ" -i "$input" -o "$TMP/$name" -V "$seconds" -s 1 "$@" \
       -- "$TMP/target" "$TMP/$name.children" "$scenario" \
       > "$TMP/$name.log" 2>&1; then
    fail "afl-fuzz aborted"
  fi

  [ -f "$TMP/$name.children" ] || fail "target did not initialize"
  children=$(( $(wc -c < "$TMP/$name.children") - before ))
  if [ "$scenario" = limit ]; then
    [ "$children" -eq 1 ] || fail "startup exceeded the 400 ms ceiling"
  else
    [ "$children" -ge 3 ] || fail "only $children child startups completed"
  fi

  timeout=$(stat_of "$name" exec_timeout)
  startup=$(stat_of "$name" child_init_tmout)
  [ -n "$timeout" ] && [ -n "$startup" ] || fail "missing timeout statistics"

  if [ "$expected" = auto ]; then
    [ "$timeout" -lt 300 ] || fail "warm timeout increased to $timeout ms"
    [ "$startup" -ge 300 ] && [ "$startup" -le 1000 ] ||
      fail "startup timeout is $startup ms"
  else
    [ "$timeout" -eq "$expected" ] && [ "$startup" -eq 0 ] ||
      fail "fixed timeout changed: $timeout/$startup ms"
  fi

  case "$scenario" in
    normal|slow)
      [ "$(stat_of "$name" total_tmout)" -eq 0 ] || fail "spurious timeouts"
      ;;
    hang)
      [ "$(stat_of "$name" saved_hangs)" -gt 0 ] || fail "warm hang was missed"
      ;;
    limit)
      [ "$(stat_of "$name" total_tmout)" -gt 0 ] || fail "ceiling was ignored"
      ;;
    crash)
      [ "$(stat_of "$name" saved_crashes)" -gt 0 ] || fail "warm crash was missed"
      ;;
  esac

  echo "[+] PASS: $name ($scenario, $children children, $timeout/$startup ms)"
}

for sync in default pipe; do
  unset AFL_OLD_CHILD_SYNC
  if [ "$sync" = pipe ]; then export AFL_OLD_CHILD_SYNC=1; fi

  run_case "$sync-auto" normal "$TMP/in" auto
  run_case "$sync-auto" normal - auto
  run_case "$sync-auto" normal - auto -t 1000+
  run_case "$sync-auto" normal - 500 -t 500
  run_case "$sync-ceiling" normal "$TMP/in" auto -t 1000+
  run_case "$sync-slow" slow "$TMP/in" auto
  run_case "$sync-limit" limit "$TMP/in" auto -t 400+
  run_case "$sync-hang" hang "$TMP/in" auto
  run_case "$sync-crash" crash "$TMP/in" auto
done
