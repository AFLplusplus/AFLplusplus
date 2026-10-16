#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Skipping seed calibration must still start the target's forkserver.

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
AFL_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
FUZZ="$AFL_DIR/afl-fuzz"
TARGET=$(command -v dd)

if [ ! -x "$FUZZ" ]; then
  echo "[-] afl-fuzz not built; skipping"
  exit 0
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

unset AFL_NO_STARTUP_CALIBRATION AFL_SKIP_BIN_CHECK AFL_NO_FORKSRV
unset AFL_DUMB_FORKSRV AFL_EXIT_WHEN_DONE AFL_EXIT_ON_TIME
export AFL_NO_UI=1 AFL_NO_AFFINITY=1 AFL_SKIP_CPUFREQ=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_NO_FASTRESUME=1
mkdir "$TMP/in"
printf 'seed' > "$TMP/in/seed"

run_case() {
  name=$1
  shift

  if ! "$FUZZ" -n -i "$TMP/in" -o "$TMP/$name" -t 1000 -V 1 \
       -- "$TARGET" bs=1 count=1 "of=$TMP/$name.executed" "$@" \
       > "$TMP/$name.log" 2>&1; then
    echo "[-] FAIL: $name aborted"
    cat "$TMP/$name.log"
    return 1
  fi

  if [ ! -s "$TMP/$name.executed" ]; then
    echo "[-] FAIL: $name did not execute the target"
    cat "$TMP/$name.log"
    return 1
  fi

  if [ -n "${AFL_NO_STARTUP_CALIBRATION:-}" ]; then
    if ! grep -q 'Skipping initial seed calibration' "$TMP/$name.log" ||
       grep -q 'Attempting dry run' "$TMP/$name.log"; then
      echo "[-] FAIL: $name did not skip seed calibration"
      cat "$TMP/$name.log"
      return 1
    fi
  fi

  echo "[+] PASS: $name"
}

CODE=0
run_case calibrated-stdin || CODE=1
export AFL_NO_STARTUP_CALIBRATION=1
run_case uncalibrated-stdin || CODE=1
run_case uncalibrated-file if=@@ || CODE=1
exit "$CODE"
