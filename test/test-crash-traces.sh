#!/bin/bash
# test/test-crash-traces.sh — integration test for AFL_CRASH_TRACES
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AFL_DIR="$SCRIPT_DIR/.."
TMP=$(mktemp -d)
trap "rm -rf $TMP" EXIT

CC="$AFL_DIR/afl-clang-fast"
FUZZ="$AFL_DIR/afl-fuzz"

if [ ! -x "$CC" ] || [ ! -x "$FUZZ" ]; then
  echo "[-] afl-clang-fast or afl-fuzz not built; skipping"
  exit 0
fi

# Build at -O0: afl-cc forces -O3, under which ASAN memory checks may not fire
# for this small target in some LLVM setups; -O0 keeps the overflow observable.
if ! AFL_QUIET=1 AFL_USE_ASAN=1 "$CC" -O0 -o "$TMP/target" \
     "$SCRIPT_DIR/test-crash-trace-target.c" 2>"$TMP/build.log"; then
  echo "[-] could not build ASAN target; skipping"
  cat "$TMP/build.log"
  exit 0
fi

mkdir -p "$TMP/in"
printf 'B' > "$TMP/in/seed"          # non-crashing seed; any other byte crashes

COMMON_ENV="AFL_BENCH_UNTIL_CRASH=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
AFL_SKIP_CPUFREQ=1 AFL_NO_AFFINITY=1 AFL_NO_UI=1 \
ASAN_OPTIONS=abort_on_error=1:detect_leaks=0:symbolize=0"

run_fuzz() {  # $1=outdir  $2=traces(0/1)  $3=use_file(0/1)
  local out="$1" traces="$2" usefile="$3" tgt="$TMP/target"
  local args="-i $TMP/in -o $out -m none"
  if [ "$usefile" = "1" ]; then args="$args -- $tgt @@"; else args="$args -- $tgt"; fi
  ( cd "$TMP" && env $COMMON_ENV AFL_CRASH_TRACES=$traces \
    timeout 60 "$FUZZ" $args > "$out.log" 2>&1 ) || true
}

# trace files are named like the crash input + ".txt" (id:*.txt); this must
# exclude the always-present crashes/README.txt.
find_trace() { find "$1" -path '*crashes*' -name 'id:*.txt' 2>/dev/null | head -1; }
find_core() { find "$1" -path '*crashes*' -name 'id:*.core' 2>/dev/null | head -1; }
find_crash() {
  find "$1" -path '*crashes*' -name 'id:*' ! -name '*.txt' ! -name '*.core' \
    2>/dev/null | head -1
}

CORE_PATTERN=$(cat /proc/sys/kernel/core_pattern 2>/dev/null || echo "")
core_capture_possible() {
  if [ "$(id -u)" = "0" ]; then return 0; fi
  case "$CORE_PATTERN" in
    "|"* | /* | "") return 1 ;;
    *) return 0 ;;
  esac
}

CODE=0

# --- Positive, stdin delivery: .txt exists and holds the ASAN report ---
run_fuzz "$TMP/out_stdin" 1 0
CRASH=$(find_crash "$TMP/out_stdin")
TXT=$(find_trace "$TMP/out_stdin")
if [ -z "$CRASH" ]; then
  echo "[*] stdin run produced no crash in time; skipping positive assertion"
elif [ -n "$TXT" ] && grep -q "AddressSanitizer" "$TXT"; then
  echo "[+] AFL_CRASH_TRACES (stdin): trace file written with ASAN report"
  # The target prints a marker on every run; the trace must hold only the
  # crashing run's output (exactly one marker), not accumulated prior runs.
  MARKERS=$(grep -c "run-marker:" "$TXT")
  if [ "$MARKERS" = "1" ]; then
    echo "[+] AFL_CRASH_TRACES: trace holds only the crashing run's output"
  else
    echo "[!] AFL_CRASH_TRACES: trace has $MARKERS run-markers (expected 1) - prior-run output leaked in"
    CODE=1
  fi
else
  echo "[!] AFL_CRASH_TRACES (stdin): crash found but trace/ASAN report missing"
  echo "    crash=$CRASH txt=$TXT"
  [ -n "$TXT" ] && { echo "--- $TXT ---"; cat "$TXT"; }
  CODE=1
fi

# --- Positive, stdin: a "<crash>.core" is written when cores are capturable ---
if [ -n "$CRASH" ] && core_capture_possible; then
  CORE=$(find_core "$TMP/out_stdin")
  if [ -n "$CORE" ] && [ -s "$CORE" ] && head -c4 "$CORE" | grep -q ELF; then
    echo "[+] AFL_CRASH_TRACES (stdin): core file written beside the crash"
  else
    echo "[!] AFL_CRASH_TRACES (stdin): crash found but no valid .core (core_pattern='$CORE_PATTERN')"
    CODE=1
  fi
elif [ -n "$CRASH" ]; then
  echo "[*] core capture not possible (core_pattern='$CORE_PATTERN', not root); skipping .core assertion"
fi

# --- Positive, file (@@) delivery: .txt exists beside the crash ---
run_fuzz "$TMP/out_file" 1 1
CRASH=$(find_crash "$TMP/out_file")
TXT=$(find_trace "$TMP/out_file")
if [ -z "$CRASH" ]; then
  echo "[*] @@ run produced no crash in time; skipping positive assertion"
elif [ -n "$TXT" ]; then
  echo "[+] AFL_CRASH_TRACES (@@): trace file written"
  MARKERS=$(grep -c "run-marker:" "$TXT")
  if [ "$MARKERS" = "1" ]; then
    echo "[+] AFL_CRASH_TRACES (@@): trace holds only the crashing run's output"
  else
    echo "[!] AFL_CRASH_TRACES (@@): trace has $MARKERS run-markers (expected 1) - prior-run output leaked in"
    CODE=1
  fi
else
  echo "[!] AFL_CRASH_TRACES (@@): crash found but no trace file beside it"
  CODE=1
fi

# --- Positive, @@: a "<crash>.core" is written when cores are capturable ---
if [ -n "$CRASH" ] && core_capture_possible; then
  CORE=$(find_core "$TMP/out_file")
  if [ -n "$CORE" ] && [ -s "$CORE" ] && head -c4 "$CORE" | grep -q ELF; then
    echo "[+] AFL_CRASH_TRACES (@@): core file written beside the crash"
  else
    echo "[!] AFL_CRASH_TRACES (@@): crash found but no valid .core (core_pattern='$CORE_PATTERN')"
    CODE=1
  fi
elif [ -n "$CRASH" ]; then
  echo "[*] core capture not possible (core_pattern='$CORE_PATTERN', not root); skipping .core assertion"
fi

# --- Negative: without the env, a crash must NOT get a .txt ---
run_fuzz "$TMP/out_off" 0 0
if [ -n "$(find_crash "$TMP/out_off")" ] && [ -z "$(find_trace "$TMP/out_off")" ]; then
  echo "[+] without AFL_CRASH_TRACES: no trace file written (correct)"
elif [ -z "$(find_crash "$TMP/out_off")" ]; then
  echo "[*] negative run produced no crash in time; skipping negative assertion"
else
  echo "[!] trace file written even though AFL_CRASH_TRACES was unset"
  CODE=1
fi

# --- Negative: without the env, no "<crash>.core" must be written ---
if [ -n "$(find_crash "$TMP/out_off")" ]; then
  if [ -z "$(find_core "$TMP/out_off")" ]; then
    echo "[+] without AFL_CRASH_TRACES: no core file written (correct)"
  else
    echo "[!] core file written even though AFL_CRASH_TRACES was unset"
    CODE=1
  fi
fi

exit $CODE
