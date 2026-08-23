#!/bin/bash
# Sweep the park depth and report fork cost against dirty footprint.
# usage: fork-cost.sh <harness> <input> [depths...]
#
# The input is fed on stdin, not as argv[1]. Under afl-clang-fast the harness's
# main always takes the __AFL_LOOP path and the argv branch is compiled out, so
# an argv[1] input is silently ignored and every depth reports park_ops=0.
# Prefer the plain-cc build here anyway: this measures fork cost against dirty
# footprint, and instrumentation is neither.

set -o pipefail

HARNESS="$1"
INPUT="$2"
shift 2
DEPTHS="${*:-0 1 2 4 8 16}"

if [ ! -x "$HARNESS" ] || [ ! -f "$INPUT" ]; then

  echo "usage: $0 <harness> <input> [depths...]" >&2
  exit 1

fi

printf '| park_ops | us_per_fork | rss_kb | delta_us_vs_0 |\n'
printf '|---|---|---|---|\n'

BASE=""

for k in $DEPTHS; do

  LINE="$(AFL_POOL_FORK_PROBE="$k" "$HARNESS" < "$INPUT" | grep '^park_ops=')"
  [ -z "$LINE" ] && continue
  US="$(echo "$LINE" | sed 's/.*us_per_fork=\([0-9.]*\).*/\1/')"
  RSS="$(echo "$LINE" | sed 's/.*rss_kb=\([0-9]*\).*/\1/')"
  [ -z "$BASE" ] && BASE="$US"
  printf '| %s | %s | %s | %s |\n' "$k" "$US" "$RSS" \
    "$(awk -v a="$US" -v b="$BASE" 'BEGIN{printf "%.2f", a-b}')"

done
