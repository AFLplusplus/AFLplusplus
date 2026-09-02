#!/bin/bash
# prefix-share.sh - does an execution cost scale with input length?
#
# The §7.3 question for a target with no mutator that reports operation
# boundaries. A snapshot pool removes prefix replay, so if truncating the input
# does not make an execution cheaper there is nothing for a pool to remove, and
# the answer is a no-go however good the Amdahl and -Jb readings are.
#
# Method: run `afl-fuzz -Jb` on a one-seed input directory and read
# cost_fork_us, which is 200 forkserver executions of that one seed. Repeat with
# the seed truncated to a fraction of its bytes. For an input that is a sequence
# of operations, taking the first f% of the bytes is roughly taking the first f%
# of the operations.
#
# usage: prefix-share.sh <afl-fuzz> <seed-file> <core> -- <target...>
#        (@@ in the target argv is replaced with the input file)

set -u

AFL="$1"; SEED="$2"; CORE="$3"; shift 3
[ "${1:-}" = "--" ] && shift

if [ ! -x "$AFL" ] || [ ! -f "$SEED" ] || [ $# -eq 0 ]; then

  echo "usage: $0 <afl-fuzz> <seed-file> <core> -- <target...>" >&2
  exit 1

fi

SZ=$(stat -c %s "$SEED")
BASE=""

printf '| fraction | bytes | cost_fork_us | share of full |\n'
printf '|---|---|---|---|\n'

for frac in 100 50 25 10; do

  N=$((SZ * frac / 100))
  [ "$N" -lt 1 ] && continue

  IN=$(mktemp -d); OUT=$(mktemp -d); rm -rf "$OUT"
  head -c "$N" "$SEED" > "$IN/s"

  AFL_NO_UI=1 AFL_NO_AFFINITY=1 taskset -c "$CORE" \
    timeout 600 "$AFL" -Jb -V 5 -m none -t 2000 -i "$IN" -o "$OUT" -- "$@" \
    >/dev/null 2>&1

  US=$(awk '/^cost_fork_us/{print $3}' "$OUT/default/fuzzer_stats" 2>/dev/null)
  rm -rf "$IN" "$OUT"

  if [ -z "${US:-}" ]; then

    printf '| %s%% | %s | (no reading) | |\n' "$frac" "$N"
    continue

  fi

  [ -z "$BASE" ] && BASE="$US"
  printf '| %s%% | %s | %s | %s |\n' "$frac" "$N" "$US" \
    "$(awk -v a="$US" -v b="$BASE" 'BEGIN{if(b>0)printf "%.1f%%", a*100/b}')"

done

cat <<'EOF'

Reading: a share that stays near 100% as the fraction falls means the execution
cost is fixed per-execution work, not input-proportional, and prefix replay is
~0% of target time - a §7.3 no-go. A share that falls roughly with the fraction
means prefix replay is real and worth its own measurement.
EOF
