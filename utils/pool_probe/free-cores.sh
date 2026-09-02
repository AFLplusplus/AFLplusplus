#!/bin/sh
#
# free-cores.sh - what a shared fuzzing host has spare, and which CPUs other
# people's campaigns already hold.
#
# Read-only: starts nothing, kills nothing. Run this before launching any
# measurement arm on bigfuzz or fuzzybear.
#
# usage: free-cores.sh [host ...]        (default: bigfuzz fuzzybear)

set -u

HOSTS="${*:-bigfuzz fuzzybear}"

for h in $HOSTS; do

  ssh -o ConnectTimeout=8 -o BatchMode=yes "$h" '
    TOTAL=$(nproc)
    FUZZ=$(pgrep -xc afl-fuzz 2>/dev/null); FUZZ=${FUZZ:-0}
    OCC=$(ps -eo psr,comm --no-headers 2>/dev/null \
          | awk "\$2 ~ /^(afl-fuzz|afl-showmap|afl-tmin|honggfuzz|qemu-system)\$/ {print \$1}" \
          | sort -un)
    NOCC=$(printf "%s\n" "$OCC" | grep -c .)
    FREE=$(printf "%s\n" "$OCC" | grep . | awk -v t="$TOTAL" "
      {busy[\$1]=1}
      END {s=\"\"; for (i=0; i<t; i++) if (!(i in busy)) s = s (s==\"\" ? \"\" : \",\") i; print s}")
    printf "%-11s total=%-3s afl-fuzz=%-3s occupied=%-3s free=%-3s load=%s\n" \
      "$(hostname -s)" "$TOTAL" "$FUZZ" "$NOCC" "$((TOTAL - NOCC))" \
      "$(cut -d" " -f1-3 /proc/loadavg)"
    [ "$NOCC" -gt 0 ] && printf "            occupied: %s\n" \
      "$(printf "%s\n" "$OCC" | tr "\n" "," | sed "s/,$//")"
    printf "            free    : %s\n" "$FREE"
    lscpu | grep -i "^NUMA node[0-9]" | sed "s/^/            /"
  ' || printf "%-11s UNREACHABLE\n" "$h"

done
