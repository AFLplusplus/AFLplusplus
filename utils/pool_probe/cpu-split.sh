#!/bin/bash
# Per-instance CPU accounting: how much CPU the arm actually got, and how it
# split between fuzzer-side and target-side work. Reads the whole process tree
# so that both live and already-reaped descendants are counted.
#
# This is the comparison to make between two arms, not execs_done: more
# executions can mean less fuzzer-side overhead or cheaper inputs, and those have
# opposite implications. Check first that total CPU is equal between the arms;
# if it is not, they did not get the same machine.
#
# usage: cpu-split.sh [output-dir prefix]     (default /tmp/pool-p0)

PREFIX="${1:-/tmp/pool-p0}"
HZ=$(getconf CLK_TCK)
descend() {  # echo pid and all descendants
  echo "$1"
  for c in $(cat /proc/$1/task/$1/children 2>/dev/null); do descend "$c"; done
}
printf "%-24s %6s %9s %9s %9s %9s %11s\n" instance wall own_s child_s total_s util%% cpu_us_exec
for p in $(pgrep -x afl-fuzz); do
  # which output dir is this
  O=$(tr "\0" "\n" < /proc/$p/cmdline 2>/dev/null \
        | awk '$0 == "-o" { getline; print; exit }')
  case "$O" in "${PREFIX}"*) ;; *) continue ;; esac
  [ -z "$O" ] && continue
  B=$(basename "$O")
  # afl-fuzz own CPU
  read -r -a F < <(cut -d" " -f14-17 /proc/$p/stat 2>/dev/null)
  OWN=$(( ${F[0]:-0} + ${F[1]:-0} ))
  REAPED=$(( ${F[2]:-0} + ${F[3]:-0} ))
  # descendants (the forkserver and anything it holds)
  KIDS=0
  for d in $(descend "$p" | tail -n +2); do
    read -r -a G < <(cut -d" " -f14-17 /proc/$d/stat 2>/dev/null)
    KIDS=$(( KIDS + ${G[0]:-0} + ${G[1]:-0} + ${G[2]:-0} + ${G[3]:-0} ))
  done
  CHILD=$(( REAPED + KIDS ))
  TOT=$(( OWN + CHILD ))
  WALL=$(awk "/^run_time /{print \$3}" "$O/default/fuzzer_stats" 2>/dev/null)
  EX=$(awk "/^execs_done /{print \$3}" "$O/default/fuzzer_stats" 2>/dev/null)
  [ -z "$WALL" ] && continue
  printf "%-24s %6s %9.1f %9.1f %9.1f %9.1f %11.2f\n" "$B" "$WALL" \
    "$(echo "$OWN $HZ" | awk "{print \$1/\$2}")" \
    "$(echo "$CHILD $HZ" | awk "{print \$1/\$2}")" \
    "$(echo "$TOT $HZ" | awk "{print \$1/\$2}")" \
    "$(echo "$TOT $HZ $WALL" | awk "{print \$1/\$2*100/\$3}")" \
    "$(echo "$TOT $HZ $EX" | awk "{if(\$3>0) print \$1/\$2*1000000/\$3; else print 0}")"
done
