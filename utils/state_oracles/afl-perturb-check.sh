#!/bin/sh
#
# american fuzzy lop++ - uninitialised-memory probe
# -------------------------------------------------
#
# Written by Marc Heuse <mh@mh-sec.de>
#
# Copyright 2019-2026 AFLplusplus Project. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#   https://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0
#
# Runs one target on one input at four different heap-perturbation settings
# and diffs the outputs. Any difference means the output depends on
# uninitialised heap.
#
# glibc offers MALLOC_PERTURB_, a byte value written into freed and freshly
# allocated chunks. macOS libmalloc has no equivalent knob; it offers
# MallocScribble (0x55 into freed memory) and MallocPreScribble (0xaa into
# fresh allocations), which are on/off rather than a byte, so there the sweep
# runs over the four on/off combinations instead.
#
#   afl-perturb-check.sh ./target input            input on stdin
#   afl-perturb-check.sh ./target input -f @@      @@ is the input path
#
# Exit codes:
#   0  all four runs produced identical output
#   1  the output depends on uninitialised heap
#   2  usage error, or the target could not be run

set -u

case `uname -s` in

  Darwin)
    PERTURB_VALUES="none scribble prescribble both"
    ;;
  *)
    PERTURB_VALUES="0 42 170 255"
    ;;

esac

# Echoes the environment assignments for one point of the sweep. Unquoted at
# the call site on purpose: the result is a list of assignments for env(1).

perturb_env() {

  case "$1" in
    none)        echo "" ;;
    scribble)    echo "MallocScribble=1" ;;
    prescribble) echo "MallocPreScribble=1" ;;
    both)        echo "MallocScribble=1 MallocPreScribble=1" ;;
    *)           echo "MALLOC_PERTURB_=$1" ;;
  esac

}

usage() {

  echo "usage: $0 <target> <input> [args ...]" >&2
  echo "       @@ in args is replaced by the input path; without @@ the" >&2
  echo "       input is fed on stdin" >&2
  exit 2

}

test $# -ge 2 || usage

TARGET="$1"
INPUT="$2"
shift 2

test -x "$TARGET" || { echo "[-] not executable: $TARGET" >&2; exit 2; }
test -r "$INPUT" || { echo "[-] not readable: $INPUT" >&2; exit 2; }

WORK=`mktemp -d "${TMPDIR:-/tmp}/afl-perturb.XXXXXX"` || exit 2
trap 'rm -rf "$WORK"' EXIT INT TERM

USE_STDIN=1
ARGS=""
for a in "$@"; do
  if [ "$a" = "@@" ]; then
    USE_STDIN=0
    ARGS="$ARGS $INPUT"
  else
    ARGS="$ARGS $a"
  fi
done

for p in $PERTURB_VALUES; do

  if [ "$USE_STDIN" = 1 ]; then
    env `perturb_env "$p"` "$TARGET" $ARGS <"$INPUT" >"$WORK/out.$p" 2>&1
  else
    env `perturb_env "$p"` "$TARGET" $ARGS >"$WORK/out.$p" 2>&1
  fi

  echo "$?" >"$WORK/rc.$p"

done

FIRST=""
STATUS=0

for p in $PERTURB_VALUES; do

  if [ -z "$FIRST" ]; then
    FIRST="$p"
    continue
  fi

  if ! cmp -s "$WORK/out.$FIRST" "$WORK/out.$p"; then
    echo "[-] output differs between perturbation $FIRST and $p" >&2
    diff "$WORK/out.$FIRST" "$WORK/out.$p" >&2 || true
    STATUS=1
  fi

  if [ "`cat "$WORK/rc.$FIRST"`" != "`cat "$WORK/rc.$p"`" ]; then
    echo "[-] exit status differs between perturbation $FIRST ("`cat "$WORK/rc.$FIRST"`") and $p ("`cat "$WORK/rc.$p"`")" >&2
    STATUS=1
  fi

done

if [ "$STATUS" = 0 ]; then
  echo "[+] identical across perturbation settings: $PERTURB_VALUES"
else
  echo "[-] the output of $TARGET depends on uninitialised heap" >&2
fi

exit $STATUS
