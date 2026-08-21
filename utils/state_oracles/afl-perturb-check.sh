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
# Runs one target on one input at four different MALLOC_PERTURB_ values and
# diffs the outputs. Any difference means the output depends on uninitialised
# heap.
#
#   afl-perturb-check.sh ./target input            input on stdin
#   afl-perturb-check.sh ./target input -f @@      @@ is the input path
#
# Exit codes:
#   0  all four runs produced identical output
#   1  the output depends on uninitialised heap
#   2  usage error, or the target could not be run

set -u

PERTURB_VALUES="0 42 170 255"

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
    MALLOC_PERTURB_=$p "$TARGET" $ARGS <"$INPUT" >"$WORK/out.$p" 2>&1
  else
    MALLOC_PERTURB_=$p "$TARGET" $ARGS >"$WORK/out.$p" 2>&1
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
    echo "[-] output differs between MALLOC_PERTURB_=$FIRST and $p" >&2
    diff "$WORK/out.$FIRST" "$WORK/out.$p" >&2 || true
    STATUS=1
  fi

  if [ "`cat "$WORK/rc.$FIRST"`" != "`cat "$WORK/rc.$p"`" ]; then
    echo "[-] exit status differs between MALLOC_PERTURB_=$FIRST ("`cat "$WORK/rc.$FIRST"`") and $p ("`cat "$WORK/rc.$p"`")" >&2
    STATUS=1
  fi

done

if [ "$STATUS" = 0 ]; then
  echo "[+] identical across MALLOC_PERTURB_ = $PERTURB_VALUES"
else
  echo "[-] the output of $TARGET depends on uninitialised heap" >&2
fi

exit $STATUS
