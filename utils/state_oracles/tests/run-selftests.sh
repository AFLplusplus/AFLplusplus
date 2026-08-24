#!/bin/sh
#
# american fuzzy lop++ - oracle self-tests
# ----------------------------------------
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
# Asserts that every detector fires on its deliberately broken example and
# stays quiet on the matching correct one. Run it from utils/state_oracles,
# or through "make selftest". Exits 0 when all four detectors behave.

set -u

HERE=`dirname "$0"`
cd "$HERE/.." || exit 2

FAIL=0

ok() { echo "[+] $1"; }
no() { echo "[-] $1" >&2; FAIL=1; }

# Two things are spelled differently outside Linux. The preload variable is
# LD_PRELOAD for ELF and DYLD_INSERT_LIBRARIES for dyld. And a write into a
# guard page comes back as SIGSEGV (rc 139) on Linux but as SIGBUS on Darwin,
# where SIGBUS is signal 10 and so rc 138; both mean the guard page did its
# job, and nothing else does.

case `uname -s` in

  Darwin)
    PRELOAD_VAR=DYLD_INSERT_LIBRARIES
    FAULT_RCS="139 138"
    ;;
  *)
    PRELOAD_VAR=LD_PRELOAD
    FAULT_RCS="139"
    ;;

esac

is_fault() {

  for want in $FAULT_RCS; do

    test "$1" = "$want" && return 0

  done

  return 1

}

# --- 1. round-trip oracle: the broken loader must abort ---

rc=`./tests/roundtrip_bad >/dev/null 2>&1; echo $?`
test "$rc" = 134 && ok "round-trip oracle fires on roundtrip_bad (SIGABRT)" \
                 || no "round-trip oracle did NOT fire on roundtrip_bad (rc=$rc, expected 134)"

rc=`./tests/roundtrip_good >/dev/null 2>&1; echo $?`
test "$rc" = 0 && ok "round-trip oracle quiet on roundtrip_good" \
               || no "round-trip oracle fired on roundtrip_good (rc=$rc, expected 0)"

# --- 2. exact-size buffers: the one-byte overrun must fault ---

rc=`./tests/exactbuf_bad >/dev/null 2>&1; echo $?`
is_fault "$rc" && ok "guard page fires on exactbuf_bad (rc=$rc)" \
                || no "guard page did NOT fire on exactbuf_bad (rc=$rc, expected one of $FAULT_RCS)"

rc=`./tests/exactbuf_good >/dev/null 2>&1; echo $?`
test "$rc" = 0 && ok "guard page quiet on exactbuf_good" \
               || no "guard page fired on exactbuf_good (rc=$rc, expected 0)"

# --- 3. allocation-failure injection ---
# N is swept because the first allocations of a process belong to libc
# startup, not to the program. The broken example must die for at least one
# N; the correct one must survive every N.

hit=0
n=1
while [ "$n" -le 20 ]; do

  rc=`AFL_ALLOCFAIL_N=$n env "$PRELOAD_VAR=./afl_allocfail.so" ./tests/allocfail_bad >/dev/null 2>&1; echo $?`
  test "$rc" -ge 128 && hit=1
  n=`expr $n + 1`

done

test "$hit" = 1 && ok "allocation-failure injection fires on allocfail_bad" \
                || no "allocation-failure injection did NOT fire on allocfail_bad for any N in 1..20"

bad=0
n=1
while [ "$n" -le 20 ]; do

  rc=`AFL_ALLOCFAIL_N=$n env "$PRELOAD_VAR=./afl_allocfail.so" ./tests/allocfail_good >/dev/null 2>&1; echo $?`
  test "$rc" = 0 || bad=1
  n=`expr $n + 1`

done

test "$bad" = 0 && ok "allocation-failure injection quiet on allocfail_good" \
                || no "allocfail_good did not survive every N in 1..20"

# --- 4. uninitialised-memory probe ---

INPUT=`mktemp "${TMPDIR:-/tmp}/afl-oracle-input.XXXXXX"` || exit 2
trap 'rm -f "$INPUT"' EXIT INT TERM
printf 'x' >"$INPUT"

./afl-perturb-check.sh ./tests/perturb_bad "$INPUT" >/dev/null 2>&1
rc=$?
test "$rc" = 1 && ok "perturb probe fires on perturb_bad" \
               || no "perturb probe did NOT fire on perturb_bad (rc=$rc, expected 1)"

./afl-perturb-check.sh ./tests/perturb_good "$INPUT" >/dev/null 2>&1
rc=$?
test "$rc" = 0 && ok "perturb probe quiet on perturb_good" \
               || no "perturb probe fired on perturb_good (rc=$rc, expected 0)"

if [ "$FAIL" = 0 ]; then
  echo "[+] all four detectors were seen to fire and to stay quiet"
else
  echo "[-] oracle self-tests FAILED" >&2
fi

exit $FAIL
