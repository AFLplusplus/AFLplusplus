#!/bin/sh
echo "[*] Testing compilers ..."
ERR=
for cc in afl-cc afl-clang-fast afl-clang-lto afl-gcc-fast; do
  test -e ../$cc && { { ../$cc -o t ../test-instr.c >/dev/null 2<&1 && echo "[*] Success: $cc" ; } || { ERR=1; echo "[*] Failing: $cc"; } ; } || { echo "[*] Missing: $cc"; }
done
rm -f t
echo [*] Done!
test "$ERR" = 1 && exit 1
exit 0
