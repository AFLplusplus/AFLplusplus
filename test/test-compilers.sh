#!/bin/sh
echo Testing compilers ...
for cc in afl-cc afl-gcc afl-clang afl-clang-fast afl-clang-lto afl-gcc-fast; do
  test -e ../$cc && { { ../$cc -o t ../test-instr.c >/dev/null 2<&1 && echo Success: $cc ; } || echo Failing: $cc ; } || echo Missing: $cc
done
rm -f t
echo Done!
