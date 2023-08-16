#!/bin/sh
test -x ../afl-fuzz -a -x ../afl-cc -a -e ../SanitizerCoveragePCGUARD.so || {
  echo Error: you need to compile AFL++ first, we need afl-fuzz, afl-clang-fast and SanitizerCoveragePCGUARD.so built.
  exit 1
}

echo Preparing environment

env | grep AFL_ | sed 's/=.*//' | while read e; do
  unset $e
done

AFL_PATH=`pwd`/..
export PATH=$AFL_PATH:$PATH

AFL_LLVM_INSTRUMENT=PCGUARD afl-cc -o test-instr ../test-instr.c > afl.log 2>&1 || {
  echo Error: afl-cc is unable to compile
  exit 1
}

{
mkdir in
dd if=/dev/zero of=in/in.txt bs=10K count=1
} > /dev/null 2>&1

echo Ready, starting benchmark - this will take approx 20-30 seconds ...

AFL_DISABLE_TRIM=1 AFL_NO_UI=1 AFL_TRY_AFFINITY=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_BENCH_JUST_ONE=1 time afl-fuzz -i in -o out -s 123 -D ./test-instr >> afl.log 2>&1

echo Analysis:

CPUID=$(grep 'try binding to' afl.log | tail -n 1 | sed 's/.*#//' | sed 's/\..*//')
grep 'model name' /proc/cpuinfo | head -n 1 | sed 's/.*:/ CPU:/'
test -n "$CPUID" && grep -E '^processor|^cpu MHz' /proc/cpuinfo | grep -A1 -w "$CPUID" | grep 'cpu MHz' | head -n 1 | sed 's/.*:/ Mhz:/'
test -z "$CPUID" && grep 'cpu MHz' /proc/cpuinfo | head -n 1 | sed 's/.*:/ Mhz:/'
grep execs_per_sec out/default/fuzzer_stats | sed 's/.*:/ execs\/s:/'

echo
echo "Comparison: (note that values can change by 10-15% per run)"
cat COMPARISON

rm -rf in out test-instr afl.log
