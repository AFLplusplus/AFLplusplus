#!/bin/sh
CMDLINE="/prg/tests/normal/tiff-4.0.4/tools/thumbnail @@ /dev/null"
INDIR="/prg/tests/normal/tiff-4.0.4/in-small"

test -z "$1" -o -n "$4" && { 
  echo "Syntax: $0 commit-id <indir> \"<cmdline>\""
  echo
  echo "Switches to the defined commit ID, compiles with profiling and runs"
  echo "afl-fuzz on a defind target and input directory, saving timing,"
  echo "fuzzer_stats and profiling output to \"<commit-id>.out\""
  echo "Honors CFLAGS and LDFLAGS"
  echo
  echo "Defaults:"
  echo "  indir: \"$INDIR\""
  echo "  cmdline: \"$CMDLINE\""
  exit 1
}

C=$1
test -n "$2" && INDIR=$2
test -n "$3" && CMDLINE=$3

git checkout "$C" || { echo "CHECKOUT FAIL $C" > $C.out ; exit 1 ; }
export AFL_BENCH_JUST_ONE=1
test -z "$CFLAGS" && CFLAGS="-O3 -funroll-loops"
export CFLAGS="$CFLAGS -pg"
export LDFLAGS="$LDFLAGS -pg"
make >/dev/null 2>&1 || echo ERROR: BUILD FAILURE 
test -x ./afl-fuzz || { echo "BUILD FAIL $C" > $C.out ; make clean ; exit 1 ; }

START=`date +%s`
echo $START > $C.out
time nice -n -20 ./afl-fuzz -i "$INDIR" -s 123 -o out-profile -- $CMDLINE 2>> $C.out
STOP=`date +%s`
echo $STOP >> $C.out
echo RUNTIME: `expr $STOP - $START` >> $C.out
cat out-profile/default/fuzzer_stats >> $C.out
gprof ./afl-fuzz gmon.out >> $C.out

make clean >/dev/null 2>&1
rm -rf out-profile gmon.out
