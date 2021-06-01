#!/bin/bash

# if you want a specific performance file (e.g. to compare features to another)
# you can set the AFL_PERFORMANCE_FILE environment variable:
FILE=$AFL_PERFORMANCE_FILE
# otherwise we use ~/.afl_performance
test -z "$FILE" && FILE=.afl_performance

test -e $FILE || {
  echo Warning: This script measure the performance of afl++ and saves the result for future comparisons into $FILE
  echo Press ENTER to continue or CONTROL-C to abort
  read IN
}

test -e ./test-performance.sh || { echo Error: this script must be run from the directory in which it lies. ; exit 1 ; }

export AFL_QUIET=1
export AFL_PATH=`pwd`/..

unset AFL_EXIT_WHEN_DONE
unset AFL_EXIT_ON_TIME
unset AFL_SKIP_CPUFREQ
unset AFL_DEBUG
unset AFL_HARDEN
unset AFL_USE_ASAN
unset AFL_USE_MSAN
unset AFL_CC
unset AFL_PRELOAD
unset AFL_GCC_INSTRUMENT_FILE
unset AFL_LLVM_INSTRUMENT_FILE
unset AFL_LLVM_INSTRIM
unset AFL_LLVM_LAF_SPLIT_SWITCHES
unset AFL_LLVM_LAF_TRANSFORM_COMPARES
unset AFL_LLVM_LAF_SPLIT_COMPARES

# on OpenBSD we need to work with llvm from /usr/local/bin
test -e /usr/local/bin/opt && {
  export PATH=/usr/local/bin:${PATH}
} 
# on MacOS X we prefer afl-clang over afl-gcc, because
# afl-gcc does not work there
test `uname -s` = 'Darwin' -o `uname -s` = 'FreeBSD' && {
  AFL_GCC=afl-clang
  CC=clang
} || {
  AFL_GCC=afl-gcc
  CC=gcc
}

ECHO="printf %b\\n"
$ECHO \\101 2>&1 | grep -qE '^A' || {
  ECHO=
  test -e /bin/printf && {
    ECHO="/bin/printf %b\\n"
    $ECHO '\\101' 2>&1 | grep -qE '^A' || ECHO=
  }
}
test -z "$ECHO" && { printf Error: printf command does not support octal character codes ; exit 1 ; }

GREY="\\033[1;90m"
BLUE="\\033[1;94m"
GREEN="\\033[0;32m"
RED="\\033[0;31m"
YELLOW="\\033[1;93m"
RESET="\\033[0m"

MEM_LIMIT=500

touch $FILE || { echo Error: can not write to $FILE ; exit 1 ; }

echo Warning: this script is setting performance parameters with afl-system-config
sleep 1
afl-system-config > /dev/null 2>&1
echo Performance settings applied.
echo

$ECHO "${RESET}${GREY}[*] starting afl++ performance test framework ..."

$ECHO "$BLUE[*] Testing: ${AFL_GCC}"
GCC=x
test -e ../${AFL_GCC} -a -e ../afl-fuzz && {
  ../${AFL_GCC} -o test-instr.plain ../test-instr.c > /dev/null 2>&1
  test -e test-instr.plain && {
    $ECHO "$GREEN[+] ${AFL_GCC} compilation succeeded"
    mkdir -p in
    echo 0 > in/in
    $ECHO "$GREY[*] running afl-fuzz for ${AFL_GCC} for 30 seconds"
    {
      ../afl-fuzz -V 30 -s 123 -m ${MEM_LIMIT} -i in -o out-gcc -- ./test-instr.plain
    } >>errors 2>&1
    test -n "$( ls out-gcc/default/queue/id:000002* 2> /dev/null )" && {
      GCC=`grep execs_done out-gcc/default/fuzzer_stats | awk '{print$3}'`
    } || {
        echo CUT----------------------------------------------------------------
        cat errors
        echo CUT----------------------------------------------------------------
      $ECHO "$RED[!] afl-fuzz is not working correctly with ${AFL_GCC}"
    }
    rm -rf in out-gcc errors test-instr.plain
  } || $ECHO "$RED[!] ${AFL_GCC} instrumentation failed"
} || $ECHO "$YELLOW[-] afl is not compiled, cannot test"

$ECHO "$BLUE[*] Testing: llvm_mode"
LLVM=x
test -e ../afl-clang-fast -a -e ../afl-fuzz && {
  ../afl-clang-fast -o test-instr.llvm ../test-instr.c > /dev/null 2>&1
  test -e test-instr.llvm && {
    $ECHO "$GREEN[+] llvm_mode compilation succeeded"
    mkdir -p in
    echo 0 > in/in
    $ECHO "$GREY[*] running afl-fuzz for llvm_mode for 30 seconds"
    {
      ../afl-fuzz -V 30 -s 123 -m ${MEM_LIMIT} -i in -o out-llvm -- ./test-instr.llvm
    } >>errors 2>&1
    test -n "$( ls out-llvm/default/queue/id:000002* 2> /dev/null )" && {
      LLVM=`grep execs_done out-llvm/default/fuzzer_stats | awk '{print$3}'`
    } || {
        echo CUT----------------------------------------------------------------
        cat errors
        echo CUT----------------------------------------------------------------
      $ECHO "$RED[!] afl-fuzz is not working correctly with llvm_mode"
    }
    rm -rf in out-llvm errors test-instr.llvm
  } || $ECHO "$RED[!] llvm_mode instrumentation failed"
} || $ECHO "$YELLOW[-] llvm_mode is not compiled, cannot test"

$ECHO "$BLUE[*] Testing: gcc_plugin"
GCCP=x
test -e ../afl-gcc-fast -a -e ../afl-fuzz && {
  ../afl-gcc-fast -o test-instr.gccp ../test-instr.c > /dev/null 2>&1
  test -e test-instr.gccp && {
    $ECHO "$GREEN[+] gcc_plugin compilation succeeded"
    mkdir -p in
    echo 0 > in/in
    $ECHO "$GREY[*] running afl-fuzz for gcc_plugin for 30 seconds"
    {
      ../afl-fuzz -V 30 -s 123 -m ${MEM_LIMIT} -i in -o out-gccp -- ./test-instr.gccp
    } >>errors 2>&1
    test -n "$( ls out-gccp/default/queue/id:000002* 2> /dev/null )" && {
      GCCP=`grep execs_done out-gccp/default/fuzzer_stats | awk '{print$3}'`
    } || {
        echo CUT----------------------------------------------------------------
        cat errors
        echo CUT----------------------------------------------------------------
      $ECHO "$RED[!] afl-fuzz is not working correctly with gcc_plugin"
    }
    rm -rf in out-gccp errors test-instr.gccp
  } || $ECHO "$RED[!] gcc_plugin instrumentation failed"
} || $ECHO "$YELLOW[-] gcc_plugin is not compiled, cannot test"

$ECHO "$BLUE[*] Testing: qemu_mode"
QEMU=x
test -e ../afl-qemu-trace -a -e ../afl-fuzz && {
  $CC -o test-instr.qemu ../test-instr.c > /dev/null 2>&1
  test -e test-instr.qemu && {
    $ECHO "$GREEN[+] native compilation with cc succeeded"
    mkdir -p in
    echo 0 > in/in
    $ECHO "$GREY[*] running afl-fuzz for qemu_mode for 30 seconds"
    {
      ../afl-fuzz -Q -V 30 -s 123 -m ${MEM_LIMIT} -i in -o out-qemu -- ./test-instr.qemu
    } >>errors 2>&1
    test -n "$( ls out-qemu/default/queue/id:000002* 2> /dev/null )" && {
      QEMU=`grep execs_done out-qemu/default/fuzzer_stats | awk '{print$3}'`
    } || {
        echo CUT----------------------------------------------------------------
        echo ../afl-fuzz -Q -V 30 -s 123 -m ${MEM_LIMIT} -i in -o out-qemu -- ./test-instr.qemu
        cat errors
        echo CUT----------------------------------------------------------------
      $ECHO "$RED[!] afl-fuzz is not working correctly with qemu_mode"
    }
    rm -rf in out-qemu errors test-instr.qemu
  } || $ECHO "$RED[!] qemu_mode instrumentation failed"
} || $ECHO "$YELLOW[-] qemu_mode is not compiled, cannot test"

LOW_GCC=
HIGH_GCC=
LAST_GCC=
LOW_LLVM=
HIGH_LLVM=
LAST_LLVM=
LOW_GCCP=
HIGH_GCCP=
LAST_GCCP=
LOW_QEMU=
HIGH_QEMU=
LAST_QEMU=

test -s $FILE && {
  while read LINE; do
    G=`echo $LINE | awk '{print$1}'`
    L=`echo $LINE | awk '{print$2}'`
    P=`echo $LINE | awk '{print$3}'`
    Q=`echo $LINE | awk '{print$4}'`
    test "$G" = x && G=
    test "$L" = x && L=
    test "$P" = x && P=
    test "$Q" = x && Q=
    test -n "$G" && LAST_GCC=$G
    test -n "$L" && LAST_LLVM=$L
    test -n "$P" && LAST_GCCP=$P
    test -n "$Q" && LAST_QEMU=$Q
    test -n "$G" -a -z "$LOW_GCC" && LOW_GCC=$G || {
      test -n "$G" -a "$G" -lt "$LOW_GCC" 2> /dev/null && LOW_GCC=$G
    }
    test -n "$L" -a -z "$LOW_LLVM" && LOW_LLVM=$L || {
      test -n "$L" -a "$L" -lt "$LOW_LLVM" 2> /dev/null && LOW_LLVM=$L
    }
    test -n "$P" -a -z "$LOW_GCCP" && LOW_GCCP=$P || {
      test -n "$P" -a "$P" -lt "$LOW_GCCP" 2> /dev/null && LOW_GCCP=$P
    }
    test -n "$Q" -a -z "$LOW_QEMU" && LOW_QEMU=$Q || {
      test -n "$Q" -a "$Q" -lt "$LOW_QEMU" 2> /dev/null && LOW_QEMU=$Q
    }   
    test -n "$G" -a -z "$HIGH_GCC" && HIGH_GCC=$G || {
      test -n "$G" -a "$G" -gt "$HIGH_GCC" 2> /dev/null && HIGH_GCC=$G
    }
    test -n "$L" -a -z "$HIGH_LLVM" && HIGH_LLVM=$L || {
      test -n "$L" -a "$L" -gt "$HIGH_LLVM" 2> /dev/null && HIGH_LLVM=$L
    }
    test -n "$P" -a -z "$HIGH_GCCP" && HIGH_GCCP=$P || {
      test -n "$P" -a "$P" -gt "$HIGH_GCCP" 2> /dev/null && HIGH_GCCP=$P
    }
    test -n "$Q" -a -z "$HIGH_QEMU" && HIGH_QEMU=$Q || {
      test -n "$Q" -a "$Q" -gt "$HIGH_QEMU" 2> /dev/null && HIGH_QEMU=$Q
    }
  done < $FILE
  $ECHO "$YELLOW[!] Reading saved data from $FILE completed, please compare the results:"
  $ECHO "$BLUE[!] afl-cc: lowest=$LOW_GCC highest=$HIGH_GCC last=$LAST_GCC current=$GCC"
  $ECHO "$BLUE[!] llvm_mode: lowest=$LOW_LLVM highest=$HIGH_LLVM last=$LAST_LLVM current=$LLVM"
  $ECHO "$BLUE[!] gcc_plugin: lowest=$LOW_GCCP highest=$HIGH_GCCP last=$LAST_GCCP current=$GCCP"
  $ECHO "$BLUE[!] qemu_mode: lowest=$LOW_QEMU highest=$HIGH_QEMU last=$LAST_QEMU current=$QEMU"
} || {
  $ECHO "$YELLOW[!] First run, just saving data"
  $ECHO "$BLUE[!] afl-gcc=$GCC  llvm_mode=$LLVM  gcc_plugin=$GCCP  qemu_mode=$QEMU"
}
echo "$GCC $LLVM $GCCP $QEMU" >> $FILE
$ECHO "$GREY[*] done."
$ECHO "$RESET"
