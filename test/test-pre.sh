#!/bin/sh

# All tests should start with sourcing test-pre.sh and finish with sourcing test-post.sh
# They may set an error code with $CODE=1
# If tests are incomplete, they may set $INCOMPLETE=1

AFL_TEST_COUNT=$((AFL_TEST_COUNT+1))
AFL_TEST_DEPTH=$((AFL_TEST_DEPTH+1))

if [ $AFL_TEST_DEPTH = 1 ]; then
# First run :)

#
# Ensure we have: test, type, diff, grep -qE
#
test -z "" 2>/dev/null || { echo Error: test command not found ; exit 1 ; }
GREP=`type grep > /dev/null 2>&1 && echo OK`
test "$GREP" = OK || { echo Error: grep command not found ; exit 1 ; }
echo foobar | grep -qE 'asd|oob' 2>/dev/null || { echo Error: grep command does not support -q and/or -E option ; exit 1 ; }
test -e ./test-all.sh || cd $(dirname $0) || exit 1
test -e ./test-all.sh || { echo Error: you must be in the test/ directory ; exit 1 ; }
export AFL_PATH=`pwd`/..
export AFL_NO_AFFINITY=1 # workaround for travis that fails for no avail cores 

echo 1 > test.1
echo 1 > test.2
OK=OK
diff test.1 test.2 >/dev/null 2>&1 || OK=
rm -f test.1 test.2
test -z "$OK" && { echo Error: diff is not working ; exit 1 ; }
test -z "$LLVM_CONFIG" && LLVM_CONFIG=llvm-config

# check for '-a' option of grep
if grep -a test test-all.sh >/dev/null 2>&1; then
  GREPAOPTION=' -a'
else
  GREPAOPTION=
fi

test_compcov_binary_functionality() {
  RUN="../afl-showmap -m ${MEM_LIMIT} -o /dev/null -- $1"
  $RUN 'LIBTOKENCAP' | grep 'your string was LIBTOKENCAP' \
    && $RUN 'BUGMENOT' | grep 'your string was BUGMENOT' \
    && $RUN 'BANANA' | grep 'your string started with BAN' \
    && $RUN 'APRI' | grep 'your string was APRI' \
    && $RUN 'kiWI' | grep 'your string was Kiwi' \
    && $RUN 'Avocado' | grep 'your string was avocado' \
    && $RUN 'GRAX' 3 | grep 'your string was a prefix of Grapes' \
    && $RUN 'LOCALVARIABLE' | grep 'local var memcmp works!' \
    && $RUN 'abc' | grep 'short local var memcmp works!' \
    && $RUN 'GLOBALVARIABLE' | grep 'global var memcmp works!'
} > /dev/null

ECHO="printf %b\\n"
$ECHO \\101 2>&1 | grep -qE '^A' || {
  ECHO=
  test -e /bin/printf && {
    ECHO="/bin/printf %b\\n"
    $ECHO "\\101" 2>&1 | grep -qE '^A' || ECHO=
  }
}
test -z "$ECHO" && { printf Error: printf command does not support octal character codes ; exit 1 ; }

export AFL_EXIT_WHEN_DONE=1
export AFL_EXIT_ON_TIME=60
export AFL_SKIP_CPUFREQ=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
unset AFL_NO_X86
unset AFL_QUIET
unset AFL_DEBUG
unset AFL_HARDEN
unset AFL_USE_ASAN
unset AFL_USE_MSAN
unset AFL_USE_UBSAN
unset AFL_USE_LSAN
unset AFL_TMPDIR
unset AFL_CC
unset AFL_PRELOAD
unset AFL_GCC_INSTRUMENT_FILE
unset AFL_LLVM_INSTRUMENT_FILE
unset AFL_LLVM_INSTRIM
unset AFL_LLVM_LAF_SPLIT_SWITCHES
unset AFL_LLVM_LAF_TRANSFORM_COMPARES
unset AFL_LLVM_LAF_SPLIT_COMPARES
unset AFL_QEMU_PERSISTENT_ADDR
unset AFL_QEMU_PERSISTENT_RETADDR_OFFSET
unset AFL_QEMU_PERSISTENT_GPR
unset AFL_QEMU_PERSISTENT_RET
unset AFL_QEMU_PERSISTENT_HOOK
unset AFL_QEMU_PERSISTENT_CNT
unset AFL_CUSTOM_MUTATOR_LIBRARY
unset AFL_PYTHON_MODULE
unset AFL_PRELOAD
unset LD_PRELOAD
unset SKIP

rm -rf in in2 out

test -z "$TRAVIS_OS_NAME" && {
  export ASAN_OPTIONS=detect_leaks=0:allocator_may_return_null=1:abort_on_error=1:symbolize=0
}
test -n "$TRAVIS_OS_NAME" && {
  export ASAN_OPTIONS=detect_leaks=0:allocator_may_return_null=1:abort_on_error=1:symbolize=1
}

export AFL_LLVM_INSTRUMENT=AFL

# on OpenBSD we need to work with llvm from /usr/local/bin
test -e /usr/local/bin/opt && {
  export PATH="/usr/local/bin:${PATH}"
}
# on MacOS X we prefer afl-clang over afl-gcc, because
# afl-gcc does not work there
test `uname -s` = 'Darwin' -o `uname -s` = 'FreeBSD' && {
  AFL_GCC=afl-clang
} || {
  AFL_GCC=afl-gcc
}
command -v gcc >/dev/null 2>&1 || AFL_GCC=afl-clang

SYS=`uname -m`

GREY="\\033[1;90m"
BLUE="\\033[1;94m"
GREEN="\\033[0;32m"
RED="\\033[0;31m"
YELLOW="\\033[1;93m"
RESET="\\033[0m"

MEM_LIMIT=none

export PATH="${PATH}:/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin"

$ECHO "${RESET}${GREY}[*] starting afl++ test framework ..."

test -z "$SYS" && $ECHO "$YELLOW[-] uname -m did not succeed"

CODE=0
INCOMPLETE=0

fi
