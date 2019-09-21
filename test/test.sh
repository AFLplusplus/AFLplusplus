#!/bin/bash

#
# Ensure we have: test, type, diff -q, echo -e, grep -qE
#
test -z "" 2> /dev/null || { echo Error: test command not found ; exit 1 ; }
GREP=`type grep > /dev/null 2>&1 && echo OK`
test "$GREP" = OK || { echo Error: grep command not found ; exit 1 ; }
echo foobar | grep -aqE 'asd|oob' 2> /dev/null || { echo Error: grep command does not support -q, -a and/or -E option ; exit 1 ; }
echo 1 > test.1
echo 1 > test.2
OK=OK
diff -q test.1 test.2 >/dev/null 2>&1 || OK=
rm -f test.1 test.2
test -z "$OK" && { echo Error: diff -q is not working ; exit 1 ; }

ECHO="echo -e"
$ECHO '\x41' 2>&1 | grep -qE '^A' || {
  ECHO=
  test -e /bin/echo && {
    ECHO="/bin/echo -e"
    $ECHO '\x41' 2>&1 | grep -qE '^A' || ECHO=
  }
}
test -z "$ECHO" && { echo Error: echo command does not support -e option ; exit 1 ; }

GREY="\\x1b[1;90m"
GREEN="\\x1b[0;32m"
RED="\\x1b[0;31m"
YELLOW="\\x1b[1;93m"
RESET="\\x1b[0m"

$ECHO "$RESET"

test -e ../afl-gcc -a -e ../afl-showmap -a -e ../afl-fuzz && {
  ../afl-gcc -o test-instr.plain ../test-instr.c > /dev/null 2>&1
  AFL_HARDEN=1 ../afl-gcc -o test-instr.harden ../test-instr.c > /dev/null 2>&1
  test -e test-instr.plain && {
    $ECHO "$GREEN[*] afl-gcc compilation succeeded"
    echo 0 | ../afl-showmap -o test-instr.plain.0 -r -- ./test-instr.plain > /dev/null 2>&1
    ../afl-showmap -o test-instr.plain.1 -r -- ./test-instr.plain < /dev/null > /dev/null 2>&1
    test -e test-instr.plain.0 -a -e test-instr.plain.1 && {
      diff -q test-instr.plain.0 test-instr.plain.1 > /dev/null 2>&1 && {
        $ECHO "$RED[!] afl-gcc instrumentation should be different on different input but is not"
      } || $ECHO "$GREEN[*] afl-gcc instrumentation present and working correctly"
    } || $ECHO "$RED[!] afl-gcc instrumentation failed"
    rm -f test-instr.plain test-instr.plain.0 test-instr.plain.1
  } || $ECHO "$RED[!] afl-gcc failed"
  test -e test-instr.harden && {
    grep -qa fstack-protector-all test-instr.harden > /dev/null 2>&1 && {
      $ECHO "$GREEN[*] afl-gcc hardened mode succeeded and is working"
    } || $ECHO "$RED[!] hardened mode is not hardened"
    rm -f test-instr.harden
  } || $ECHO "$RED[!] afl-gcc hardened mode compilation failed"
  

} || $ECHO "$YELLOW[-] afl is not compiled, cannot test"

test -e ../afl-clang-fast && {
  echo todo: llvm_mode


} || $ECHO "$YELLOW[-] llvm_mode not compiled, cannot test"

test -e ../libtokencap.so && {
  echo todo: libtokencap

} || $ECHO "$YELLOW[-] libtokencap is not compiled, cannot test"

$ECHO "$RESET"

# libdislocator
# unicorn
# qemu