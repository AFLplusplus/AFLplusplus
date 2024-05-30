#!/bin/sh

. ./test-pre.sh

test -z "$AFL_CC" && unset AFL_CC

$ECHO "$BLUE[*] Testing: shared library extensions"
cc $CFLAGS -O0 -o test-compcov test-compcov.c > /dev/null 2>&1
test -e ../libtokencap.so && {
  AFL_TOKEN_FILE=token.out LD_PRELOAD=../libtokencap.so DYLD_INSERT_LIBRARIES=../libtokencap.so DYLD_FORCE_FLAT_NAMESPACE=1 ./test-compcov foobar > /dev/null 2>&1
  grep -q BUGMENOT token.out > /dev/null 2>&1 && {
    $ECHO "$GREEN[+] libtokencap did successfully capture tokens"
  } || {
    $ECHO "$RED[!] libtokencap did not capture tokens"
    CODE=1
  }
  rm -f token.out
} || {
  $ECHO "$YELLOW[-] libtokencap is not compiled, cannot test"
  INCOMPLETE=1
}
test -e ../libdislocator.so && {
  {
    ulimit -c 1
    # DYLD_INSERT_LIBRARIES and DYLD_FORCE_FLAT_NAMESPACE is used on Darwin/MacOSX
    LD_PRELOAD=../libdislocator.so DYLD_INSERT_LIBRARIES=../libdislocator.so DYLD_FORCE_FLAT_NAMESPACE=1 ./test-compcov BUFFEROVERFLOW > test.out 2>/dev/null
  } > /dev/null 2>&1
  grep -q BUFFEROVERFLOW test.out > /dev/null 2>&1 && {
    $ECHO "$RED[!] libdislocator did not detect the memory corruption"
    CODE=1
  } || {
    $ECHO "$GREEN[+] libdislocator did successfully detect the memory corruption"
  }
  rm -f test.out core test-compcov.core core.test-compcov
} || {
  $ECHO "$YELLOW[-] libdislocator is not compiled, cannot test"
  INCOMPLETE=1
}
rm -f test-compcov

. ./test-post.sh
