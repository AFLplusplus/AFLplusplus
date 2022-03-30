#!/bin/sh

. ./test-pre.sh

$ECHO "$BLUE[*] Testing: LTO llvm_mode"
test -e ../afl-clang-lto -a -e ../SanitizerCoverageLTO.so && {
  # on FreeBSD need to set AFL_CC
  test `uname -s` = 'FreeBSD' && {
    if type clang >/dev/null; then
      export AFL_CC=`command -v clang`
    else
      export AFL_CC=`$LLVM_CONFIG --bindir`/clang
    fi
  }

  ../afl-clang-lto -o test-instr.plain ../test-instr.c > /dev/null 2>&1
  test -e test-instr.plain && {
    $ECHO "$GREEN[+] llvm_mode LTO compilation succeeded"
    echo 0 | AFL_QUIET=1 ../afl-showmap -m ${MEM_LIMIT} -o test-instr.plain.0 -r -- ./test-instr.plain > /dev/null 2>&1
    AFL_QUIET=1 ../afl-showmap -m ${MEM_LIMIT} -o test-instr.plain.1 -r -- ./test-instr.plain < /dev/null > /dev/null 2>&1
    test -e test-instr.plain.0 -a -e test-instr.plain.1 && {
      diff -q test-instr.plain.0 test-instr.plain.1 > /dev/null 2>&1 && {
        $ECHO "$RED[!] llvm_mode LTO instrumentation should be different on different input but is not"
        CODE=1
      } || {
        $ECHO "$GREEN[+] llvm_mode LTO instrumentation present and working correctly"
        TUPLES=`echo 0|AFL_QUIET=1 ../afl-showmap -m ${MEM_LIMIT} -o /dev/null -- ./test-instr.plain 2>&1 | grep Captur | awk '{print$3}'`
        test "$TUPLES" -gt 2 -a "$TUPLES" -lt 7 && {
          $ECHO "$GREEN[+] llvm_mode LTO run reported $TUPLES instrumented locations which is fine"
        } || {
          $ECHO "$RED[!] llvm_mode LTO instrumentation produces weird numbers: $TUPLES"
          CODE=1
        }
      }
    } || {
      $ECHO "$RED[!] llvm_mode LTO instrumentation failed"
      CODE=1
    }
    rm -f test-instr.plain.0 test-instr.plain.1
  } || {
    $ECHO "$RED[!] LTO llvm_mode failed"
    CODE=1
  }
  rm -f test-instr.plain

  echo foobar.c > instrumentlist.txt
  AFL_DEBUG=1 AFL_LLVM_INSTRUMENT_FILE=instrumentlist.txt ../afl-clang-lto -o test-compcov test-compcov.c > test.out 2>&1
  test -e test-compcov && {
    grep -q "No instrumentation targets found" test.out && {
      $ECHO "$GREEN[+] llvm_mode LTO instrumentlist feature works correctly"
    } || {
	echo CUT------------------------------------------------------------------CUT
        cat test.out
        echo CUT------------------------------------------------------------------CUT
      $ECHO "$RED[!] llvm_mode LTO instrumentlist feature failed"
      CODE=1
    }
  } || {
    $ECHO "$RED[!] llvm_mode LTO instrumentlist feature compilation failed"
    CODE=1
  }
  rm -f test-compcov test.out instrumentlist.txt
  ../afl-clang-lto -o test-persistent ../utils/persistent_mode/persistent_demo.c > /dev/null 2>&1
  test -e test-persistent && {
    echo foo | AFL_QUIET=1 ../afl-showmap -m none -o /dev/null -q -r ./test-persistent && {
      $ECHO "$GREEN[+] llvm_mode LTO persistent mode feature works correctly"
    } || {
      $ECHO "$RED[!] llvm_mode LTO persistent mode feature failed to work"
      CODE=1
    }
  } || {
    $ECHO "$RED[!] llvm_mode LTO persistent mode feature compilation failed"
    CODE=1
  }
  rm -f test-persistent
} || {
  $ECHO "$YELLOW[-] LTO llvm_mode not compiled, cannot test"
  INCOMPLETE=1
}

. ./test-post.sh
