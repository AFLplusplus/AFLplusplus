#!/bin/sh

. ./test-pre.sh

OS=$(uname -s)

AFL_COMPILER=afl-clang-fast
$ECHO "$BLUE[*] Testing: ${AFL_COMPILER}, afl-showmap, afl-fuzz, afl-cmin and afl-tmin"
 test -e ../${AFL_COMPILER} -a -e ../afl-showmap -a -e ../afl-fuzz && {
   ../${AFL_COMPILER} -o test-instr.plain -O0 ../test-instr.c > /dev/null 2>&1
   AFL_HARDEN=1 ../${AFL_COMPILER} -o test-compcov.harden test-compcov.c > /dev/null 2>&1
   test -e test-instr.plain && {
    $ECHO "$GREEN[+] ${AFL_COMPILER} compilation succeeded"
    echo 0 | AFL_QUIET=1 ../afl-showmap -m ${MEM_LIMIT} -o test-instr.plain.0 -r -- ./test-instr.plain > /dev/null 2>&1
    AFL_QUIET=1 ../afl-showmap -m ${MEM_LIMIT} -o test-instr.plain.1 -r -- ./test-instr.plain < /dev/null > /dev/null 2>&1
    test -e test-instr.plain.0 -a -e test-instr.plain.1 && {
      diff test-instr.plain.0 test-instr.plain.1 > /dev/null 2>&1 && {
        $ECHO "$RED[!] ${AFL_COMPILER} instrumentation should be different on different input but is not"
        CODE=1
      } || {
        $ECHO "$GREEN[+] ${AFL_COMPILER} instrumentation present and working correctly"
      }
    } || {
      $ECHO "$RED[!] ${AFL_COMPILER} instrumentation failed"
      CODE=1
    }
    rm -f test-instr.plain.0 test-instr.plain.1
    SKIP=
    TUPLES=`echo 1|AFL_QUIET=1 ../afl-showmap -m ${MEM_LIMIT} -o /dev/null -- ./test-instr.plain 2>&1 | grep Captur | awk '{print$3}'`
    test "$TUPLES" -gt 1 -a "$TUPLES" -lt 22 && {
      $ECHO "$GREEN[+] ${AFL_COMPILER} run reported $TUPLES instrumented locations which is fine"
    } || {
      $ECHO "$RED[!] ${AFL_COMPILER} instrumentation produces weird numbers: $TUPLES"
      CODE=1
    }
    test "$TUPLES" -lt 3 && SKIP=1
    true  # this is needed because of the test above
   } || {
    $ECHO "$RED[!] ${AFL_COMPILER} failed"
    echo CUT------------------------------------------------------------------CUT
    uname -a
    ../${AFL_COMPILER} -o test-instr.plain -O0 ../test-instr.c
    echo CUT------------------------------------------------------------------CUT
    CODE=1
   }
   test -e test-compcov.harden && {
    nm test-compcov.harden | grep -Eq 'stack_chk_fail|fstack-protector-all|fortified' > /dev/null 2>&1 && {
      $ECHO "$GREEN[+] ${AFL_COMPILER} hardened mode succeeded and is working"
    } || {
      $ECHO "$RED[!] ${AFL_COMPILER} hardened mode is not hardened"
      env | grep -E 'AFL|PATH|LLVM'
      AFL_DEBUG=1 AFL_HARDEN=1 ../${AFL_COMPILER} -o test-compcov.harden test-compcov.c
      nm test-compcov.harden
      CODE=1
    }
    rm -f test-compcov.harden
   } || {
    $ECHO "$RED[!] ${AFL_COMPILER} hardened mode compilation failed"
    CODE=1
   }
   # now we want to be sure that afl-fuzz is working
   # make sure crash reporter is disabled on Mac OS X
   (test "$OS" = "Darwin" && test $(launchctl list 2>/dev/null | grep -q '\.ReportCrash$') && {
    $ECHO "$RED[!] we cannot run afl-fuzz with enabled crash reporter. Run 'sudo sh afl-system-config'.$RESET"
    true
   }) || {
    mkdir -p in
    echo 0 > in/in
    test -z "$SKIP" && {
      $ECHO "$GREY[*] running afl-fuzz for ${AFL_COMPILER}, this will take approx 10 seconds"
      {
        ../afl-fuzz -V07 -m ${MEM_LIMIT} -i in -o out -- ./test-instr.plain >>errors 2>&1
      } >>errors 2>&1
      test -n "$( ls out/default/queue/id:000002* 2>/dev/null )" && {
        $ECHO "$GREEN[+] afl-fuzz is working correctly with ${AFL_COMPILER}"
      } || {
        echo CUT------------------------------------------------------------------CUT
        cat errors
        echo CUT------------------------------------------------------------------CUT
        $ECHO "$RED[!] afl-fuzz is not working correctly with ${AFL_COMPILER}"
        CODE=1
      }
    }
    echo 000000000000000000000000 > in/in2
    echo 111 > in/in3
    test "$OS" = "Darwin" && {
      $ECHO "$GREY[*] afl-cmin not available on macOS, cannot test afl-cmin"
    } || {
      mkdir -p in2
      ../afl-cmin -m ${MEM_LIMIT} -i in -o in2 -- ./test-instr.plain >/dev/null 2>&1 # why is afl-forkserver writing to stderr?
      CNT=`ls in2/* 2>/dev/null | wc -l`
      case "$CNT" in
        *2) $ECHO "$GREEN[+] afl-cmin correctly minimized the number of testcases" ;;
        *)  $ECHO "$RED[!] afl-cmin did not correctly minimize the number of testcases ($CNT)"
            CODE=1
            ;;
      esac
      rm -f in2/in*
    }
    export AFL_QUIET=1
    if command -v bash >/dev/null ; then {
      ../afl-cmin.bash -m ${MEM_LIMIT} -i in -o in2 -- ./test-instr.plain >/dev/null
      CNT=`ls in2/* 2>/dev/null | wc -l`
      case "$CNT" in
        *2) $ECHO "$GREEN[+] afl-cmin.bash correctly minimized the number of testcases" ;;
        *)  $ECHO "$RED[!] afl-cmin.bash did not correctly minimize the number of testcases ($CNT)"
            CODE=1
            ;;
        esac
    } else {
      $ECHO "$GREY[*] no bash available, cannot test afl-cmin.bash"
    }
    fi
    ../afl-tmin -m ${MEM_LIMIT} -i in/in2 -o in2/in2 -- ./test-instr.plain > /dev/null 2>&1
    SIZE=`ls -l in2/in2 2>/dev/null | awk '{print$5}'`
    test "$SIZE" = 1 && $ECHO "$GREEN[+] afl-tmin correctly minimized the testcase"
    test "$SIZE" = 1 || {
       $ECHO "$RED[!] afl-tmin did incorrectly minimize the testcase to $SIZE"
       CODE=1
    }
    rm -rf in out errors in2
    unset AFL_QUIET
   }
   rm -f test-instr.plain
 } || {
   $ECHO "$YELLOW[-] afl is not compiled, cannot test"
   INCOMPLETE=1
 }

. ./test-post.sh
