#!/bin/sh

. ./test-pre.sh

$ECHO "$BLUE[*] Testing: frida_mode"
test -z "$AFL_CC" && {
  if type gcc >/dev/null; then
    export AFL_CC=gcc
  else
    if type clang >/dev/null; then
      export AFL_CC=clang
    fi
  fi
}

test -e ../afl-frida-trace.so && {
  cc -no-pie -o test-instr ../test-instr.c
  cc -o test-compcov test-compcov.c
  test -e test-instr -a -e test-compcov && {
    {
      mkdir -p in
      echo 00000 > in/in
      $ECHO "$GREY[*] running afl-fuzz for frida_mode, this will take approx 10 seconds"
      {
        AFL_DEBUG=1 AFL_FRIDA_VERBOSE=1 ../afl-fuzz -m ${MEM_LIMIT} -V07 -O -i in -o out -- ./test-instr >>errors 2>&1
      } >>errors 2>&1
      test -n "$( ls out/default/queue/id:000002* 2>/dev/null )" && {
        $ECHO "$GREEN[+] afl-fuzz is working correctly with frida_mode"
        RUNTIME=`grep execs_done out/default/fuzzer_stats | awk '{print$3}'`
      } || {
        echo CUT------------------------------------------------------------------CUT
        cat errors
        echo CUT------------------------------------------------------------------CUT
        $ECHO "$RED[!] afl-fuzz is not working correctly with frida_mode"
        CODE=1
      }
      rm -f errors

      test "$SYS" = "i686" -o "$SYS" = "x86_64" -o "$SYS" = "amd64" -o "$SYS" = "i86pc" -o "$SYS" = "aarch64" -o ! "${SYS%%arm*}" && {
        $ECHO "$GREY[*] running afl-fuzz for frida_mode cmplog, this will take approx 10 seconds"
        {
          ../afl-fuzz -m none -V07 -O -c 0 -l 3 -i in -o out -- ./test-compcov >>errors 2>&1
        } >>errors 2>&1
        test -n "$( ls out/default/queue/id:000003* 2>/dev/null )" && {
          $ECHO "$GREEN[+] afl-fuzz is working correctly with frida_mode cmplog"
        } || {
          echo CUT------------------------------------------------------------------CUT
          cat errors
          echo CUT------------------------------------------------------------------CUT
          $ECHO "$RED[!] afl-fuzz is not working correctly with frida_mode cmplog"
          CODE=1
        }
        rm -f errors
      } || {
       $ECHO "$YELLOW[-] not an intel or arm platform, cannot test frida_mode cmplog"
      }

      test "$SYS" = "i686" -o "$SYS" = "x86_64" -o "$SYS" = "amd64" -o "$SYS" = "i86pc" -o "$SYS" = "aarch64" -o ! "${SYS%%arm*}" && {
        $ECHO "$GREY[*] running afl-fuzz for persistent frida_mode, this will take approx 10 seconds"
        {
          #if file test-instr | grep -q "32-bit"; then
          #else
          #fi
          export AFL_FRIDA_PERSISTENT_ADDR=0x`nm test-instr | grep -Ei "T _main|T main" | awk '{print $1}'`
          $ECHO "Note: AFL_FRIDA_PERSISTENT_ADDR=$AFL_FRIDA_PERSISTENT_ADDR <= $(nm test-instr | grep "T main" | awk '{print $1}')"
          env|grep AFL_|sort
          file test-instr
          export AFL_DEBUG_CHILD=1
          export AFL_FRIDA_VERBOSE=1
          ../afl-fuzz -m ${MEM_LIMIT} -V07 -O -i in -o out -- ./test-instr
          nm test-instr | grep -i "main"
          unset AFL_FRIDA_PERSISTENT_ADDR
        } >>errors 2>&1
        test -n "$( ls out/default/queue/id:000002* 2>/dev/null )" && {
          $ECHO "$GREEN[+] afl-fuzz is working correctly with persistent frida_mode"
          RUNTIMEP=`grep execs_done out/default/fuzzer_stats | awk '{print$3}'`
          test -n "$RUNTIME" -a -n "$RUNTIMEP" && {
            DIFF=`expr $RUNTIMEP / $RUNTIME`
            test "$DIFF" -gt 1 && { # must be at least twice as fast
              $ECHO "$GREEN[+] persistent frida_mode was noticeable faster than standard frida_mode"
            } || {
              $ECHO "$YELLOW[-] persistent frida_mode was not noticeable faster than standard frida_mode"
            }
          } || {
            $ECHO "$YELLOW[-] we got no data on executions performed? weird!"
          }
        } || {
          echo CUT------------------------------------------------------------------CUT
          cat errors
          echo CUT------------------------------------------------------------------CUT
          $ECHO "$RED[!] afl-fuzz is not working correctly with persistent frida_mode"
          CODE=1
        }
        rm -rf in out errors
      } || {
       $ECHO "$YELLOW[-] not an intel or arm platform, cannot test persistent frida_mode"
      }

    }
  } || {
    $ECHO "$RED[!] gcc compilation of test targets failed - what is going on??"
    CODE=1
  }

  rm -f test-instr test-compcov
} || {
  $ECHO "$YELLOW[-] frida_mode is not compiled, cannot test"
  INCOMPLETE=1
}

. ./test-post.sh
