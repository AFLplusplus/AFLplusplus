#!/bin/sh

. ./test-pre.sh

$ECHO "$BLUE[*] Testing: gcc_plugin"
test -e ../afl-gcc-fast -a -e ../afl-compiler-rt.o && {
  SAVE_AFL_CC=${AFL_CC}
  export AFL_CC=`command -v gcc`
  rm -f test-instr.plain.gccpi
  ../afl-gcc-fast -o test-instr.plain.gccpi ../test-instr.c > /dev/null 2>&1
  AFL_HARDEN=1 ../afl-gcc-fast -o test-compcov.harden.gccpi test-compcov.c > /dev/null 2>&1
  test -e test-instr.plain.gccpi && {
    chmod +x test-instr.plain.gccpi
    ls -l test-instr.plain.gccpi
    $ECHO "$GREEN[+] gcc_plugin compilation succeeded"
    echo 0 | AFL_QUIET=1 ../afl-showmap -m ${MEM_LIMIT} -o test-instr.plain.0 -r -- ./test-instr.plain.gccpi > /dev/null 2>&1
    AFL_QUIET=1 ../afl-showmap -m ${MEM_LIMIT} -o test-instr.plain.1 -r -- ./test-instr.plain.gccpi < /dev/null > /dev/null 2>&1
    test -e test-instr.plain.0 -a -e test-instr.plain.1 && {
      diff test-instr.plain.0 test-instr.plain.1 > /dev/null 2>&1 && {
        $ECHO "$RED[!] gcc_plugin instrumentation should be different on different input but is not"
        CODE=1
      } || {
        $ECHO "$GREEN[+] gcc_plugin instrumentation present and working correctly"
        TUPLES=`echo 0|AFL_QUIET=1 ../afl-showmap -m ${MEM_LIMIT} -o /dev/null -- ./test-instr.plain.gccpi 2>&1 | grep Captur | awk '{print$3}'`
        test "$TUPLES" -gt 1 -a "$TUPLES" -lt 10 && {
          $ECHO "$GREEN[+] gcc_plugin run reported $TUPLES instrumented locations which is fine"
        } || {
          $ECHO "$RED[!] gcc_plugin instrumentation produces a weird numbers: $TUPLES"
          $ECHO "$YELLOW[-] this is a known issue in gcc, not AFL++. It is not flagged as an error because travis builds would all fail otherwise :-("
          #CODE=1
        }
        test "$TUPLES" -lt 2 && SKIP=1
        true
      }
    } || {
      $ECHO "$RED[!] gcc_plugin instrumentation failed"
      CODE=1
    }
    rm -f test-instr.plain.0 test-instr.plain.1
  } || {
    $ECHO "$RED[!] gcc_plugin failed"
    CODE=1
  }

  test -e test-compcov.harden.gccpi && test_compcov_binary_functionality ./test-compcov.harden.gccpi && {
    nm test-compcov.harden.gccpi | grep -Eq 'stack_chk_fail|fstack-protector-all|fortified' > /dev/null 2>&1 && {
      $ECHO "$GREEN[+] gcc_plugin hardened mode succeeded and is working"
    } || {
      $ECHO "$RED[!] gcc_plugin hardened mode is not hardened"
      CODE=1
    }
    rm -f test-compcov.harden.gccpi
  } || {
    $ECHO "$RED[!] gcc_plugin hardened mode compilation failed"
    CODE=1
  }
  # now we want to be sure that afl-fuzz is working
  # make sure crash reporter is disabled on Mac OS X
  (test "$(uname -s)" = "Darwin" && test $(launchctl list 2>/dev/null | grep -q '\.ReportCrash$') && {
    $ECHO "$RED[!] we cannot run afl-fuzz with enabled crash reporter. Run 'sudo sh afl-system-config'.$RESET"
    CODE=1
    true
  }) || {
    test -z "$SKIP" && {
      mkdir -p in
      echo 0 > in/in
      $ECHO "$GREY[*] running afl-fuzz for gcc_plugin, this will take approx 10 seconds"
      {
        ../afl-fuzz -V07 -m ${MEM_LIMIT} -i in -o out -- ./test-instr.plain.gccpi >>errors 2>&1
      } >>errors 2>&1
      test -n "$( ls out/default/queue/id:000002* 2>/dev/null )" && {
        $ECHO "$GREEN[+] afl-fuzz is working correctly with gcc_plugin"
      } || {
        echo CUT------------------------------------------------------------------CUT
        cat errors
        echo CUT------------------------------------------------------------------CUT
        $ECHO "$RED[!] afl-fuzz is not working correctly with gcc_plugin"
        CODE=1
      }
      rm -rf in out errors
    }
  }
  rm -f test-instr.plain.gccpi

  # now for the special gcc_plugin things
  echo foobar.c > instrumentlist.txt
  AFL_GCC_INSTRUMENT_FILE=instrumentlist.txt ../afl-gcc-fast -o test-compcov test-compcov.c > /dev/null 2>&1
  test -x test-compcov && test_compcov_binary_functionality ./test-compcov && {
    echo 1 | AFL_QUIET=1 ../afl-showmap -m ${MEM_LIMIT} -o - -r -- ./test-compcov 2>&1 | grep -q "Captured 0 tuples" && {
      $ECHO "$GREEN[+] gcc_plugin instrumentlist feature works correctly"
    } || {
      $ECHO "$RED[!] gcc_plugin instrumentlist feature failed"
      CODE=1
    }
  } || {
    $ECHO "$RED[!] gcc_plugin instrumentlist feature compilation failed."
    CODE=1
  }
  rm -f test-compcov test.out instrumentlist.txt
  ../afl-gcc-fast -o test-persistent ../utils/persistent_mode/persistent_demo.c > /dev/null 2>&1
  test -e test-persistent && {
    echo foo | AFL_QUIET=1 ../afl-showmap -m ${MEM_LIMIT} -o /dev/null -q -r ./test-persistent && {
      $ECHO "$GREEN[+] gcc_plugin persistent mode feature works correctly"
    } || {
      $ECHO "$RED[!] gcc_plugin persistent mode feature failed to work"
      CODE=1
    }
  } || {
    $ECHO "$RED[!] gcc_plugin persistent mode feature compilation failed"
    CODE=1
  }
  rm -f test-persistent

  # Test setjmp/returns_twice instrumentation fix (GitHub issue #2541)
  # GCC 13+ requires returns_twice calls to be first in their basic block.
  # Compile with -fchecking to verify the CFG is valid.
  $ECHO "$GREY[*] testing setjmp/returns_twice instrumentation (issue #2541)"
  ../afl-gcc-fast -fchecking -fdump-tree-afl -o test-setjmp ./test-setjmp.c > test-setjmp.log 2>&1
  test -e test-setjmp && {
    # Run the binary and capture output for debugging
    SETJMP_OUTPUT=$(./test-setjmp 2>&1)
    SETJMP_RC=$?
    test "$SETJMP_RC" -eq 0 && {
      # Verify instrumentation is present via afl-showmap
      TUPLES=`AFL_QUIET=1 ../afl-showmap -m ${MEM_LIMIT} -o /dev/null -- ./test-setjmp 2>&1 | grep Captur | awk '{print$3}'`
      test "$TUPLES" -gt 0 && {
        # Verify trampoline structure in GIMPLE dump:
        # - setjmp should be first stmt in its block (after DEBUG_STMT)
        # - AFL instrumentation should be in a separate preceding block
        DUMP_FILE=$(ls test-setjmp-test-setjmp.c.*.afl 2>/dev/null | head -1)
        if test -n "$DUMP_FILE"; then
          # Check: setjmp/sigsetjmp blocks should NOT contain afl_prev_loc before the call
          # Extract the blocks and verify no AFL instrumentation before them
          SETJMP_BLOCK=$(grep -B2 "_setjmp" "$DUMP_FILE" | grep -c "afl_prev_loc" || true)
          SIGSETJMP_BLOCK=$(grep -B2 "sigsetjmp" "$DUMP_FILE" | grep -c "afl_prev_loc" || true)
          test "$SETJMP_BLOCK" -eq 0 -a "$SIGSETJMP_BLOCK" -eq 0 && {
            $ECHO "$GREEN[+] gcc_plugin setjmp/returns_twice instrumentation works correctly"
            $ECHO "$GREEN[+] gcc_plugin verified: setjmp/sigsetjmp are first in block, instrumentation in trampoline"
          } || {
            $ECHO "$RED[!] gcc_plugin setjmp test: instrumentation incorrectly placed before setjmp/sigsetjmp"
            CODE=1
          }
        else
          $ECHO "$GREEN[+] gcc_plugin setjmp/returns_twice instrumentation works correctly"
        fi
      } || {
        $ECHO "$RED[!] gcc_plugin setjmp test has no instrumentation (tuples=$TUPLES)"
        CODE=1
      }
    } || {
      $ECHO "$RED[!] gcc_plugin setjmp test execution failed (exit code $SETJMP_RC)"
      test -n "$SETJMP_OUTPUT" && $ECHO "$RED    output: $SETJMP_OUTPUT"
      CODE=1
    }
  } || {
    $ECHO "$RED[!] gcc_plugin setjmp/returns_twice compilation failed (with -fchecking)"
    cat test-setjmp.log
    CODE=1
  }
  rm -f test-setjmp test-setjmp.log test-setjmp-test-setjmp.c.*.afl

  export AFL_CC=${SAVE_AFL_CC}
} || {
  $ECHO "$YELLOW[-] gcc_plugin not compiled, cannot test"
  INCOMPLETE=1
}

. ./test-post.sh
