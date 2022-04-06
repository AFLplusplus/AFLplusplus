#!/bin/sh

. ./test-pre.sh

$ECHO "$BLUE[*] Testing: llvm_mode, afl-showmap, afl-fuzz, afl-cmin and afl-tmin"
test -e ../afl-clang-fast -a -e ../split-switches-pass.so && {
  ../afl-clang-fast -o test-instr.plain ../test-instr.c > /dev/null 2>&1
  AFL_HARDEN=1 ../afl-clang-fast -o test-compcov.harden test-compcov.c > /dev/null 2>&1
  test -e test-instr.plain && {
    $ECHO "$GREEN[+] llvm_mode compilation succeeded"
    echo 0 | AFL_QUIET=1 ../afl-showmap -m ${MEM_LIMIT} -o test-instr.plain.0 -r -- ./test-instr.plain > /dev/null 2>&1
    AFL_QUIET=1 ../afl-showmap -m ${MEM_LIMIT} -o test-instr.plain.1 -r -- ./test-instr.plain < /dev/null > /dev/null 2>&1
    test -e test-instr.plain.0 -a -e test-instr.plain.1 && {
      diff test-instr.plain.0 test-instr.plain.1 > /dev/null 2>&1 && {
        $ECHO "$RED[!] llvm_mode instrumentation should be different on different input but is not"
        CODE=1
      } || {
        $ECHO "$GREEN[+] llvm_mode instrumentation present and working correctly"
        TUPLES=`echo 0|AFL_QUIET=1 ../afl-showmap -m ${MEM_LIMIT} -o /dev/null -- ./test-instr.plain 2>&1 | grep Captur | awk '{print$3}'`
        test "$TUPLES" -gt 2 -a "$TUPLES" -lt 8 && {
          $ECHO "$GREEN[+] llvm_mode run reported $TUPLES instrumented locations which is fine"
        } || {
          $ECHO "$RED[!] llvm_mode instrumentation produces weird numbers: $TUPLES"
          CODE=1
        }
        test "$TUPLES" -lt 3 && SKIP=1
        true
      }
    } || {
      $ECHO "$RED[!] llvm_mode instrumentation failed"
      CODE=1
    }
    rm -f test-instr.plain.0 test-instr.plain.1
  } || {
    $ECHO "$RED[!] llvm_mode failed"
    CODE=1
  }
  AFL_LLVM_INSTRUMENT=CLASSIC AFL_LLVM_THREADSAFE_INST=1 ../afl-clang-fast -o test-instr.ts ../test-instr.c > /dev/null 2>&1
  test -e test-instr.ts && {
    $ECHO "$GREEN[+] llvm_mode threadsafe compilation succeeded"
    echo 0 | AFL_QUIET=1 ../afl-showmap -m ${MEM_LIMIT} -o test-instr.ts.0 -r -- ./test-instr.ts > /dev/null 2>&1
    AFL_QUIET=1 ../afl-showmap -m ${MEM_LIMIT} -o test-instr.ts.1 -r -- ./test-instr.ts < /dev/null > /dev/null 2>&1
    test -e test-instr.ts.0 -a -e test-instr.ts.1 && {
      diff test-instr.ts.0 test-instr.ts.1 > /dev/null 2>&1 && {
        $ECHO "$RED[!] llvm_mode threadsafe instrumentation should be different on different input but is not"
        CODE=1
      } || {
        $ECHO "$GREEN[+] llvm_mode threadsafe instrumentation present and working correctly"
        TUPLES=`echo 0|AFL_QUIET=1 ../afl-showmap -m ${MEM_LIMIT} -o /dev/null -- ./test-instr.ts 2>&1 | grep Captur | awk '{print$3}'`
        test "$TUPLES" -gt 2 -a "$TUPLES" -lt 8 && {
          $ECHO "$GREEN[+] llvm_mode run reported $TUPLES threadsafe instrumented locations which is fine"
        } || {
          $ECHO "$RED[!] llvm_mode threadsafe instrumentation produces weird numbers: $TUPLES"
          CODE=1
        }
        test "$TUPLES" -lt 3 && SKIP=1
        true
      }
    } || {
      $ECHO "$RED[!] llvm_mode threadsafe instrumentation failed"
      CODE=1
    }
    rm -f test-instr.ts.0 test-instr.ts.1
  } || {
    $ECHO "$RED[!] llvm_mode (threadsafe) failed"
    CODE=1
  }
  ../afl-clang-fast -DTEST_SHARED_OBJECT=1 -z defs -fPIC -shared -o test-instr.so ../test-instr.c > /dev/null 2>&1
  test -e test-instr.so && {
    $ECHO "$GREEN[+] llvm_mode shared object with -z defs compilation succeeded"
    test `uname -s` = 'Linux' && LIBS=-ldl
    ../afl-clang-fast -o test-dlopen.plain test-dlopen.c ${LIBS} > /dev/null 2>&1
    test -e test-dlopen.plain && {
      $ECHO "$GREEN[+] llvm_mode test-dlopen compilation succeeded"
      echo 0 | DYLD_INSERT_LIBRARIES=./test-instr.so LD_PRELOAD=./test-instr.so TEST_DLOPEN_TARGET=./test-instr.so AFL_QUIET=1 ./test-dlopen.plain > /dev/null 2>&1
      if [ $? -ne 0 ]; then
        $ECHO "$RED[!] llvm_mode test-dlopen exits with an error"
        CODE=1
      fi
      echo 0 | AFL_PRELOAD=./test-instr.so TEST_DLOPEN_TARGET=./test-instr.so AFL_QUIET=1 ../afl-showmap -m ${MEM_LIMIT} -o test-dlopen.plain.0 -r -- ./test-dlopen.plain > /dev/null 2>&1
      AFL_PRELOAD=./test-instr.so TEST_DLOPEN_TARGET=./test-instr.so AFL_QUIET=1 ../afl-showmap -m ${MEM_LIMIT} -o test-dlopen.plain.1 -r -- ./test-dlopen.plain < /dev/null > /dev/null 2>&1
      test -e test-dlopen.plain.0 -a -e test-dlopen.plain.1 && {
        diff test-dlopen.plain.0 test-dlopen.plain.1 > /dev/null 2>&1 && {
          $ECHO "$RED[!] llvm_mode test-dlopen instrumentation should be different on different input but is not"
          CODE=1
        } || {
          $ECHO "$GREEN[+] llvm_mode test-dlopen instrumentation present and working correctly"
          TUPLES=`echo 0|AFL_PRELOAD=./test-instr.so TEST_DLOPEN_TARGET=./test-instr.so AFL_QUIET=1 ../afl-showmap -m ${MEM_LIMIT} -o /dev/null -- ./test-dlopen.plain 2>&1 | grep Captur | awk '{print$3}'`
          test "$TUPLES" -gt 3 -a "$TUPLES" -lt 12 && {
            $ECHO "$GREEN[+] llvm_mode test-dlopen run reported $TUPLES instrumented locations which is fine"
          } || {
            $ECHO "$RED[!] llvm_mode test-dlopen instrumentation produces weird numbers: $TUPLES"
            CODE=1
          }
          test "$TUPLES" -lt 3 && SKIP=1
          true
        }
      } || {
        $ECHO "$RED[!] llvm_mode test-dlopen instrumentation failed"
        CODE=1
      }
    } || {
      $ECHO "$RED[!] llvm_mode test-dlopen compilation failed"
      CODE=1
    }
    rm -f test-dlopen.plain test-dlopen.plain.0 test-dlopen.plain.1 test-instr.so
    unset LIBS
  } || {
    $ECHO "$RED[!] llvm_mode shared object with -z defs compilation failed"
    CODE=1
  }
  test -e test-compcov.harden && test_compcov_binary_functionality ./test-compcov.harden && {
    nm test-compcov.harden | grep -Eq 'stack_chk_fail|fstack-protector-all|fortified' > /dev/null 2>&1 && {
      $ECHO "$GREEN[+] llvm_mode hardened mode succeeded and is working"
    } || {
      $ECHO "$RED[!] llvm_mode hardened mode is not hardened"
      CODE=1
    }
    rm -f test-compcov.harden
  } || {
    $ECHO "$RED[!] llvm_mode hardened mode compilation failed"
    CODE=1
  }
  # now we want to be sure that afl-fuzz is working
  # make sure crash reporter is disabled on Mac OS X
  (test "$(uname -s)" = "Darwin" && test $(launchctl list 2>/dev/null | grep -q '\.ReportCrash$') && {
    $ECHO "$RED[!] we cannot run afl-fuzz with enabled crash reporter. Run 'sudo sh afl-system-config'.$RESET"
    CODE=1
    true
  }) || {
    mkdir -p in
    echo 0 > in/in
    test -z "$SKIP" && {
      $ECHO "$GREY[*] running afl-fuzz for llvm_mode, this will take approx 10 seconds"
      {
        ../afl-fuzz -V10 -m ${MEM_LIMIT} -i in -o out -D -- ./test-instr.plain >>errors 2>&1
      } >>errors 2>&1
      test -n "$( ls out/default/queue/id:000002* 2>/dev/null )" && {
        $ECHO "$GREEN[+] afl-fuzz is working correctly with llvm_mode"
      } || {
        echo CUT------------------------------------------------------------------CUT
        cat errors
        echo CUT------------------------------------------------------------------CUT
        $ECHO "$RED[!] afl-fuzz is not working correctly with llvm_mode"
        CODE=1
      }
    }
    test "$SYS" = "i686" -o "$SYS" = "x86_64" -o "$SYS" = "amd64" -o "$SYS" = "i86pc" || {
      echo 000000000000000000000000 > in/in2
      echo 111 > in/in3
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
      export AFL_QUIET=1
      if type bash >/dev/null ; then {
        ../afl-cmin.bash -m ${MEM_LIMIT} -i in -o in2 -- ./test-instr.plain >/dev/null
        CNT=`ls in2/* 2>/dev/null | wc -l`
        case "$CNT" in
          *2) $ECHO "$GREEN[+] afl-cmin.bash correctly minimized the number of testcases" ;;
          *)  $ECHO "$RED[!] afl-cmin.bash did not correctly minimize the number of testcases ($CNT)"
              CODE=1
              ;;
          esac
      } else {
        $ECHO "$YELLOW[-] no bash available, cannot test afl-cmin.bash"
        INCOMPLETE=1
      }
      fi
      ../afl-tmin -m ${MEM_LIMIT} -i in/in2 -o in2/in2 -- ./test-instr.plain > /dev/null 2>&1
      SIZE=`ls -l in2/in2 2>/dev/null | awk '{print$5}'`
      test "$SIZE" = 1 && $ECHO "$GREEN[+] afl-tmin correctly minimized the testcase"
      test "$SIZE" = 1 || {
         $ECHO "$RED[!] afl-tmin did incorrectly minimize the testcase to $SIZE"
         CODE=1
      }
      rm -rf in2
    }
    rm -rf in out errors
  }
  rm -f test-instr.plain

  $ECHO "$GREY[*] llvm_mode laf-intel/compcov testing splitting integer types (this might take some time)"
  for testcase in ./test-int_cases.c ./test-uint_cases.c; do
    for I in char short int long "long long"; do
      for BITS in 8 16 32 64; do
        bin="$testcase-split-$I-$BITS.compcov" 
        AFL_LLVM_INSTRUMENT=AFL AFL_DEBUG=1 AFL_LLVM_LAF_SPLIT_COMPARES_BITW=$BITS AFL_LLVM_LAF_SPLIT_COMPARES=1 ../afl-clang-fast -fsigned-char -DINT_TYPE="$I" -o "$bin" "$testcase" > test.out 2>&1;
        if ! test -e "$bin"; then
            cat test.out
            $ECHO "$RED[!] llvm_mode laf-intel/compcov integer splitting failed! ($testcase with type $I split to $BITS)!";
            CODE=1
            break
        fi
        if ! "$bin"; then
            $ECHO "$RED[!] llvm_mode laf-intel/compcov integer splitting resulted in miscompilation (type $I split to $BITS)!";
            CODE=1
            break
        fi
        rm -f "$bin" test.out || true
      done
    done
  done
  rm -f test-int-split*.compcov test.out

  AFL_LLVM_INSTRUMENT=AFL AFL_DEBUG=1 AFL_LLVM_LAF_SPLIT_SWITCHES=1 AFL_LLVM_LAF_TRANSFORM_COMPARES=1 AFL_LLVM_LAF_SPLIT_COMPARES=1 ../afl-clang-fast -o test-compcov.compcov test-compcov.c > test.out 2>&1
  test -e test-compcov.compcov && test_compcov_binary_functionality ./test-compcov.compcov && {
    grep --binary-files=text -Eq " [ 123][0-9][0-9] location| [3-9][0-9] location" test.out && {
      $ECHO "$GREEN[+] llvm_mode laf-intel/compcov feature works correctly"
    } || {
      $ECHO "$RED[!] llvm_mode laf-intel/compcov feature failed"
      CODE=1
    }
  } || {
    $ECHO "$RED[!] llvm_mode laf-intel/compcov feature compilation failed"
    CODE=1
  }
  rm -f test-compcov.compcov test.out
  AFL_LLVM_INSTRUMENT=AFL AFL_LLVM_LAF_SPLIT_FLOATS=1 ../afl-clang-fast -o test-floatingpoint test-floatingpoint.c >errors 2>&1
  test -e test-floatingpoint && {
    mkdir -p in
    echo ZZZZ > in/in
    $ECHO "$GREY[*] running afl-fuzz with floating point splitting, this will take max. 45 seconds"
    {
      AFL_BENCH_UNTIL_CRASH=1 AFL_NO_UI=1 ../afl-fuzz -Z -s 123 -V50 -m ${MEM_LIMIT} -i in -o out -D -- ./test-floatingpoint >>errors 2>&1
    } >>errors 2>&1
    test -n "$( ls out/default/crashes/id:* 2>/dev/null )" && {
      $ECHO "$GREEN[+] llvm_mode laf-intel floatingpoint splitting feature works correctly"
    } || {
      cat errors
      $ECHO "$RED[!] llvm_mode laf-intel floatingpoint splitting feature failed"
      CODE=1
    }
  } || {
    $ECHO "$RED[!] llvm_mode laf-intel floatingpoint splitting feature compilation failed"
    CODE=1
  }
  rm -f test-floatingpoint test.out in/in errors core.*
  echo foobar.c > instrumentlist.txt
  AFL_DEBUG=1 AFL_LLVM_INSTRUMENT_FILE=instrumentlist.txt ../afl-clang-fast -o test-compcov test-compcov.c > test.out 2>&1
  test -e test-compcov && test_compcov_binary_functionality ./test-compcov && {
    grep -q "No instrumentation targets found" test.out && {
      $ECHO "$GREEN[+] llvm_mode instrumentlist feature works correctly"
    } || {
      $ECHO "$RED[!] llvm_mode instrumentlist feature failed"
      CODE=1
    }
  } || {
    $ECHO "$RED[!] llvm_mode instrumentlist feature compilation failed"
    CODE=1
  }
  rm -f test-compcov test.out instrumentlist.txt
  AFL_LLVM_CMPLOG=1 ../afl-clang-fast -o test-cmplog test-cmplog.c > /dev/null 2>&1
  test -e test-cmplog && {
    $ECHO "$GREY[*] running afl-fuzz for llvm_mode cmplog, this will take approx 10 seconds"
    {
      mkdir -p in
      echo 00000000000000000000000000000000 > in/in
      AFL_BENCH_UNTIL_CRASH=1 ../afl-fuzz -m none -V60 -i in -o out -c./test-cmplog -- ./test-cmplog >>errors 2>&1
    } >>errors 2>&1
    test -n "$( ls out/default/crashes/id:000000* out/default/hangs/id:000000* 2>/dev/null )" & {
      $ECHO "$GREEN[+] afl-fuzz is working correctly with llvm_mode cmplog"
    } || {
      echo CUT------------------------------------------------------------------CUT
      cat errors
      echo CUT------------------------------------------------------------------CUT
      $ECHO "$RED[!] afl-fuzz is not working correctly with llvm_mode cmplog"
      CODE=1
    }
  } || {
    $ECHO "$YELLOW[-] we cannot test llvm_mode cmplog because it is not present"
    INCOMPLETE=1
  }
  rm -rf errors test-cmplog in core.*
  ../afl-clang-fast -o test-persistent ../utils/persistent_mode/persistent_demo.c > /dev/null 2>&1
  test -e test-persistent && {
    echo foo | AFL_QUIET=1 ../afl-showmap -m ${MEM_LIMIT} -o /dev/null -q -r ./test-persistent && {
      $ECHO "$GREEN[+] llvm_mode persistent mode feature works correctly"
    } || {
      $ECHO "$RED[!] llvm_mode persistent mode feature failed to work"
      CODE=1
    }
  } || {
    $ECHO "$RED[!] llvm_mode persistent mode feature compilation failed"
    CODE=1
  }
  rm -f test-persistent
} || {
  $ECHO "$YELLOW[-] llvm_mode not compiled, cannot test"
  INCOMPLETE=1
}

. ./test-post.sh
