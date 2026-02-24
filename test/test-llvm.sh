#!/bin/sh

. ./test-pre.sh

OS=$(uname -s)

$ECHO "$BLUE[*] Testing: llvm_mode, afl-showmap, afl-fuzz, afl-cmin and afl-tmin"
test -e ../afl-clang-fast -a -e ../split-switches-pass.so && {
  rm -f test-instr.plain
  ../afl-clang-fast -o test-instr.plain ../test-instr.c > /dev/null 2>&1
  AFL_HARDEN=1 ../afl-clang-fast -o test-compcov.harden test-compcov.c > /dev/null 2>&1
  test -e test-instr.plain && {
    chmod +x test-instr.plain
    ls -l test-instr.plain
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
    rm -f test-instr.ts.0 test-instr.ts.1 test-instr.ts
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
  (test "$OS" = "Darwin" && test $(launchctl list 2>/dev/null | grep -q '\.ReportCrash$') && {
    $ECHO "$RED[!] we cannot run afl-fuzz with enabled crash reporter. Run 'sudo sh afl-system-config'.$RESET"
    CODE=1
    true
  }) || {
    mkdir -p in
    echo 0 > in/in
    test -z "$SKIP" && {
      $ECHO "$GREY[*] running afl-fuzz for llvm_mode, this will take approx 10 seconds"
      {
        ../afl-fuzz -V07 -m ${MEM_LIMIT} -i in -o out -- ./test-instr.plain >>errors 2>&1
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
      mkdir -p in2
      echo 000000000000000000000000 > in/in2
      echo 111 > in/in3
      test "$OS" = "Darwin" && {
        $ECHO "$GREY[*] afl-cmin not available on macOS, cannot test afl-cmin"
      } || {
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
        #AFL_LLVM_INSTRUMENT=AFL 
        AFL_DEBUG=1 AFL_LLVM_LAF_SPLIT_COMPARES_BITW=$BITS AFL_LLVM_LAF_SPLIT_COMPARES=1 ../afl-clang-fast -fsigned-char -DINT_TYPE="$I" -o "$bin" "$testcase" > test.out 2>&1;
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
      AFL_BENCH_UNTIL_CRASH=1 AFL_NO_UI=1 ../afl-fuzz -Z -s 123 -V15 -m ${MEM_LIMIT} -i in -o out -- ./test-floatingpoint >>errors 2>&1
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
 test "$SYS" = "i686" -o "$SYS" = "x86_64" -o "$SYS" = "amd64" && {
  AFL_LLVM_CMPLOG=1 ../afl-clang-fast -o test-cmplog test-cmplog.c > /dev/null 2>&1
  test -e test-cmplog && {
    $ECHO "$GREY[*] running afl-fuzz for llvm_mode cmplog, this will take approx 10 seconds"
    {
      mkdir -p in
      echo 00000000000000000000000000000000 > in/in
      AFL_BENCH_UNTIL_CRASH=1 AFL_NO_CRASH_README=1 AFL_SHA1_FILENAMES=1 ../afl-fuzz -Z -l 3 -m none -V30 -i in -o out -c 0 -- ./test-cmplog >>errors 2>&1
    } >>errors 2>&1
    test -n "$( ls out/default/crashes/* out/default/hangs/* 2>/dev/null )" && {
      $ECHO "$GREEN[+] afl-fuzz is working correctly with llvm_mode cmplog"
    } || {
      echo CUT------------------------------------------------------------------CUT
      cat errors
      echo CUT------------------------------------------------------------------CUT
      $ECHO "$RED[!] afl-fuzz is not working correctly with llvm_mode cmplog"
      CODE=1
    }
    test -n "$( ls out/default/crashes/id:000000* out/default/hangs/id:000000* 2>/dev/null )" && {
      $ECHO "$RED[!] filenames are not SHA1"
      CODE=1
    } || true
  } || {
    $ECHO "$YELLOW[-] we cannot test llvm_mode cmplog because it is not present"
    INCOMPLETE=1
  }
 } || {
  $ECHO "$YELLOW[-] CMPLOG too slow to test in ARM CI, cannot test"
  INCOMPLETE=1
 }
  rm -rf errors test-cmplog in core.*
  # Test cmplog back-edge/loop detection
  test -e test-cmplog-loops.sh && {
    ./test-cmplog-loops.sh > /dev/null 2>&1 && {
      $ECHO "$GREEN[+] cmplog loop back-edge detection test passed"
    } || {
      $ECHO "$RED[!] cmplog loop back-edge detection test failed"
      CODE=1
    }
  }
  # Test cmplog routines pass instrumentation
  test -e test-cmplog-routines-pass.sh && {
    ./test-cmplog-routines-pass.sh > /dev/null 2>&1 && {
      $ECHO "$GREEN[+] cmplog routines pass instrumentation test passed"
    } || {
      $ECHO "$RED[!] cmplog routines pass instrumentation test failed"
      CODE=1
    }
  }
  # Test value profiling with cmplog
 test "$SYS" = "i686" -o "$SYS" = "x86_64" -o "$SYS" = "amd64" && {
  ../afl-clang-fast -o test-value-profile test-value-profile.c > /dev/null 2>&1
  AFL_LLVM_CMPLOG=1 ../afl-clang-fast -o test-value-profile.cmplog test-value-profile.c > /dev/null 2>&1
  AFL_LLVM_VALUE_PROFILE=1 ../afl-clang-fast -o test-value-profile.vp test-value-profile.c > /dev/null 2>&1
  AFL_LLVM_CMPLOG=1 AFL_LLVM_VALUE_PROFILE=1 ../afl-clang-fast -o test-value-profile.both test-value-profile.c > /dev/null 2>&1
  test -e test-value-profile -a -e test-value-profile.cmplog -a -e test-value-profile.vp -a -e test-value-profile.both && {
    $ECHO "$GREY[*] running afl-fuzz for llvm_mode value profiling checks, this will take approx 150 seconds"
    {
      mkdir -p in
      echo 00000000 > in/in
      AFL_VALUE_PROFILE=0 AFL_BENCH_UNTIL_CRASH=1 AFL_NO_CRASH_README=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 ../afl-fuzz -m none -V20 -i in -o out_no_vp -c ./test-value-profile.cmplog -- ./test-value-profile >>errors 2>&1
      AFL_VALUE_PROFILE=1 AFL_VALUE_PROFILE_LEVEL=2 AFL_BENCH_UNTIL_CRASH=1 AFL_NO_CRASH_README=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 ../afl-fuzz -m none -V90 -i in -o out_vp -c ./test-value-profile.cmplog -- ./test-value-profile >>errors 2>&1
      # Regression check: mode 2 must activate from edge-coverage stagnation.
      timeout 120s env AFL_VALUE_PROFILE=2 AFL_VALUE_PROFILE_LEVEL=2 AFL_NO_CRASH_README=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 ../afl-fuzz -m none -V20 -i in -o out_vp_stag -c ./test-value-profile.cmplog -- ./test-value-profile >>errors 2>&1 || true
      # Level 2 inline source path (main target built with CmpLog)
      AFL_VALUE_PROFILE=1 AFL_VALUE_PROFILE_LEVEL=2 AFL_BENCH_UNTIL_CRASH=1 AFL_NO_CRASH_README=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 ../afl-fuzz -m none -V8 -i in -o out_vp_inline -- ./test-value-profile.cmplog >>errors 2>&1
      # Level 1 runtime path (main target built with VP runtime instrumentation)
      AFL_VALUE_PROFILE=1 AFL_VALUE_PROFILE_LEVEL=1 AFL_BENCH_UNTIL_CRASH=1 AFL_NO_CRASH_README=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 ../afl-fuzz -m none -V8 -i in -o out_vp_l1 -- ./test-value-profile.vp >>errors 2>&1
      # Level 1 must fail clearly when runtime VP instrumentation is missing.
      AFL_VALUE_PROFILE=1 AFL_VALUE_PROFILE_LEVEL=1 AFL_BENCH_UNTIL_CRASH=1 AFL_NO_CRASH_README=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 ../afl-fuzz -m none -V4 -i in -o out_l1_err -- ./test-value-profile >>errors 2>&1 || true
      # Snapshot pre-resume VP stats now: the fastresume checks below intentionally
      # mutate out_vp/default/* and out_no_vp/default/*.
      cp out_vp/default/fuzzer_stats vp_pre_resume_fuzzer_stats
      no_vp_stats_has_vp=0
      grep -q "^value_profile_finds" out_no_vp/default/fuzzer_stats && no_vp_stats_has_vp=1 || true
      # Fastresume VP compatibility checks:
      # 1) resume VP fastresume without AFL_VALUE_PROFILE
      AFL_AUTORESUME=1 AFL_NO_CRASH_README=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 ../afl-fuzz -m none -V2 -i in -o out_vp -c ./test-value-profile.cmplog -- ./test-value-profile >vp_resume_no_vp.log 2>&1
      # 2) resume non-VP fastresume with AFL_VALUE_PROFILE
      AFL_AUTORESUME=1 AFL_VALUE_PROFILE=1 AFL_VALUE_PROFILE_LEVEL=2 AFL_NO_CRASH_README=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 ../afl-fuzz -m none -V2 -i in -o out_no_vp -c ./test-value-profile.cmplog -- ./test-value-profile >vp_resume_with_vp.log 2>&1
      cat vp_resume_no_vp.log vp_resume_with_vp.log >>errors
    } >>errors 2>&1

    vp_finds="$(awk -F: '/^value_profile_finds/ {gsub(/[[:space:]]/, "", $2); print $2; exit}' vp_pre_resume_fuzzer_stats)"
    vp_stag_finds="$(awk -F: '/^value_profile_finds/ {gsub(/[[:space:]]/, "", $2); print $2; exit}' out_vp_stag/default/fuzzer_stats)"
    vp_inline_finds="$(awk -F: '/^value_profile_finds/ {gsub(/[[:space:]]/, "", $2); print $2; exit}' out_vp_inline/default/fuzzer_stats)"
    vp_l1_finds="$(awk -F: '/^value_profile_finds/ {gsub(/[[:space:]]/, "", $2); print $2; exit}' out_vp_l1/default/fuzzer_stats)"
    test -n "$vp_finds" &&
    test "$vp_finds" -gt 0 &&
    test -n "$vp_stag_finds" &&
    test "$vp_stag_finds" -gt 0 &&
    test -n "$vp_inline_finds" &&
    test "$vp_inline_finds" -gt 0 &&
    test -n "$vp_l1_finds" &&
    test "$vp_l1_finds" -gt 0 &&
    grep -q "Stagnation (" errors &&
    grep -q "AFL_VALUE_PROFILE_LEVEL=1 requires runtime VP instrumentation" errors &&
    grep -q "Will perform FAST RESUME" vp_resume_no_vp.log &&
    grep -q "Will perform FAST RESUME" vp_resume_with_vp.log &&
    ! grep -q "Segmentation fault" vp_resume_no_vp.log &&
    ! grep -q "Segmentation fault" vp_resume_with_vp.log &&
    test "$no_vp_stats_has_vp" -eq 0 &&
    strings -a test-value-profile.both | grep -q "__AFL_CMPLOG_INSTRUMENTED" &&
    strings -a test-value-profile.both | grep -q "__AFL_VP_RUNTIME_INSTRUMENTED" &&
    ! grep -q "Segmentation fault" errors && {
      $ECHO "$GREEN[+] afl-fuzz is working correctly with llvm_mode value profiling"
    } || {
      echo CUT------------------------------------------------------------------CUT
      cat errors
      echo CUT------------------------------------------------------------------CUT
      $ECHO "$RED[!] afl-fuzz is not working correctly with llvm_mode value profiling"
      CODE=1
    }
  } || {
    $ECHO "$YELLOW[-] we cannot test llvm_mode value profiling because compilation failed"
    INCOMPLETE=1
  }
  cc -O2 -fPIC -shared -I../include -o test-vp-postprocess-mutator.so test-vp-postprocess-mutator.c > /dev/null 2>&1
  ../afl-clang-fast -DVP_LOG_PATH='"/tmp/afl-vp-main.log"' -o test-vp-postprocess test-vp-postprocess-target.c > /dev/null 2>&1
  AFL_LLVM_CMPLOG=1 ../afl-clang-fast -DVP_LOG_PATH='"/tmp/afl-vp-cmplog.log"' -o test-vp-postprocess.cmplog test-vp-postprocess-target.c > /dev/null 2>&1
  test -e test-vp-postprocess-mutator.so -a -e test-vp-postprocess -a -e test-vp-postprocess.cmplog && {
    $ECHO "$GREY[*] running VP post_process regression check"
    {
      rm -f /tmp/afl-vp-main.log /tmp/afl-vp-cmplog.log
      mkdir -p in_post
      echo 0000000000 > in_post/in
      AFL_VALUE_PROFILE=1 AFL_VALUE_PROFILE_LEVEL=2 AFL_POST_PROCESS_KEEP_ORIGINAL=1 AFL_CUSTOM_MUTATOR_LIBRARY=./test-vp-postprocess-mutator.so AFL_BENCH_UNTIL_CRASH=1 AFL_NO_CRASH_README=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 ../afl-fuzz -m none -V10 -i in_post -o out_vp_post -c ./test-vp-postprocess.cmplog -- ./test-vp-postprocess >>errors_post 2>&1
    } >>errors_post 2>&1
    if test -f /tmp/afl-vp-cmplog.log; then
      vp_cmplog_total="$(wc -l < /tmp/afl-vp-cmplog.log)"
      vp_non_magic="$(awk '$2 != "4d41474943" {c++} END {print c+0}' /tmp/afl-vp-cmplog.log)"
    else
      vp_cmplog_total=0
      vp_non_magic=1
    fi
    test -n "$vp_cmplog_total" &&
    test "$vp_cmplog_total" -gt 0 &&
    test "$vp_non_magic" -eq 0 && {
      $ECHO "$GREEN[+] VP post_process regression check passed"
    } || {
      echo CUT------------------------------------------------------------------CUT
      cat errors_post
      echo CUT------------------------------------------------------------------CUT
      if test -f /tmp/afl-vp-cmplog.log; then
        echo VP-CMPLOG------------------------------------------------------------
        awk '$2 != "4d41474943" {print; if(++n==20) exit}' /tmp/afl-vp-cmplog.log
        echo VP-CMPLOG------------------------------------------------------------
      fi
      $ECHO "$RED[!] VP post_process regression check failed"
      CODE=1
    }
  } || {
    $ECHO "$YELLOW[-] we cannot run VP post_process regression check because compilation failed"
    INCOMPLETE=1
  }
  rm -rf errors errors_post vp_resume_no_vp.log vp_resume_with_vp.log vp_pre_resume_fuzzer_stats test-value-profile test-value-profile.cmplog test-value-profile.vp test-value-profile.both test-vp-postprocess test-vp-postprocess.cmplog test-vp-postprocess-mutator.so in in_post out_no_vp out_vp out_vp_stag out_vp_inline out_vp_l1 out_l1_err out_vp_post core.* /tmp/afl-vp-main.log /tmp/afl-vp-cmplog.log
 } || {
  $ECHO "$YELLOW[-] value profiling requires CmpLog, too slow to test in ARM CI"
  INCOMPLETE=1
 }
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
 test "$SYS" = "i686" -o "$SYS" = "x86_64" -o "$SYS" = "amd64" && {
  AFL_LLVM_IJON=1 ../afl-clang-fast -o ijon-maze -fsanitize=fuzzer ijon-maze.c > /dev/null 2>&1
  test -e ijon-maze && {
    $ECHO "$GREY[*] running afl-fuzz with IJON maze, this will take approx 10 seconds"
    {
      mkdir -p in
      echo 00000000000000000000000000000000 > in/in
      AFL_BENCH_UNTIL_CRASH=1 AFL_NO_CRASH_README=1 ../afl-fuzz -Z -m none -V64 -i in -o out -- ./ijon-maze >>errors 2>&1
    } >>errors 2>&1
    test -n "$( ls out/default/crashes/* 2>/dev/null )" && {
      $ECHO "$GREEN[+] afl-fuzz is working correctly with IJON"
    } || {
      echo CUT------------------------------------------------------------------CUT
      cat errors
      echo CUT------------------------------------------------------------------CUT
      $ECHO "$RED[!] afl-fuzz is not working correctly with IJON"
      CODE=1
    }
  } || {
    $ECHO "$RED[!] IJON maze compilation failed"
    CODE=1
  }
  rm -rf ijon-maze in out errors
 } || {
  $ECHO "$YELLOW[-] IJON too slow to test in ARM CI, cannot test"
  INCOMPLETE=1
 }
} || {
  $ECHO "$YELLOW[-] llvm_mode not compiled, cannot test"
  INCOMPLETE=1
}

. ./test-post.sh
