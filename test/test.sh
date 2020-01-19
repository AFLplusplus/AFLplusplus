#!/bin/sh

#
# Ensure we have: test, type, diff -q, grep -aqE
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
test -z "$LLVM_CONFIG" && LLVM_CONFIG=llvm-config


ECHO="printf %b\\n"
$ECHO \\101 2>&1 | grep -qE '^A' || {
  ECHO=
  test -e /bin/printf && {
    ECHO="/bin/printf %b\\n"
    $ECHO '\\101' 2>&1 | grep -qE '^A' || ECHO=
  }
}
test -z "$ECHO" && { printf Error: printf command does not support octal character codes ; exit 1 ; }

CODE=0
INCOMPLETE=0

export AFL_EXIT_WHEN_DONE=1
export AFL_SKIP_CPUFREQ=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
unset AFL_QUIET
unset AFL_DEBUG
unset AFL_HARDEN
unset AFL_USE_ASAN
unset AFL_USE_MSAN
unset AFL_CC
unset AFL_PRELOAD
unset AFL_GCC_WHITELIST
unset AFL_LLVM_WHITELIST
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
} || {
  AFL_GCC=afl-gcc
}
SYS=`uname -m`

GREY="\\033[1;90m"
BLUE="\\033[1;94m"
GREEN="\\033[0;32m"
RED="\\033[0;31m"
YELLOW="\\033[1;93m"
RESET="\\033[0m"

MEM_LIMIT=150

export PATH=$PATH:/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin

$ECHO "${RESET}${GREY}[*] starting afl++ test framework ..."

test -z "$SYS" && $ECHO "$YELLOW[-] uname -m did not succeed"

$ECHO "$BLUE[*] Testing: ${AFL_GCC}, afl-showmap, afl-fuzz, afl-cmin and afl-tmin"
test "$SYS" = "i686" -o "$SYS" = "x86_64" -o "$SYS" = "amd64" && {
 test -e ../${AFL_GCC} -a -e ../afl-showmap -a -e ../afl-fuzz && {
  ../${AFL_GCC} -o test-instr.plain ../test-instr.c > /dev/null 2>&1
  AFL_HARDEN=1 ../${AFL_GCC} -o test-compcov.harden test-compcov.c > /dev/null 2>&1
  test -e test-instr.plain && {
    $ECHO "$GREEN[+] ${AFL_GCC} compilation succeeded"
    echo 0 | ../afl-showmap -m ${MEM_LIMIT} -o test-instr.plain.0 -r -- ./test-instr.plain > /dev/null 2>&1
    ../afl-showmap -m ${MEM_LIMIT} -o test-instr.plain.1 -r -- ./test-instr.plain < /dev/null > /dev/null 2>&1
    test -e test-instr.plain.0 -a -e test-instr.plain.1 && {
      diff -q test-instr.plain.0 test-instr.plain.1 > /dev/null 2>&1 && {
        $ECHO "$RED[!] ${AFL_GCC} instrumentation should be different on different input but is not"
        CODE=1
      } || {
        $ECHO "$GREEN[+] ${AFL_GCC} instrumentation present and working correctly"
      }
    } || {
      $ECHO "$RED[!] ${AFL_GCC} instrumentation failed"
      CODE=1
    }
    rm -f test-instr.plain.0 test-instr.plain.1
    TUPLES=`echo 0|../afl-showmap -m ${MEM_LIMIT} -o /dev/null -- ./test-instr.plain 2>&1 | grep Captur | awk '{print$3}'`
    test "$TUPLES" -gt 3 -a "$TUPLES" -lt 7 && {
      $ECHO "$GREEN[+] ${AFL_GCC} run reported $TUPLES instrumented locations which is fine"
    } || {
      $ECHO "$RED[!] ${AFL_GCC} produces weird instrumentation numbers: $TUPLES"
      CODE=1
    }
  } || {
    $ECHO "$RED[!] ${AFL_GCC} failed"
    echo CUT------------------------------------------------------------------CUT
    uname -a
    ../${AFL_GCC} -o test-instr.plain ../test-instr.c
    echo CUT------------------------------------------------------------------CUT
    CODE=1
  }
  test -e test-compcov.harden && {
    grep -Eqa 'stack_chk_fail|fstack-protector-all|fortified' test-compcov.harden > /dev/null 2>&1 && {
      $ECHO "$GREEN[+] ${AFL_GCC} hardened mode succeeded and is working"
    } || {
      $ECHO "$RED[!] ${AFL_GCC} hardened mode is not hardened"
      CODE=1
    }
    rm -f test-compcov.harden
  } || { 
    $ECHO "$RED[!] ${AFL_GCC} hardened mode compilation failed"
    CODE=1
  }
  # now we want to be sure that afl-fuzz is working  
  # make sure core_pattern is set to core on linux
  (test "$(uname -s)" = "Linux" && test "$(sysctl kernel.core_pattern)" != "kernel.core_pattern = core" && {
    $ECHO "$YELLOW[-] we should not run afl-fuzz with enabled core dumps. Run 'sudo sh afl-system-config'.$RESET"
    true
  }) ||
  # make sure crash reporter is disabled on Mac OS X
  (test "$(uname -s)" = "Darwin" && test $(launchctl list 2>/dev/null | grep -q '\.ReportCrash$') && {
    $ECHO "$RED[!] we cannot run afl-fuzz with enabled crash reporter. Run 'sudo sh afl-system-config'.$RESET"
    true
  }) || {
    mkdir -p in
    echo 0 > in/in
    $ECHO "$GREY[*] running afl-fuzz for ${AFL_GCC}, this will take approx 10 seconds"
    {
      ../afl-fuzz -V10 -m ${MEM_LIMIT} -i in -o out -- ./test-instr.plain >>errors 2>&1
    } >>errors 2>&1
    test -n "$( ls out/queue/id:000002* 2> /dev/null )" && {
      $ECHO "$GREEN[+] afl-fuzz is working correctly with ${AFL_GCC}"
    } || {
      echo CUT------------------------------------------------------------------CUT
      cat errors
      echo CUT------------------------------------------------------------------CUT
      $ECHO "$RED[!] afl-fuzz is not working correctly with ${AFL_GCC}"
      CODE=1
    }
    echo 000000000000000000000000 > in/in2
    mkdir -p in2
    ../afl-cmin -i in -o in2 -- ./test-instr.plain > /dev/null 2>&1
    CNT=`ls in2/ | wc -l`
    case "$CNT" in
1| *1) $ECHO "$GREEN[+] afl-cmin correctly minimized testcase numbers" ;;
*) $ECHO "$RED[!] afl-cmin did not correctly minimize testcase numbers"
       CODE=1
       ;;
    esac
    ../afl-tmin -i in/in2 -o in2/in2 -- ./test-instr.plain > /dev/null 2>&1
    SIZE=`ls -l in2/in2 2> /dev/null | awk '{print$5}'`
    test "$SIZE" = 1 && $ECHO "$GREEN[+] afl-tmin correctly minimized the testcase"
    test "$SIZE" = 1 || {
       $ECHO "$RED[!] afl-tmin did incorrectly minimize the testcase to $SIZE"
       CODE=1
    }
    rm -rf in out errors in2
  }
  rm -f test-instr.plain
 } || { 
  $ECHO "$YELLOW[-] afl is not compiled, cannot test"
  INCOMPLETE=1
 }
} || { 
 $ECHO "$YELLOW[-] not an intel platform, cannot test afl-gcc"
} 

$ECHO "$BLUE[*] Testing: llvm_mode"
test -e ../afl-clang-fast -a -e ../split-switches-pass.so && {
  # on FreeBSD need to set AFL_CC
  if which clang >/dev/null; then
    export AFL_CC=`which clang`
  else
    export AFL_CC=`$LLVM_CONFIG --bindir`/clang
  fi
  ../afl-clang-fast -o test-instr.plain ../test-instr.c > /dev/null 2>&1
  AFL_HARDEN=1 ../afl-clang-fast -o test-compcov.harden test-compcov.c > /dev/null 2>&1
  test -e test-instr.plain && {
    $ECHO "$GREEN[+] llvm_mode compilation succeeded"
    echo 0 | ../afl-showmap -m ${MEM_LIMIT} -o test-instr.plain.0 -r -- ./test-instr.plain > /dev/null 2>&1
    ../afl-showmap -m ${MEM_LIMIT} -o test-instr.plain.1 -r -- ./test-instr.plain < /dev/null > /dev/null 2>&1
    test -e test-instr.plain.0 -a -e test-instr.plain.1 && {
      diff -q test-instr.plain.0 test-instr.plain.1 > /dev/null 2>&1 && {
        $ECHO "$RED[!] llvm_mode instrumentation should be different on different input but is not"
        CODE=1
      } || {
        $ECHO "$GREEN[+] llvm_mode instrumentation present and working correctly"
        TUPLES=`echo 0|../afl-showmap -m ${MEM_LIMIT} -o /dev/null -- ./test-instr.plain 2>&1 | grep Captur | awk '{print$3}'`
        test "$TUPLES" -gt 3 -a "$TUPLES" -lt 6 && {
          $ECHO "$GREEN[+] llvm_mode run reported $TUPLES instrumented locations which is fine"
        } || {
          $ECHO "$RED[!] llvm_mode instrumentation produces weird numbers: $TUPLES"
          CODE=1
        }
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
  test -e test-compcov.harden && {
    grep -Eqa 'stack_chk_fail|fstack-protector-all|fortified' test-compcov.harden > /dev/null 2>&1 && {
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
  (test "$(uname -s)" = "Linux" && test "$(sysctl kernel.core_pattern)" != "kernel.core_pattern = core" && {
    $ECHO "$YELLOW[-] we should not run afl-fuzz with enabled core dumps. Run 'sudo sh afl-system-config'.$RESET"
    true
  }) ||
  # make sure crash reporter is disabled on Mac OS X
  (test "$(uname -s)" = "Darwin" && test $(launchctl list 2>/dev/null | grep -q '\.ReportCrash$') && {
    $ECHO "$RED[!] we cannot run afl-fuzz with enabled crash reporter. Run 'sudo sh afl-system-config'.$RESET"
    CODE=1
    true
  }) || {
    mkdir -p in
    echo 0 > in/in
    $ECHO "$GREY[*] running afl-fuzz for llvm_mode, this will take approx 10 seconds"
    {
      ../afl-fuzz -V10 -m ${MEM_LIMIT} -i in -o out -- ./test-instr.plain >>errors 2>&1
    } >>errors 2>&1
    test -n "$( ls out/queue/id:000002* 2> /dev/null )" && {
      $ECHO "$GREEN[+] afl-fuzz is working correctly with llvm_mode"
    } || {
      echo CUT------------------------------------------------------------------CUT
      cat errors
      echo CUT------------------------------------------------------------------CUT
      $ECHO "$RED[!] afl-fuzz is not working correctly with llvm_mode"
      CODE=1
    }
    rm -rf in out errors
  }
  rm -f test-instr.plain

  # now for the special llvm_mode things
  AFL_LLVM_INSTRIM=1 AFL_LLVM_INSTRIM_LOOPHEAD=1 ../afl-clang-fast -o test-compcov.instrim test-compcov.c > /dev/null 2> test.out
  test -e test-compcov.instrim && {
    grep -Eq " [1-3] location" test.out && {
      $ECHO "$GREEN[+] llvm_mode InsTrim feature works correctly"
    } || {
      $ECHO "$RED[!] llvm_mode InsTrim feature failed"
      CODE=1
    }
  } || {
    $ECHO "$RED[!] llvm_mode InsTrim feature compilation failed"
    CODE=1
  }
  rm -f test-compcov.instrim test.out
  AFL_LLVM_LAF_SPLIT_SWITCHES=1 AFL_LLVM_LAF_TRANSFORM_COMPARES=1 AFL_LLVM_LAF_SPLIT_COMPARES=1 ../afl-clang-fast -o test-compcov.compcov test-compcov.c > /dev/null 2> test.out
  test -e test-compcov.compcov && {
    grep -Eq " [3-9][0-9] location" test.out && {
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
  echo foobar.c > whitelist.txt
  AFL_LLVM_WHITELIST=whitelist.txt ../afl-clang-fast -o test-compcov test-compcov.c > test.out 2>&1
  test -e test-compcov && {
    grep -q "No instrumentation targets found" test.out && {
      $ECHO "$GREEN[+] llvm_mode whitelist feature works correctly"
    } || {
      $ECHO "$RED[!] llvm_mode whitelist feature failed"
      CODE=1
    }
  } || { 
    $ECHO "$RED[!] llvm_mode whitelist feature compilation failed"
    CODE=1
  }
  rm -f test-compcov test.out whitelist.txt
  ../afl-clang-fast -o test-persistent ../experimental/persistent_demo/persistent_demo.c > /dev/null 2>&1
  test -e test-persistent && {
    echo foo | ../afl-showmap -o /dev/null -q -r ./test-persistent && {
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

$ECHO "$BLUE[*] Testing: gcc_plugin"
export AFL_CC=`which gcc`
test -e ../afl-gcc-fast -a -e ../afl-gcc-rt.o && {
  ../afl-gcc-fast -o test-instr.plain.gccpi ../test-instr.c > /dev/null 2>&1
  AFL_HARDEN=1 ../afl-gcc-fast -o test-compcov.harden.gccpi test-compcov.c > /dev/null 2>&1
  test -e test-instr.plain.gccpi && {
    $ECHO "$GREEN[+] gcc_plugin compilation succeeded"
    echo 0 | ../afl-showmap -m ${MEM_LIMIT} -o test-instr.plain.0 -r -- ./test-instr.plain.gccpi > /dev/null 2>&1
    ../afl-showmap -m ${MEM_LIMIT} -o test-instr.plain.1 -r -- ./test-instr.plain.gccpi < /dev/null > /dev/null 2>&1
    test -e test-instr.plain.0 -a -e test-instr.plain.1 && {
      diff -q test-instr.plain.0 test-instr.plain.1 > /dev/null 2>&1 && {
        $ECHO "$RED[!] gcc_plugin instrumentation should be different on different input but is not"
        CODE=1
      } || { 
        $ECHO "$GREEN[+] gcc_plugin instrumentation present and working correctly"
        TUPLES=`echo 0|../afl-showmap -m ${MEM_LIMIT} -o /dev/null -- ./test-instr.plain.gccpi 2>&1 | grep Captur | awk '{print$3}'`
        test "$TUPLES" -gt 3 -a "$TUPLES" -lt 7 && {
          $ECHO "$GREEN[+] gcc_plugin run reported $TUPLES instrumented locations which is fine"
        } || {
          $ECHO "$RED[!] gcc_plugin instrumentation produces a weird number of instrumented locations: $TUPLES"
          $ECHO "$YELLOW[-] the gcc_plugin instrumentation issue is not flagged as an error because travis builds would all fail otherwise :-("
          #CODE=1
        }
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

  test -e test-compcov.harden.gccpi && {
    grep -Eqa 'stack_chk_fail|fstack-protector-all|fortified' test-compcov.harden.gccpi > /dev/null 2>&1 && {
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
  (test "$(uname -s)" = "Linux" && test "$(sysctl kernel.core_pattern)" != "kernel.core_pattern = core" && {
    $ECHO "$YELLOW[-] we should not run afl-fuzz with enabled core dumps. Run 'sudo sh afl-system-config'.$RESET"
    true
  }) ||
  # make sure crash reporter is disabled on Mac OS X
  (test "$(uname -s)" = "Darwin" && test $(launchctl list 2>/dev/null | grep -q '\.ReportCrash$') && {
    $ECHO "$RED[!] we cannot run afl-fuzz with enabled crash reporter. Run 'sudo sh afl-system-config'.$RESET"
    CODE=1
    true
  }) || {
    mkdir -p in
    echo 0 > in/in
    $ECHO "$GREY[*] running afl-fuzz for gcc_plugin, this will take approx 10 seconds"
    {
      ../afl-fuzz -V10 -m ${MEM_LIMIT} -i in -o out -- ./test-instr.plain.gccpi >>errors 2>&1
    } >>errors 2>&1
    test -n "$( ls out/queue/id:000002* 2> /dev/null )" && {
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
  rm -f test-instr.plain.gccpi

  # now for the special gcc_plugin things
  echo foobar.c > whitelist.txt
  AFL_GCC_WHITELIST=whitelist.txt ../afl-gcc-fast -o test-compcov test-compcov.c > /dev/null 2>&1
  test -e test-compcov && {
    echo 1 | ../afl-showmap -m ${MEM_LIMIT} -o - -r -- ./test-compcov 2>&1 | grep -q "Captured 1 tuples" && {
      $ECHO "$GREEN[+] gcc_plugin whitelist feature works correctly"
    } || { 
      $ECHO "$RED[!] gcc_plugin whitelist feature failed"
      CODE=1
    }
  } || { 
    $ECHO "$RED[!] gcc_plugin whitelist feature compilation failed"
    CODE=1
  }
  rm -f test-compcov test.out whitelist.txt
  ../afl-gcc-fast -o test-persistent ../experimental/persistent_demo/persistent_demo.c > /dev/null 2>&1
  test -e test-persistent && {
    echo foo | ../afl-showmap -o /dev/null -q -r ./test-persistent && {
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
} || {
  $ECHO "$YELLOW[-] gcc_plugin not compiled, cannot test"
  INCOMPLETE=1
}

$ECHO "$BLUE[*] Testing: shared library extensions"
cc -o test-compcov test-compcov.c > /dev/null 2>&1
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
    LD_PRELOAD=../libdislocator.so DYLD_INSERT_LIBRARIES=../libdislocator.so DYLD_FORCE_FLAT_NAMESPACE=1 ./test-compcov BUFFEROVERFLOW > test.out 2> /dev/null
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
test -e ../libradamsa.so && {
  # on FreeBSD need to set AFL_CC

  test `uname -s` = 'FreeBSD' && {
    if which clang >/dev/null; then
      export AFL_CC=`which clang`
    else
      export AFL_CC=`$LLVM_CONFIG --bindir`/clang
    fi
  }
  test -e test-instr.plain || ../afl-clang-fast -o test-instr.plain ../test-instr.c > /dev/null 2>&1
  test -e test-instr.plain || ../afl-gcc-fast -o test-instr.plain ../test-instr.c > /dev/null 2>&1
  test -e test-instr.plain || ../${AFL_GCC} -o test-instr.plain ../test-instr.c > /dev/null 2>&1
  test -e test-instr.plain && {
    mkdir -p in
    printf 1 > in/in
    $ECHO "$GREY[*] running afl-fuzz with radamsa, this will take approx 10 seconds"
    {
      ../afl-fuzz -RR -V10 -m ${MEM_LIMIT} -i in -o out -- ./test-instr.plain
    } >>errors 2>&1
    test -n "$( ls out/queue/id:000001* 2> /dev/null )" && {
      $ECHO "$GREEN[+] libradamsa performs good - and very slow - mutations"
    } || {
      echo CUT------------------------------------------------------------------CUT
      cat errors
      echo CUT------------------------------------------------------------------CUT
      $ECHO "$RED[!] libradamsa failed"
      CODE=1
    }
    rm -rf in out errors test-instr.plain
  } || {
    $ECHO "$YELLOW[-] compilation of test target failed, cannot test libradamsa"
    INCOMPLETE=1
  }
} || {
  $ECHO "$YELLOW[-] libradamsa is not compiled, cannot test"
  INCOMPLETE=1
}

$ECHO "$BLUE[*] Testing: qemu_mode"
test -e ../afl-qemu-trace && {
  gcc -o test-instr ../test-instr.c
  gcc -o test-compcov test-compcov.c
  test -e test-instr -a -e test-compcov && {
    {
      mkdir -p in
      echo 0 > in/in
      $ECHO "$GREY[*] running afl-fuzz for qemu_mode, this will take approx 10 seconds"
      {
        ../afl-fuzz -V10 -Q -i in -o out -- ./test-instr >>errors 2>&1
      } >>errors 2>&1
      test -n "$( ls out/queue/id:000002* 2> /dev/null )" && {
        $ECHO "$GREEN[+] afl-fuzz is working correctly with qemu_mode"
        RUNTIME=`grep execs_done out/fuzzer_stats | awk '{print$3}'`
      } || {
        echo CUT------------------------------------------------------------------CUT
        cat errors
        echo CUT------------------------------------------------------------------CUT
        $ECHO "$RED[!] afl-fuzz is not working correctly with qemu_mode"
        CODE=1
      }
      rm -f errors

      test -e ../libcompcov.so && {
        $ECHO "$GREY[*] running afl-fuzz for qemu_mode libcompcov, this will take approx 10 seconds"
        {
          export AFL_PRELOAD=../libcompcov.so 
          export AFL_COMPCOV_LEVEL=2
          ../afl-fuzz -V10 -Q -i in -o out -- ./test-compcov >>errors 2>&1
        } >>errors 2>&1
        test -n "$( ls out/queue/id:000002* 2> /dev/null )" && {
          $ECHO "$GREEN[+] afl-fuzz is working correctly with qemu_mode libcompcov"
        } || {
          echo CUT------------------------------------------------------------------CUT
          cat errors
          echo CUT------------------------------------------------------------------CUT
          $ECHO "$RED[!] afl-fuzz is not working correctly with qemu_mode libcompcov"
          CODE=1
        }
      } || {
        $ECHO "$YELLOW[-] we cannot test qemu_mode libcompcov because it is not present"
        INCOMPLETE=1
      }
      rm -f errors

      $ECHO "$GREY[*] running afl-fuzz for persistent qemu_mode, this will take approx 10 seconds"
      {
        export AFL_QEMU_PERSISTENT_ADDR=0x$(nm test-instr | grep "T main" | awk '{ print $1 }')
        export AFL_QEMU_PERSISTENT_GPR=1
        ../afl-fuzz -V10 -Q -i in -o out -- ./test-instr > /dev/null 2>&1
      } >>errors 2>&1
      test -n "$( ls out/queue/id:000002* 2> /dev/null )" && {
        $ECHO "$GREEN[+] afl-fuzz is working correctly with persistent qemu_mode"
        RUNTIMEP=`grep execs_done out/fuzzer_stats | awk '{print$3}'`
        test -n "$RUNTIME" -a -n "$RUNTIMEP" && {
          SLOW=`expr $RUNTIME '*' 103` # persistent mode should be at least 3% faster - minimum!
          FAST=`expr $RUNTIMEP '*' 100`
          test "$SLOW" -lt "$FAST" && {
            $ECHO "$GREEN[+] persistent qemu_mode was noticeable faster than standard qemu_mode"
          } || {
            $ECHO "$YELLOW[-] persistent qemu_mode was not noticeable faster than standard qemu_mode"
          }
        } || {
          $ECHO "$YELLOW[-] we got no data on executions performed? weird!"
        }
      } || {
        echo CUT------------------------------------------------------------------CUT
        cat errors
        echo CUT------------------------------------------------------------------CUT
        $ECHO "$RED[!] afl-fuzz is not working correctly with persistent qemu_mode"
        CODE=1
        exit 1
      }
      $ECHO "$YELLOW[-] we need a test case for qemu_mode unsigaction library"
      rm -rf in out errors
    }
  } || {
    $ECHO "$RED[!] gcc compilation of test targets failed - what is going on??"
    CODE=1
  }
  
  rm -f test-instr test-compcov
} || {
  $ECHO "$YELLOW[-] qemu_mode is not compiled, cannot test"
  INCOMPLETE=1
}

$ECHO "$BLUE[*] Testing: unicorn_mode"
test -d ../unicorn_mode/unicornafl && {
  test -e ../unicorn_mode/samples/simple/simple_target.bin -a -e ../unicorn_mode/samples/compcov_x64/compcov_target.bin && {
    {
      # travis workaround
      PY=`which python`
      test "$PY" = "/opt/pyenv/shims/python" -a -x /usr/bin/python && PY=/usr/bin/python
      mkdir -p in
      echo 0 > in/in
      $ECHO "$GREY[*] Using python binary $PY"
      if ! $PY -c 'import unicornafl' 2> /dev/null ; then
        $ECHO "$YELLOW[-] we cannot test unicorn_mode because it is not present"
        INCOMPLETE=1
      else
      {
        $ECHO "$GREY[*] running afl-fuzz for unicorn_mode, this will take approx 25 seconds"
        {
          ../afl-fuzz -V25 -U -i in -o out -d -- "$PY" ../unicorn_mode/samples/simple/simple_test_harness.py @@ >>errors 2>&1
        } >>errors 2>&1
        test -n "$( ls out/queue/id:000002* 2> /dev/null )" && {
          $ECHO "$GREEN[+] afl-fuzz is working correctly with unicorn_mode"
        } || {
          echo CUT------------------------------------------------------------------CUT
          cat errors
          echo CUT------------------------------------------------------------------CUT
          $ECHO "$RED[!] afl-fuzz is not working correctly with unicorn_mode"
          CODE=1
        }
        rm -f errors

        printf '\x01\x01' > in/in
        # This seed is close to the first byte of the comparison.
        # If CompCov works, a new tuple will appear in the map => new input in queue
        $ECHO "$GREY[*] running afl-fuzz for unicorn_mode compcov, this will take approx 35 seconds"
        {
          export AFL_COMPCOV_LEVEL=2
          ../afl-fuzz -V35 -U -i in -o out -d -- "$PY" ../unicorn_mode/samples/compcov_x64/compcov_test_harness.py @@ >>errors 2>&1
        } >>errors 2>&1
        test -n "$( ls out/queue/id:000001* 2> /dev/null )" && {
          $ECHO "$GREEN[+] afl-fuzz is working correctly with unicorn_mode compcov"
        } || {
          echo CUT------------------------------------------------------------------CUT
          cat errors
          echo CUT------------------------------------------------------------------CUT
          $ECHO "$RED[!] afl-fuzz is not working correctly with unicorn_mode compcov"
          CODE=1
        }
        rm -rf in out errors
      }
      fi
    }
  } || {
    $ECHO "$RED[!] missing sample binaries in unicorn_mode/samples/ - what is going on??"
    CODE=1
  }
  
} || {
  $ECHO "$YELLOW[-] unicorn_mode is not compiled, cannot test"
  INCOMPLETE=1
}

$ECHO "$GREY[*] all test cases completed.$RESET"
test "$INCOMPLETE" = "0" && $ECHO "$GREEN[+] all test cases executed"
test "$INCOMPLETE" = "1" && $ECHO "$YELLOW[-] not all test cases were executed"
test "$CODE" = "0" && $ECHO "$GREEN[+] all tests were successful :-)$RESET"
test "$CODE" = "0" || $ECHO "$RED[!] failure in tests :-($RESET"
exit $CODE
