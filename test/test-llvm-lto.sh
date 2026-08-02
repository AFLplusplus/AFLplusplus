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

  LTO_CLANG=`$LLVM_CONFIG --bindir`/clang
  test -x "$LTO_CLANG" || LTO_CLANG=clang
  LTO_LD_FLAGS="-fuse-ld=lld"
  test -x "`$LLVM_CONFIG --bindir`/ld.lld" && {
    LTO_LD_FLAGS="-fuse-ld=lld --ld-path=`$LLVM_CONFIG --bindir`/ld.lld"
  }

  rm -f test-instr.plain
  AFL_DEBUG=1 ../afl-clang-lto -o test-instr.plain ../test-instr.c > test-lto.out 2>&1
  test -e test-instr.plain && {
    chmod +x test-instr.plain
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
    echo CUT------------------------------------------------------------------CUT
    cat test-lto.out
    echo CUT------------------------------------------------------------------CUT
    $ECHO "$RED[!] LTO llvm_mode failed"
    CODE=1
  }
  rm -f test-instr.plain test-lto.out

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
    echo CUT------------------------------------------------------------------CUT
    cat test.out
    echo CUT------------------------------------------------------------------CUT
    $ECHO "$RED[!] llvm_mode LTO instrumentlist feature compilation failed"
    CODE=1
  }
  rm -f test-compcov test.out instrumentlist.txt
  AFL_DEBUG=1 ../afl-clang-lto -o test-persistent ../utils/persistent_mode/persistent_demo.c > test-lto.out 2>&1
  test -e test-persistent && {
    echo foo | AFL_QUIET=1 ../afl-showmap -m none -o /dev/null -q -r ./test-persistent && {
      $ECHO "$GREEN[+] llvm_mode LTO persistent mode feature works correctly"
    } || {
      $ECHO "$RED[!] llvm_mode LTO persistent mode feature failed to work"
      CODE=1
    }
  } || {
    echo CUT------------------------------------------------------------------CUT
    cat test-lto.out
    echo CUT------------------------------------------------------------------CUT
    $ECHO "$RED[!] llvm_mode LTO persistent mode feature compilation failed"
    CODE=1
  }
  rm -f test-persistent test-lto.out

  # Test runtime value profiling in LTO mode
  test "$SYS" = "i686" -o "$SYS" = "x86_64" -o "$SYS" = "amd64" && {
    rm -f test-value-profile-switch.lto test-value-profile-switch-128.lto \
      test-value-profile-slot-spill.lto \
      test-value-profile-routine.lto test-value-profile-hookn.lto \
      test-value-profile-float-semantics.lto \
      test-value-profile-weak-guard-lto \
      test-value-profile-weak-guard-lto.o \
      test-value-profile-weak-guard-stubs-lto.o \
      test-value-profile-dlopen.lto.so test-dlopen.lto test-vp-lto.out \
      vp_weak_guard_lto.log
    vp_dlopen_libs=
    test `uname -s` = 'Linux' && vp_dlopen_libs=-ldl
    AFL_LLVM_VALUE_PROFILE=1 ../afl-clang-lto -O0 -fno-inline -fno-builtin \
      -o test-value-profile-switch.lto test-value-profile-switch.c \
      > test-vp-lto.out 2>&1
    vp_switch128_ok=1
    if [ "$SYS" = "x86_64" -o "$SYS" = "amd64" ]; then
      AFL_LLVM_VALUE_PROFILE=1 ../afl-clang-lto -O0 -fno-inline \
        -fno-builtin -o test-value-profile-switch-128.lto \
        test-value-profile-switch-128.c >> test-vp-lto.out 2>&1 || \
        vp_switch128_ok=0
    fi
    AFL_LLVM_VALUE_PROFILE=1 ../afl-clang-lto -O0 -fno-inline -fno-builtin \
      -o test-value-profile-slot-spill.lto test-value-profile-slot-spill.c \
      >> test-vp-lto.out 2>&1
    AFL_LLVM_VALUE_PROFILE=1 ../afl-clang-lto -O0 -fno-inline -fno-builtin \
      -o test-value-profile-routine.lto test-value-profile-routine.c \
      >> test-vp-lto.out 2>&1
    AFL_LLVM_VALUE_PROFILE=1 ../afl-clang-lto -O0 -fno-inline -fno-builtin \
      -o test-value-profile-hookn.lto test-value-profile-hookn.c \
      >> test-vp-lto.out 2>&1
    AFL_LLVM_VALUE_PROFILE=1 ../afl-clang-lto -O0 -fno-inline -fno-builtin \
      -o test-value-profile-float-semantics.lto \
      test-value-profile-float-semantics.c >> test-vp-lto.out 2>&1
    AFL_LLVM_VALUE_PROFILE=1 ../afl-clang-lto -O0 -fno-inline -fno-builtin \
      -shared -fPIC -o test-value-profile-dlopen.lto.so \
      test-value-profile-dlopen-target.c >> test-vp-lto.out 2>&1
    AFL_LLVM_VALUE_PROFILE=1 ../afl-clang-lto -o test-dlopen.lto \
      test-dlopen.c ${vp_dlopen_libs} >> test-vp-lto.out 2>&1
    AFL_LLVM_VALUE_PROFILE=1 ../afl-clang-lto -O0 -fno-inline -fno-builtin \
      -c test-value-profile-weak-guard.c \
      -o test-value-profile-weak-guard-lto.o >> test-vp-lto.out 2>&1
    $LTO_CLANG -O0 -flto -c test-value-profile-weak-guard-stubs.c \
      -o test-value-profile-weak-guard-stubs-lto.o >> test-vp-lto.out 2>&1
    weak_guard_link_rc=0
    $LTO_CLANG -O0 -flto $LTO_LD_FLAGS \
      test-value-profile-weak-guard-lto.o \
      test-value-profile-weak-guard-stubs-lto.o \
      -o test-value-profile-weak-guard-lto >vp_weak_guard_lto.log 2>&1 || \
      weak_guard_link_rc=$?
    test -e test-value-profile-switch.lto -a \
      -e test-value-profile-slot-spill.lto -a \
      -e test-value-profile-routine.lto -a \
      -e test-value-profile-hookn.lto -a \
      -e test-value-profile-float-semantics.lto -a \
      -e test-value-profile-dlopen.lto.so -a \
      -e test-dlopen.lto -a \
      -e test-value-profile-weak-guard-lto.o -a \
      -e test-value-profile-weak-guard-stubs-lto.o && \
      test "$vp_switch128_ok" -eq 1 && {
      ./test-value-profile-switch.lto >> test-vp-lto.out 2>&1
      if test -e test-value-profile-switch-128.lto; then
        ./test-value-profile-switch-128.lto >> test-vp-lto.out 2>&1
      fi
      ./test-value-profile-slot-spill.lto >> test-vp-lto.out 2>&1
      ./test-value-profile-routine.lto >> test-vp-lto.out 2>&1
      ./test-value-profile-hookn.lto >> test-vp-lto.out 2>&1
      ./test-value-profile-float-semantics.lto >> test-vp-lto.out 2>&1
      vp_dlopen_rc=0
      DYLD_INSERT_LIBRARIES=./test-value-profile-dlopen.lto.so \
      LD_BIND_NOW=1 \
      LD_PRELOAD=./test-value-profile-dlopen.lto.so \
      TEST_DLOPEN_TARGET=./test-value-profile-dlopen.lto.so AFL_QUIET=1 \
      ./test-dlopen.lto >> test-vp-lto.out 2>&1 || vp_dlopen_rc=$?
      test "$weak_guard_link_rc" -ne 0 -a \
        "$vp_dlopen_rc" -eq 0 -a \
        `grep -c "__afl_vp_enabled_ptr" vp_weak_guard_lto.log` -gt 0 && {
        $ECHO "$GREEN[+] llvm_mode LTO runtime value profiling checks passed"
      } || {
        echo CUT------------------------------------------------------------------CUT
        cat test-vp-lto.out
        cat vp_weak_guard_lto.log
        echo CUT------------------------------------------------------------------CUT
        $ECHO "$RED[!] llvm_mode LTO runtime value profiling checks failed"
        CODE=1
      }
    } || {
      echo CUT------------------------------------------------------------------CUT
      cat test-vp-lto.out
      echo CUT------------------------------------------------------------------CUT
      $ECHO "$RED[!] llvm_mode LTO runtime value profiling compilation failed"
      CODE=1
    }
    rm -f test-value-profile-switch.lto test-value-profile-switch-128.lto \
      test-value-profile-slot-spill.lto \
      test-value-profile-routine.lto test-value-profile-hookn.lto \
      test-value-profile-float-semantics.lto \
      test-value-profile-weak-guard-lto \
      test-value-profile-weak-guard-lto.o \
      test-value-profile-weak-guard-stubs-lto.o \
      test-value-profile-dlopen.lto.so test-dlopen.lto test-vp-lto.out \
      vp_weak_guard_lto.log
  }
} || {
  $ECHO "$YELLOW[-] LTO llvm_mode not compiled, cannot test"
  INCOMPLETE=1
}

. ./test-post.sh
