#!/bin/bash
# test/test-shmem.sh
#
# Combined CMPLOG + IJON + BUG regression that also checks shared-memory
# hygiene. CMPLOG cracks the magic header, IJON max-feedback is the only
# gradient for the branchless lock, and the BUG ALLOCSIZE oracle produces the
# fault. That oracle reports a hit via _exit(134) (an exit code, not a signal),
# so afl-fuzz needs AFL_CRASH_EXITCODE to treat it as a crash; 134 is outside
# the accepted -127..128 range and is therefore passed as its signed-byte
# equivalent -122 ((u8)-122 == 134). This script asserts:
#   a) a crash is found within 20s and reproduces the ALLOCSIZE bug oracle;
#   b) afl-fuzz leaves no shared-memory segment dormant when it exits
#      (SysV via ipcs and POSIX via /dev/shm are both checked).

. ./test-pre.sh

$ECHO "$BLUE[*] Testing: CMPLOG + IJON + BUG combined run and shmem cleanup"

test_shmem() {

  CC=../afl-clang-fast

  test -x "$CC" || {
    $ECHO "$YELLOW[-] afl-clang-fast not built, skipping"
    INCOMPLETE=1
    return
  }
  test -e ../afl-llvm-bug-pass.so || {
    $ECHO "$YELLOW[-] afl-llvm-bug-pass.so not built, skipping"
    INCOMPLETE=1
    return
  }
  test -e ../afl-llvm-ijon-pass.so || {
    $ECHO "$YELLOW[-] afl-llvm-ijon-pass.so not built, skipping"
    INCOMPLETE=1
    return
  }

  case "$SYS" in
    i686 | x86_64 | amd64) ;;
    *)
      $ECHO "$YELLOW[-] CMPLOG too slow off x86 to solve this in 20s, skipping"
      INCOMPLETE=1
      return
      ;;
  esac

  unset AFL_USE_ASAN AFL_USE_MSAN AFL_USE_UBSAN AFL_USE_TSAN AFL_USE_LSAN
  unset AFL_CMPLOG_ONLY_NEW

  rm -f test-shmem
  AFL_QUIET=1 AFL_LLVM_CMPLOG=1 AFL_LLVM_IJON=1 AFL_LLVM_BUG_ALLOCSIZE=1 \
    "$CC" -fsanitize=fuzzer -O0 test-shmem.c -o test-shmem >test-shmem.cc.log 2>&1
  test -x ./test-shmem || {
    $ECHO "$RED[!] compilation of test-shmem.c failed"
    cat test-shmem.cc.log
    CODE=1
    rm -f test-shmem.cc.log
    return
  }
  rm -f test-shmem.cc.log

  ME=$(id -un)
  ipcs -m 2>/dev/null | awk -v me="$ME" '$3 == me { print $2 }' | sort \
    >.shm_sysv_before
  ls /dev/shm 2>/dev/null | grep -E '^afl_' | sort >.shm_posix_before

  rm -rf in out
  mkdir -p in
  printf 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' >in/seed

  $ECHO "$GREY[*] running afl-fuzz for up to 20s (CMPLOG -c 0 + IJON + BUG)"
  AFL_CRASH_EXITCODE=-122 AFL_BENCH_UNTIL_CRASH=1 AFL_NO_CRASH_README=1 \
    AFL_NO_UI=1 AFL_SKIP_CPUFREQ=1 \
    ../afl-fuzz -s 1 -i in -o out -V 20 -c 0 -- ./test-shmem >fuzz.log 2>&1
  fz=$?

  crash=$(ls out/default/crashes/ 2>/dev/null | grep -c '^id:')
  if [ "${crash:-0}" -ge 1 ]; then

    cfile=$(ls out/default/crashes/id:* 2>/dev/null | head -n1)
    if ./test-shmem "$cfile" 2>&1 | grep -q '\[afl-bug\] ALLOCSIZE'; then
      $ECHO "$GREEN[+] crash reproduces the BUG ALLOCSIZE oracle"
    else
      $ECHO "$RED[!] crash found but it is not the ALLOCSIZE bug oracle"
      CODE=1
    fi

  else

    $ECHO "$RED[!] no crash in 20s (rc=$fz): CMPLOG+IJON+BUG did not reach the bug"
    tail -20 fuzz.log
    CODE=1

  fi

  ipcs -m 2>/dev/null | awk -v me="$ME" '$3 == me { print $2 }' | sort \
    >.shm_sysv_after
  ls /dev/shm 2>/dev/null | grep -E '^afl_' | sort >.shm_posix_after
  leak_sysv=$(comm -13 .shm_sysv_before .shm_sysv_after)
  leak_posix=$(comm -13 .shm_posix_before .shm_posix_after)

  if [ -n "$leak_sysv" ] || [ -n "$leak_posix" ]; then

    $ECHO "$RED[!] shared memory left behind after afl-fuzz exited:"
    test -n "$leak_sysv" && $ECHO "$RED    dormant SysV shmid(s): $(echo $leak_sysv)"
    test -n "$leak_posix" && $ECHO "$RED    dormant /dev/shm: $(echo $leak_posix)"
    CODE=1

  else

    $ECHO "$GREEN[+] no dormant shared memory after exit (SysV + /dev/shm clean)"

  fi

  rm -rf in out test-shmem fuzz.log \
    .shm_sysv_before .shm_sysv_after .shm_posix_before .shm_posix_after

}

test_shmem

. ./test-post.sh
