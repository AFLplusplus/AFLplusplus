#!/bin/sh

. ./test-pre.sh

$ECHO "$GREY[*] running value-profile capability regression check"

rm -rf in out out_nofork test-value-profile-no-vp test-value-profile-vp \
  test-vp-marker-a.o test-vp-marker-b.o test-vp-marker-combined.o \
  vp_plain_missing_support.log vp_nofork.log vp_marker_link.log \
  vp_nonllvm.log vp_nonllvm.o
mkdir -p in
echo 00000000 > in/in

vp_nonllvm_rc=0
AFL_CC_COMPILER=GCC_PLUGIN AFL_LLVM_VALUE_PROFILE=1 \
  ../afl-cc -c test-value-profile.c -o vp_nonllvm.o \
  >vp_nonllvm.log 2>&1 || vp_nonllvm_rc=$?

../afl-clang-fast -O0 -fno-inline -fno-builtin -o test-value-profile-no-vp \
  test-value-profile.c > /dev/null 2>&1
AFL_LLVM_VALUE_PROFILE=1 ../afl-clang-fast -O0 -fno-inline -fno-builtin \
  -o test-value-profile-vp test-value-profile.c > /dev/null 2>&1
AFL_LLVM_VALUE_PROFILE=1 ../afl-clang-fast -O0 -fno-inline -fno-builtin \
  -Dmain=vp_marker_a -DLLVMFuzzerTestOneInput=vp_input_a \
  -c test-value-profile.c -o test-vp-marker-a.o \
  > /dev/null 2>&1
AFL_LLVM_VALUE_PROFILE=1 ../afl-clang-fast -O0 -fno-inline -fno-builtin \
  -Dmain=vp_marker_b -DLLVMFuzzerTestOneInput=vp_input_b \
  -c test-value-profile.c -o test-vp-marker-b.o \
  > /dev/null 2>&1

test -e test-value-profile-no-vp -a -e test-value-profile-vp -a \
  -e test-vp-marker-a.o -a -e test-vp-marker-b.o && {
  vp_plain_missing_support_rc=0
  vp_nofork_rc=0
  vp_marker_link_rc=0

  cc -r test-vp-marker-a.o test-vp-marker-b.o -o test-vp-marker-combined.o \
    >vp_marker_link.log 2>&1 || vp_marker_link_rc=$?

  AFL_NO_UI=1 AFL_NO_CRASH_README=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
    ../afl-fuzz -r0 -m none -V4 -i in -o out -- ./test-value-profile-no-vp \
    >vp_plain_missing_support.log 2>&1 || vp_plain_missing_support_rc=$?

  AFL_NO_FORKSRV=1 AFL_NO_UI=1 AFL_NO_CRASH_README=1 \
    AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
    ../afl-fuzz -r0 -m none -V4 -i in -o out_nofork -- \
    ./test-value-profile-vp >vp_nofork.log 2>&1 || vp_nofork_rc=$?

  test "$vp_marker_link_rc" -eq 0 &&
  test "$vp_nonllvm_rc" -ne 0 &&
  grep -q "AFL_LLVM_VALUE_PROFILE requires an LLVM compiler mode" \
    vp_nonllvm.log &&
  test -e test-vp-marker-combined.o &&
  test "$vp_plain_missing_support_rc" -ne 0 &&
  test "$vp_nofork_rc" -ne 0 &&
  grep -q "Value profiling requires target support for value profile runtime SHM" \
    vp_plain_missing_support.log &&
  ! grep -q "Using VALUE PROFILE feature" vp_plain_missing_support.log &&
  grep -q "Value profiling (-r) requires the target forkserver" \
    vp_nofork.log &&
  ! grep -q "requires target support for value profile runtime SHM" \
    vp_nofork.log && {
    $ECHO "$GREEN[+] value-profile capability regression check passed"
  } || {
    echo CUT------------------------------------------------------------------CUT
    cat vp_plain_missing_support.log
    echo CUT------------------------------------------------------------------CUT
    cat vp_nofork.log
    echo CUT------------------------------------------------------------------CUT
    cat vp_nonllvm.log
    echo CUT------------------------------------------------------------------CUT
    $ECHO "$RED[!] value-profile capability regression check failed"
    CODE=1
  }
} || {
  $ECHO "$YELLOW[-] we cannot run the value-profile capability regression check because compilation failed"
  INCOMPLETE=1
}

rm -rf in out out_nofork test-value-profile-no-vp test-value-profile-vp \
  test-vp-marker-a.o test-vp-marker-b.o test-vp-marker-combined.o \
  vp_plain_missing_support.log vp_nofork.log vp_marker_link.log \
  vp_nonllvm.log vp_nonllvm.o core.*

. ./test-post.sh
