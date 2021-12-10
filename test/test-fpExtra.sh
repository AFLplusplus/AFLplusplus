#!/bin/sh

. ./test-pre.sh

test -e ../afl-clang-fast -a -e ../split-switches-pass.so && {
  $ECHO "$GREY[*] llvm_mode laf-intel/compcov testing splitting floating point types with Nan, infinity, minusZero"
  for testcase in ./test-fp_minusZerocases.c ./test-fp_Infcases.c ./test-fp_NaNcases.c; do
  #for testcase in ./test-fp_cases.c ./test-fp_Infcases.c ./test-fp_NaNcases.c ./test-fp_minusZerocases.c ; do
    for I in float double "long double"; do
    #for I in double; do
      for BITS in 64 32 16 8; do
      #for BITS in 64; do
        bin="$testcase-split-$I-$BITS.compcov" 
#AFL_DONT_OPTIMIZE=1 AFL_LLVM_INSTRUMENT=AFL AFL_DEBUG=1 AFL_LLVM_LAF_SPLIT_COMPARES_BITW=$BITS AFL_LLVM_LAF_SPLIT_COMPARES=1 AFL_LLVM_LAF_SPLIT_FLOATS=1 ../afl-clang-fast -DFLOAT_TYPE="$I" -S "$testcase"
#AFL_DONT_OPTIMIZE=1 AFL_LLVM_INSTRUMENT=AFL AFL_DEBUG=1 AFL_LLVM_LAF_SPLIT_COMPARES_BITW=$BITS AFL_LLVM_LAF_SPLIT_COMPARES=1 AFL_LLVM_LAF_SPLIT_FLOATS=1 ../afl-clang-fast -DFLOAT_TYPE="$I" -S -emit-llvm "$testcase"
AFL_DONT_OPTIMIZE=1 AFL_LLVM_INSTRUMENT=AFL AFL_DEBUG=1 AFL_LLVM_LAF_SPLIT_COMPARES_BITW=$BITS AFL_LLVM_LAF_SPLIT_COMPARES=1 AFL_LLVM_LAF_SPLIT_FLOATS=1 ../afl-clang-fast -DFLOAT_TYPE="$I" -o "$bin" "$testcase" > test.out 2>&1;
        if ! test -e "$bin"; then
            cat test.out
            $ECHO "$RED[!] llvm_mode laf-intel/compcov float splitting failed! ($testcase with type $I split to $BITS)!";
            CODE=1
            break
        fi
        if ! "$bin"; then
            $ECHO "$RED[!] llvm_mode laf-intel/compcov float splitting resulted in miscompilation (type $I split to $BITS)!";
            CODE=1
            break
        fi
        rm -f "$bin" test.out || true
      done
    done
  done
  rm -f test-fp_cases*.compcov test.out

} || {
  $ECHO "$YELLOW[-] llvm_mode not compiled, cannot test"
  INCOMPLETE=1
}

. ./test-post.sh
