f#!/bin/sh

. ./test-pre.sh

$ECHO "$BLUE[*] Testing: custom mutator"
test "1" = "`../afl-fuzz | grep -i 'without python' >/dev/null; echo $?`" && {
  # normalize path
  CUSTOM_MUTATOR_PATH=$(cd $(pwd)/../examples/custom_mutators;pwd)
  test -e test-custom-mutator.c -a -e ${CUSTOM_MUTATOR_PATH}/example.c -a -e ${CUSTOM_MUTATOR_PATH}/example.py && {
    unset AFL_CC
    # Compile the vulnerable program for single mutator
    test -e ../afl-clang-fast && {
      ../afl-clang-fast -o test-custom-mutator test-custom-mutator.c > /dev/null 2>&1
    } || {
      test -e ../afl-gcc-fast && {
        ../afl-gcc-fast -o test-custom-mutator test-custom-mutator.c > /dev/null 2>&1
      } || {
        ../afl-gcc -o test-custom-mutator test-custom-mutator.c > /dev/null 2>&1
      }
    }
    # Compile the vulnerable program for multiple mutators
    test -e ../afl-clang-fast && {
      ../afl-clang-fast -o test-multiple-mutators test-multiple-mutators.c > /dev/null 2>&1
    } || {
      test -e ../afl-gcc-fast && {
        ../afl-gcc-fast -o test-multiple-mutators test-multiple-mutators.c > /dev/null 2>&1
      } || {
        ../afl-gcc -o test-multiple-mutators test-multiple-mutators.c > /dev/null 2>&1
      }
    }
    # Compile the custom mutator
    cc -D_FIXED_CHAR=0x41 -g -fPIC -shared -I../include ../examples/custom_mutators/simple_example.c -o libexamplemutator.so > /dev/null 2>&1
    cc -D_FIXED_CHAR=0x42 -g -fPIC -shared -I../include ../examples/custom_mutators/simple_example.c -o libexamplemutator2.so > /dev/null 2>&1
    test -e test-custom-mutator -a -e ./libexamplemutator.so && {
      # Create input directory
      mkdir -p in
      echo "00000" > in/in

      # Run afl-fuzz w/ the C mutator
      $ECHO "$GREY[*] running afl-fuzz for the C mutator, this will take approx 5 seconds"
      {
        AFL_CUSTOM_MUTATOR_LIBRARY=./libexamplemutator.so AFL_CUSTOM_MUTATOR_ONLY=1 ../afl-fuzz -V1 -m ${MEM_LIMIT} -i in -o out -- ./test-custom-mutator >>errors 2>&1
      } >>errors 2>&1

      # Check results
      test -n "$( ls out/default/crashes/id:000000* 2>/dev/null )" && {  # TODO: update here
        $ECHO "$GREEN[+] afl-fuzz is working correctly with the C mutator"
      } || {
        echo CUT------------------------------------------------------------------CUT
        cat errors
        echo CUT------------------------------------------------------------------CUT
        $ECHO "$RED[!] afl-fuzz is not working correctly with the C mutator"
        CODE=1
      }

      # Clean
      rm -rf out errors core.*

      # Run afl-fuzz w/ multiple C mutators
      $ECHO "$GREY[*] running afl-fuzz with multiple custom C mutators, this will take approx 5 seconds"
      {
        AFL_CUSTOM_MUTATOR_LIBRARY="./libexamplemutator.so;./libexamplemutator2.so" AFL_CUSTOM_MUTATOR_ONLY=1 ../afl-fuzz -V1 -m ${MEM_LIMIT} -i in -o out -- ./test-multiple-mutators >>errors 2>&1
      } >>errors 2>&1

      test -n "$( ls out/default/crashes/id:000000* 2>/dev/null )" && {  # TODO: update here
        $ECHO "$GREEN[+] afl-fuzz is working correctly with multiple C mutators"
      } || {
        echo CUT------------------------------------------------------------------CUT
        cat errors
        echo CUT------------------------------------------------------------------CUT
        $ECHO "$RED[!] afl-fuzz is not working correctly with multiple C mutators"
        CODE=1
      }

      # Clean
      rm -rf out errors core.*

      # Run afl-fuzz w/ the Python mutator
      $ECHO "$GREY[*] running afl-fuzz for the Python mutator, this will take approx 5 seconds"
      {
        export PYTHONPATH=${CUSTOM_MUTATOR_PATH}
        export AFL_PYTHON_MODULE=example
        AFL_CUSTOM_MUTATOR_ONLY=1 ../afl-fuzz -V5 -m ${MEM_LIMIT} -i in -o out -- ./test-custom-mutator >>errors 2>&1
        unset PYTHONPATH
        unset AFL_PYTHON_MODULE
      } >>errors 2>&1

      # Check results
      test -n "$( ls out/default/crashes/id:000000* 2>/dev/null )" && {  # TODO: update here
        $ECHO "$GREEN[+] afl-fuzz is working correctly with the Python mutator"
      } || {
        echo CUT------------------------------------------------------------------CUT
        cat errors
        echo CUT------------------------------------------------------------------CUT
        $ECHO "$RED[!] afl-fuzz is not working correctly with the Python mutator"
        CODE=1
      }

      # Clean
      rm -rf in out errors core.*
      rm -rf ${CUSTOM_MUTATOR_PATH}/__pycache__/
      rm -f test-multiple-mutators test-custom-mutator libexamplemutator.so libexamplemutator2.so
    } || {
      ls .
      ls ${CUSTOM_MUTATOR_PATH}
      $ECHO "$RED[!] cannot compile the test program or the custom mutator"
      CODE=1
    }

    #test "$CODE" = 1 && { $ECHO "$YELLOW[!] custom mutator tests currently will not fail travis" ; CODE=0 ; }

    make -C ../examples/custom_mutators clean > /dev/null 2>&1
    rm -f test-custom-mutator
    rm -f test-custom-mutators
  } || {
    $ECHO "$YELLOW[-] no custom mutators in $CUSTOM_MUTATOR_PATH, cannot test"
    INCOMPLETE=1
  }
  unset CUSTOM_MUTATOR_PATH
} || {
  $ECHO "$YELLOW[-] no python support in afl-fuzz, cannot test"
  INCOMPLETE=1
}

. ./test-post.sh
