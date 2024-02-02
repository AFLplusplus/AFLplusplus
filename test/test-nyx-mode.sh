#!/bin/sh

. ./test-pre.sh

$ECHO "$BLUE[*] Testing: nyx_mode"

test "$CI" = "true" && {
  $ECHO "$YELLOW[-] nyx_mode cannot be tested in the Github CI, skipping ..."
  exit 0
}

unset AFL_CC

test -e ../libnyx.so && {
  ../afl-cc -o test-instr ../test-instr.c > errors 2>&1
  test -e test-instr && {
    {
      rm -rf nyx-test in out
      $ECHO "$GREY[*] running nyx_packer"
      python3 ../nyx_mode/packer/packer/nyx_packer.py \
        ./test-instr \
        nyx-test \
        afl \
        instrumentation \
        --fast_reload_mode \
        --purge > /dev/null 2>&1

      test -e nyx-test/test-instr && {

        $ECHO "$GREY[*] running nyx_config_gen"
        python3 ../nyx_mode/packer/packer/nyx_config_gen.py nyx-test Kernel > /dev/null 2>&1
        
        test -e nyx-test/config.ron && {
          sudo modprobe -r kvm-intel
          sudo modprobe -r kvm
          sudo modprobe  kvm enable_vmware_backdoor=y
          sudo modprobe  kvm-intel
          #cat /sys/module/kvm/parameters/enable_vmware_backdoor 

          mkdir -p in
          echo 00000 > in/in
          $ECHO "$GREY[*] running afl-fuzz for nyx_mode, this will take approx 10 seconds"
          {
            AFL_DEBUG=1 ../afl-fuzz -i in -o out -V05 -X -- ./nyx-test >>errors 2>&1
          } >>errors 2>&1
          test -n "$( ls out/default/queue/id:000002* 2>/dev/null )" && {
            $ECHO "$GREEN[+] afl-fuzz is working correctly with nyx_mode"
            RUNTIME=`grep execs_done out/default/fuzzer_stats | awk '{print$3}'`
            rm -rf errors nyx-test test-instr in out
          } || {
            echo CUT------------------------------------------------------------------CUT
            cat errors
            echo CUT------------------------------------------------------------------CUT
            $ECHO "$RED[!] afl-fuzz is not working correctly with nyx_mode"
            CODE=1
          }
        } || {
          $ECHO "$RED[!] nyx_packer failed, likely install requirements not met."
          CODE=1
        }
      } || {
       $ECHO "$RED[!] nyx_packer failed, likely install requirements not met."
       CODE=1
      }
      #rm -rf test-instr in out errors nyx-test
    }
  } || {
    echo CUT------------------------------------------------------------------CUT
    cat errors
    echo CUT------------------------------------------------------------------CUT
    $ECHO "$RED[!] afl-cc compilation of test targets failed - what is going on??"
    CODE=1
  }
} || {
  $ECHO "$YELLOW[-] nyx_mode is not compiled, cannot test"
  INCOMPLETE=1
}

. ./test-post.sh
