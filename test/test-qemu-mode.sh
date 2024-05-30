#!/bin/sh

. ./test-pre.sh

$ECHO "$BLUE[*] Testing: qemu_mode"
test -z "$AFL_CC" && {
  if type gcc >/dev/null; then
    export AFL_CC=gcc
  else
    if type clang >/dev/null; then
      export AFL_CC=clang
    fi
  fi
}

test -e ../afl-qemu-trace && {
  cc -pie -fPIE -o test-instr ../test-instr.c
  cc -o test-compcov test-compcov.c
  test -e test-instr -a -e test-compcov && {
    {
      mkdir -p in
      echo 00000 > in/in
      $ECHO "$GREY[*] running afl-fuzz for qemu_mode, this will take approx 10 seconds"
      {
        ../afl-fuzz -m ${MEM_LIMIT} -V07 -Q -i in -o out -- ./test-instr >>errors 2>&1
      } >>errors 2>&1
      test -n "$( ls out/default/queue/id:000002* 2>/dev/null )" && {
        $ECHO "$GREEN[+] afl-fuzz is working correctly with qemu_mode"
        RUNTIME=`grep execs_done out/default/fuzzer_stats | awk '{print$3}'`
      } || {
        echo CUT------------------------------------------------------------------CUT
        cat errors
        echo CUT------------------------------------------------------------------CUT
        $ECHO "$RED[!] afl-fuzz is not working correctly with qemu_mode"
        CODE=1
      }
      rm -f errors

      $ECHO "$GREY[*] running afl-fuzz for qemu_mode AFL_ENTRYPOINT, this will take approx 6 seconds"
      {
        {
          export AFL_ENTRYPOINT=`printf 1 | AFL_DEBUG=1 ../afl-qemu-trace ./test-instr 2>&1 >/dev/null | awk '/forkserver/{print $4; exit}'`
          $ECHO AFL_ENTRYPOINT=$AFL_ENTRYPOINT - $(nm test-instr | grep "T main") - $(file ./test-instr)
          ../afl-fuzz -m ${MEM_LIMIT} -V2 -Q -i in -o out -- ./test-instr
          unset AFL_ENTRYPOINT
        } >>errors 2>&1
      } >>errors 2>&1
      test -n "$( ls out/default/queue/id:000001* 2>/dev/null )" && {
        $ECHO "$GREEN[+] afl-fuzz is working correctly with qemu_mode AFL_ENTRYPOINT"
        RUNTIME=`grep execs_done out/default/fuzzer_stats | awk '{print$3}'`
      } || {
        echo CUT------------------------------------------------------------------CUT
        cat errors
        echo CUT------------------------------------------------------------------CUT
        $ECHO "$RED[!] afl-fuzz is not working correctly with qemu_mode AFL_ENTRYPOINT"
        CODE=1
      }
      rm -f errors

      test "$SYS" = "i686" -o "$SYS" = "x86_64" -o "$SYS" = "amd64" -o "$SYS" = "i86pc" -o "$SYS" = "aarch64" -o ! "${SYS%%arm*}" && {
        test -e ../libcompcov.so && {
          $ECHO "$GREY[*] running afl-fuzz for qemu_mode compcov, this will take approx 10 seconds"
          {
            export AFL_PRELOAD=../libcompcov.so
            export AFL_COMPCOV_LEVEL=2
            AFL_NO_UI=1 ../afl-fuzz -V07 -Q -i in -o out -- ./test-compcov 2>&1
            unset AFL_PRELOAD
            unset AFL_COMPCOV_LEVEL
          } >>errors 2>&1
          test -n "$( ls out/default/queue/id:000001* 2>/dev/null )" && {
            $ECHO "$GREEN[+] afl-fuzz is working correctly with qemu_mode compcov"
          } || {
            echo CUT------------------------------------------------------------------CUT
            cat errors
            echo CUT------------------------------------------------------------------CUT
            $ECHO "$RED[!] afl-fuzz is not working correctly with qemu_mode compcov"
            CODE=1
          }
        } || {
          $ECHO "$YELLOW[-] we cannot test qemu_mode compcov because it is not present"
          INCOMPLETE=1
        }
        rm -f errors
      } || {
       $ECHO "$YELLOW[-] not an intel or arm platform, cannot test qemu_mode compcov"
      }
      
      test "$SYS" = "i686" -o "$SYS" = "x86_64" -o "$SYS" = "amd64" -o "$SYS" = "i86pc" -o "$SYS" = "aarch64" -o ! "${SYS%%arm*}" && {
        $ECHO "$GREY[*] running afl-fuzz for qemu_mode cmplog, this will take approx 10 seconds"
        {
          ../afl-fuzz -V07 -Q -c 0 -l 3 -i in -o out -- ./test-compcov >>errors 2>&1
        } >>errors 2>&1
        test -n "$( ls out/default/queue/id:000001* 2>/dev/null )" && {
          $ECHO "$GREEN[+] afl-fuzz is working correctly with qemu_mode cmplog"
        } || {
          echo CUT------------------------------------------------------------------CUT
          cat errors
          echo CUT------------------------------------------------------------------CUT
          $ECHO "$RED[!] afl-fuzz is not working correctly with qemu_mode cmplog"
          CODE=1
        }
        rm -f errors
      } || {
       $ECHO "$YELLOW[-] not an intel or arm platform, cannot test qemu_mode cmplog"
      }

      test "$SYS" = "i686" -o "$SYS" = "x86_64" -o "$SYS" = "amd64" -o "$SYS" = "i86pc" -o "$SYS" = "aarch64" -o ! "${SYS%%arm*}" && {
        $ECHO "$GREY[*] running afl-fuzz for persistent qemu_mode, this will take approx 10 seconds"
        {
          IS_STATIC=""
          file test-instr | grep -q 'statically linked' && IS_STATIC=1
          test -z "$IS_STATIC" && {
            if file test-instr | grep -q "32-bit"; then
              # for 32-bit reduce 8 nibbles to the lower 7 nibbles
  	      ADDR_LOWER_PART=`nm test-instr | grep "T main" | awk '{print $1}' | sed 's/^.//'`
            else
              # for 64-bit reduce 16 nibbles to the lower 9 nibbles
  	      ADDR_LOWER_PART=`nm test-instr | grep "T main" | awk '{print $1}' | sed 's/^.......//'`
            fi
            export AFL_QEMU_PERSISTENT_ADDR=`expr 0x4${ADDR_LOWER_PART}`
          }
          test -n "$IS_STATIC" && {
            export AFL_QEMU_PERSISTENT_ADDR=0x`nm test-instr | grep "T main" |  awk '{print $1}'`
          }
          export AFL_QEMU_PERSISTENT_GPR=1
          $ECHO "Info: AFL_QEMU_PERSISTENT_ADDR=$AFL_QEMU_PERSISTENT_ADDR <= $(nm test-instr | grep "T main" | awk '{print $1}')"
          env|grep AFL_|sort
          file test-instr
          ../afl-fuzz -m ${MEM_LIMIT} -V07 -Q -i in -o out -- ./test-instr
          unset AFL_QEMU_PERSISTENT_ADDR
        } >>errors 2>&1
        test -n "$( ls out/default/queue/id:000002* 2>/dev/null )" && {
          $ECHO "$GREEN[+] afl-fuzz is working correctly with persistent qemu_mode"
          RUNTIMEP=`grep execs_done out/default/fuzzer_stats | awk '{print$3}'`
          test -n "$RUNTIME" -a -n "$RUNTIMEP" && {
            DIFF=`expr $RUNTIMEP / $RUNTIME`
            test "$DIFF" -gt 1 && { # must be at least twice as fast
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
        }
        rm -rf in out errors
      } || {
       $ECHO "$YELLOW[-] not an intel or arm platform, cannot test persistent qemu_mode"
      }

      test -e ../qemu_mode/unsigaction/unsigaction32.so && {
        ${AFL_CC} -o test-unsigaction32 -m32 test-unsigaction.c >> errors 2>&1 && {
	  ./test-unsigaction32
          RETVAL_NORMAL32=$?
	  LD_PRELOAD=../qemu_mode/unsigaction/unsigaction32.so ./test-unsigaction32
          RETVAL_LIBUNSIGACTION32=$?
	  test $RETVAL_NORMAL32 = "2" -a $RETVAL_LIBUNSIGACTION32 = "0" && {
            $ECHO "$GREEN[+] qemu_mode unsigaction library (32 bit) ignores signals"
	  } || {
	    test $RETVAL_NORMAL32 != "2" && {
	      $ECHO "$RED[!] cannot trigger signal in test program (32 bit)"
	    }
	    test $RETVAL_LIBUNSIGACTION32 != "0" && {
	      $ECHO "$RED[!] signal in test program (32 bit) is not ignored with unsigaction"
	    }
            CODE=1
          }
        } || {
	  $ECHO "$YELLOW[-] cannot compile test program (32 bit) for unsigaction library"
          INCOMPLETE=1
        }
      } || {
        $ECHO "$YELLOW[-] we cannot test qemu_mode unsigaction library (32 bit) because it is not present"
        INCOMPLETE=1
      }
      test -e ../qemu_mode/unsigaction/unsigaction64.so && {
        ${AFL_CC} -o test-unsigaction64 -m64 test-unsigaction.c >> errors 2>&1 && {
	  ./test-unsigaction64
          RETVAL_NORMAL64=$?
	  LD_PRELOAD=../qemu_mode/unsigaction/unsigaction64.so ./test-unsigaction64
          RETVAL_LIBUNSIGACTION64=$?
	  test $RETVAL_NORMAL64 = "2" -a $RETVAL_LIBUNSIGACTION64 = "0" && {
            $ECHO "$GREEN[+] qemu_mode unsigaction library (64 bit) ignores signals"
	  } || {
	    test $RETVAL_NORMAL64 != "2" && {
	      $ECHO "$RED[!] cannot trigger signal in test program (64 bit)"
	    }
	    test $RETVAL_LIBUNSIGACTION64 != "0" && {
	      $ECHO "$RED[!] signal in test program (64 bit) is not ignored with unsigaction"
	    }
            CODE=1
          }
          unset LD_PRELOAD
        } || {
	  $ECHO "$YELLOW[-] cannot compile test program (64 bit) for unsigaction library"
          INCOMPLETE=1
        }
      } || {
        $ECHO "$YELLOW[-] we cannot test qemu_mode unsigaction library (64 bit) because it is not present"
        INCOMPLETE=1
      }
      rm -rf errors test-unsigaction32 test-unsigaction64
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

. ./test-post.sh
