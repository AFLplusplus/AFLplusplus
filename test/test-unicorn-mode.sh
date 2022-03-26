#!/bin/sh

. ./test-pre.sh

$ECHO "$BLUE[*] Testing: unicorn_mode"
test -d ../unicorn_mode/unicornafl -a -e ../unicorn_mode/unicornafl/Makefile && {
  test -e ../unicorn_mode/samples/python_simple/simple_target.bin -a -e ../unicorn_mode/samples/compcov_x64/compcov_target.bin && {
    {
      # We want to see python errors etc. in logs, in case something doesn't work
      export AFL_DEBUG_CHILD=1

      # some python version should be available now
      PYTHONS="`command -v python3` `command -v python` `command -v python2`"
      EASY_INSTALL_FOUND=0
      for PYTHON in $PYTHONS ; do

        if $PYTHON -c "import setuptools" ; then

            EASY_INSTALL_FOUND=1
            PY=$PYTHON
            break

        fi

      done
      if [ "0" = $EASY_INSTALL_FOUND ]; then

        echo "[-] Error: Python setup-tools not found. Run 'sudo apt-get install python-setuptools'."
        PREREQ_NOTFOUND=1

      fi


      cd ../unicorn_mode/samples/persistent
      make >>errors 2>&1
      $ECHO "$GREY[*] running afl-fuzz for unicorn_mode (persistent), this will take approx 25 seconds"
      AFL_DEBUG_CHILD=1 ../../../afl-fuzz -m none -V25 -U -i sample_inputs -o out -d -- ./harness @@ >>errors 2>&1
      test -n "$( ls out/default/queue/id:000002* 2>/dev/null )" && {
        $ECHO "$GREEN[+] afl-fuzz is working correctly with unicorn_mode (persistent)"
      } || {
        echo CUT------------------------------------------------------------------CUT
        cat errors
        echo CUT------------------------------------------------------------------CUT
        $ECHO "$RED[!] afl-fuzz is not working correctly with unicorn_mode (persistent)"
        CODE=1
      }

      rm -rf out errors >/dev/null
      make clean >/dev/null
      cd ../../../test

      # travis workaround
      test "$PY" = "/opt/pyenv/shims/python" -a -x /usr/bin/python && PY=/usr/bin/python
      mkdir -p in
      echo 0 > in/in
      $ECHO "$GREY[*] Using python binary $PY"
      if ! $PY -c 'import unicornafl' 2>/dev/null ; then
        $ECHO "$YELLOW[-] we cannot test unicorn_mode for python because it is not present"
        INCOMPLETE=1
      else
      {
        $ECHO "$GREY[*] running afl-fuzz for unicorn_mode in python, this will take approx 25 seconds"
        {
          ../afl-fuzz -m ${MEM_LIMIT} -V25 -U -i in -o out -d -- "$PY" ../unicorn_mode/samples/python_simple/simple_test_harness.py @@ >>errors 2>&1
        } >>errors 2>&1
        test -n "$( ls out/default/queue/id:000002* 2>/dev/null )" && {
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
          ../afl-fuzz -m ${MEM_LIMIT} -V35 -U -i in -o out -d -- "$PY" ../unicorn_mode/samples/compcov_x64/compcov_test_harness.py @@ >>errors 2>&1
          unset AFL_COMPCOV_LEVEL
        } >>errors 2>&1
        test -n "$( ls out/default/queue/id:000001* 2>/dev/null )" && {
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

      unset AFL_DEBUG_CHILD

    }
  } || {
    $ECHO "$RED[!] missing sample binaries in unicorn_mode/samples/ - what is going on??"
    CODE=1
  }

} || {
  $ECHO "$YELLOW[-] unicorn_mode is not compiled, cannot test"
  INCOMPLETE=1
}

. ./test-post.sh
