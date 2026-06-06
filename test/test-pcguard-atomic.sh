#!/bin/sh

#
# Regression tests for PCGUARD sub-block coverage of atomic instructions.
#
# Tests that AtomicCmpXchgInst and AtomicRMWInst (min/max) are properly
# instrumented for sub-block coverage, not reported as "unhandled".
#

. ./test-pre.sh

$ECHO "$BLUE[*] Testing: PCGUARD sub-block coverage for atomic instructions"

extract_handled_unhandled() {

  echo "$1" | sed -n 's/.*of which are \([0-9][0-9]*\) handled and \([0-9][0-9]*\) unhandled.*/\1 \2/p' | tail -n 1

}

test -e ../afl-clang-fast && {

  # --- Test 1: AtomicCmpXchgInst sub-block coverage ---
  $ECHO "$BLUE[*] Testing: cmpxchg sub-block coverage"
  RESULT=$(AFL_DEBUG=1 ../afl-clang-fast -O0 -o test-pcguard-cmpxchg test-pcguard-cmpxchg.c 2>&1)
  test -e test-pcguard-cmpxchg && {
    COUNTS=$(extract_handled_unhandled "$RESULT")
    HANDLED=
    UNHANDLED=
    test -n "$COUNTS" && {
      HANDLED=${COUNTS%% *}
      UNHANDLED=${COUNTS##* }
    }
    # Check that cmpxchg is handled (0 unhandled), not skipped
    test "$UNHANDLED" = "0" && {
      # Check that sub-block coverage was emitted (handled > 0)
      test -n "$HANDLED" && test "$HANDLED" -gt 0 && {
        $ECHO "$GREEN[+] cmpxchg sub-block coverage works correctly ($HANDLED handled, $UNHANDLED unhandled)"
      } || {
        test -z "$HANDLED" && {
          $ECHO "$RED[!] failed to parse handled/unhandled counts from compiler output"
        } || {
          $ECHO "$RED[!] cmpxchg not instrumented for sub-block coverage (handled=$HANDLED)"
        }
        CODE=1
      }
    } || {
      test -z "$UNHANDLED" && {
        $ECHO "$RED[!] failed to parse handled/unhandled counts from compiler output"
      } || {
        $ECHO "$RED[!] cmpxchg reported as unhandled ($UNHANDLED unhandled)"
      }
      CODE=1
    }
    rm -f test-pcguard-cmpxchg
  } || {
    $ECHO "$RED[!] cmpxchg test compilation failed"
    CODE=1
  }

  # --- Test 2: AtomicRMWInst min/max sub-block coverage ---
  $ECHO "$BLUE[*] Testing: atomicrmw min/max sub-block coverage"
  RESULT=$(AFL_DEBUG=1 ../afl-clang-fast -O0 -o test-pcguard-atomicrmw test-pcguard-atomicrmw.c 2>&1)
  test -e test-pcguard-atomicrmw && {
    COUNTS=$(extract_handled_unhandled "$RESULT")
    HANDLED=
    UNHANDLED=
    test -n "$COUNTS" && {
      HANDLED=${COUNTS%% *}
      UNHANDLED=${COUNTS##* }
    }
    test "$UNHANDLED" = "0" && {
      test -n "$HANDLED" && test "$HANDLED" -gt 0 && {
        $ECHO "$GREEN[+] atomicrmw min/max sub-block coverage works correctly ($HANDLED handled, $UNHANDLED unhandled)"
      } || {
        test -z "$HANDLED" && {
          $ECHO "$RED[!] failed to parse handled/unhandled counts from compiler output"
        } || {
          $ECHO "$RED[!] atomicrmw not instrumented for sub-block coverage (handled=$HANDLED)"
        }
        CODE=1
      }
    } || {
      test -z "$UNHANDLED" && {
        $ECHO "$RED[!] failed to parse handled/unhandled counts from compiler output"
      } || {
        $ECHO "$RED[!] atomicrmw reported as unhandled ($UNHANDLED unhandled)"
      }
      CODE=1
    }
    rm -f test-pcguard-atomicrmw
  } || {
    $ECHO "$RED[!] atomicrmw test compilation failed"
    CODE=1
  }

} || {
  $ECHO "$YELLOW[-] afl-clang-fast not built, skipping atomic sub-block tests"
}

. ./test-post.sh
