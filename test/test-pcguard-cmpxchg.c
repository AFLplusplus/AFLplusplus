/*
 * Regression test for PCGUARD sub-block coverage of AtomicCmpXchgInst.
 *
 * AtomicCmpXchgInst::getType() returns {T, i1} (a StructType), not i1.
 * The PCGUARD pass had a buggy isIntegerTy(1) check that always failed
 * for cmpxchg, causing it to be counted as "unhandled" and never
 * instrumented for sub-block coverage.
 *
 * Compile with: AFL_DEBUG=1 afl-clang-fast -O0 -o test-pcguard-cmpxchg this.c
 * Verify: output should show "0 ... unhandled" (not "1 ... unhandled")
 */

#include <stdio.h>

int shared = 0;

int test_cmpxchg(int expected, int desired) {

  /* __atomic_compare_exchange_n compiles to a cmpxchg instruction.
     The PCGUARD pass should provide sub-block coverage for the
     success/failure outcome of this atomic operation. */
  if (__atomic_compare_exchange_n(&shared, &expected, desired, 0,
                                  __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {

    return 1;

  } else {

    return 0;

  }

}

int main(void) {

  printf("result: %d\n", test_cmpxchg(0, 42));
  return 0;

}

