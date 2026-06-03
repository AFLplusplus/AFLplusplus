/*
 * Regression test for PCGUARD sub-block coverage of AtomicRMWInst min/max.
 *
 * AtomicRMWInst::getType() returns the operand type (e.g. i32), not i1.
 * The PCGUARD pass had a buggy isIntegerTy(1) check in the counting phase
 * that always failed for rmw, so no guard slots were allocated.  However
 * the instrumentation phase had no such guard and proceeded to emit code
 * that consumed guard slots, causing an out-of-bounds access on the
 * guard array.
 *
 * Compile with: AFL_DEBUG=1 afl-clang-fast -O0 -o test-pcguard-atomicrmw this.c
 * Verify: output should show "0 ... unhandled" (not "2 ... unhandled")
 */

#include <stdio.h>

unsigned shared_min = 100;
unsigned shared_max = 0;

unsigned test_atomic_minmax(unsigned val) {

  /* These builtins compile to atomicrmw umin / umax instructions.
     The PCGUARD pass should provide sub-block coverage for the
     update/no-update outcome of each operation. */
  unsigned old_min = __atomic_fetch_min(&shared_min, val, __ATOMIC_SEQ_CST);
  unsigned old_max = __atomic_fetch_max(&shared_max, val, __ATOMIC_SEQ_CST);
  return old_min + old_max;

}

int main(void) {

  printf("result: %u\n", test_atomic_minmax(42));
  return 0;

}

