// test/test-bug-scalar-select.c
// SCALAR must instrument size-decision selects (one constant arm).
//
// Forcing clang to emit `SelectInst` rather than a branch+PHI is
// brittle.  A ternary on a runtime boolean with both arms being
// constants is the most reliable pattern; compile at -O1+ for the
// optimizer to canonicalize to `select`.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

extern uint32_t *__afl_bug_map;
extern uint8_t   __afl_bug_active;

__attribute__((noinline)) static uint32_t cap_size(uint32_t n) {

  /* Trick clang into emitting `select` rather than branches:
     read the operands through volatile so the optimizer can't
     hoist them across the conditional, then use the ternary on
     a runtime-known boolean.  Both arms are constants — the
     defining pattern for a single SelectInst at any -O level. */
  volatile uint32_t cond = n;
  uint32_t          a = 1024;
  uint32_t          b = 4096;
  /* `cond > 1024` is runtime; arms are constants 1024 / 4096.
     clang at -O1+ folds this to:
       %c = icmp ugt i32 %cond, 1024
       %sel = select i1 %c, i32 4096, i32 1024
     which is exactly the size-decision pattern SCALAR-Select
     instruments. */
  return (cond > 1024) ? b : a;

}

int main(void) {

  uint8_t in[4] = {0};
  if (read(0, in, 4) != 4) return 1;
  uint32_t n = (uint32_t)in[0] | ((uint32_t)in[1] << 8) |
               ((uint32_t)in[2] << 16) | ((uint32_t)in[3] << 24);
  uint32_t sz = cap_size(n);
  char    *buf = (char *)malloc(sz + 1);
  if (!buf) return 2;
  buf[0] = (char)sz;
  fprintf(stderr, "BUG_SCALAR_SELECT: sz=%u\n", sz);
  free(buf);
  return 0;

}

