// ALLOCSIZE TN: in-bounds accesses to multiple live regions sharing a
// shadow granule must not be reported as OOB.
#include <stdint.h>
#include <stdio.h>
#include "../include/bug-pass.h"

static unsigned char region[64] __attribute__((aligned(64)));

int main(void) {

  __afl_alloc_register(region, 16, 1);
  __afl_alloc_register(region + 32, 16, 2);
  __afl_alloc_oracle(region + 15, 1);
  __afl_alloc_oracle(region + 47, 1);
  fprintf(stderr, "BUG_ALLOCSIZE_GRANULE_INBOUNDS: ok\n");
  __afl_alloc_unregister(region + 32);
  __afl_alloc_unregister(region);
  return 0;

}

