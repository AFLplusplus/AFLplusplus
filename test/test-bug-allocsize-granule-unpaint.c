// ALLOCSIZE TP: unregistering one region in a shared shadow granule must not
// erase OOB detection for another live region in that same granule.
#include <stdint.h>
#include <stdio.h>
#include "../include/bug-pass.h"

static unsigned char region[64] __attribute__((aligned(64)));

int main(void) {

  __afl_alloc_register(region, 16, 1);
  __afl_alloc_register(region + 32, 16, 2);
  __afl_alloc_unregister(region);
  __afl_alloc_oracle(region + 48, 1);
  fprintf(stderr, "BUG_ALLOCSIZE_GRANULE_UNPAINT: missed\n");
  __afl_alloc_unregister(region + 32);
  return 0;

}

