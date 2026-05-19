// ALLOCSIZE TP: two tracked regions can share one 64-byte shadow granule.
// An OOB immediately after the older region must not be hidden by the newer
// region's shadow id.
#include <stdint.h>
#include <stdio.h>
#include "../include/bug-pass.h"

static unsigned char region[64] __attribute__((aligned(64)));

int main(void) {

  __afl_alloc_register(region, 16, 1);
  __afl_alloc_register(region + 32, 16, 2);
  __afl_alloc_oracle(region + 16, 1);
  fprintf(stderr, "BUG_ALLOCSIZE_GRANULE_OOB: missed\n");
  __afl_alloc_unregister(region + 32);
  __afl_alloc_unregister(region);
  return 0;

}

