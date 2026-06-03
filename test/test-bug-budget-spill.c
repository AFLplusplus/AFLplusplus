// BUDGET on the spill+reload shape: at -O0 the call result is stored
// to an alloca and reloaded for the GEP index.  The matcher must walk
// through that spill on both the GEP index and the buf alloca alias.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* fill_lying writes 2*n bytes but returns n. With -O0 the result lands
 * in a stack slot before the caller's `p += s` GEP. */
__attribute__((noinline, optnone)) static uint32_t fill_lying(uint8_t *p,
                                                              uint32_t n) {

  uint32_t doubled = 2 * n;
  for (uint32_t i = 0; i < doubled; ++i)
    p[i] = (uint8_t)i;
  return n;                                                         /* lies */

}

int main(void) {

  uint8_t in[4] = {0};
  if (read(0, in, 4) != 4) return 1;
  uint8_t *buf = (uint8_t *)malloc(256);
  if (!buf) return 2;
  uint8_t *p = buf;
  /* The IR shape at -O0: store call_result to alloca, reload to GEP.
     The optimizer at -O1+ would mem2reg-promote this. */
  uint32_t s = fill_lying(p, 10);
  p += s;
  fprintf(stderr, "BUG_BUDGET_SPILL: s=%u final=%p\n", s, (void *)p);
  free(buf);
  return 0;

}

