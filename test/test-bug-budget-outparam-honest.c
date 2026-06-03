// BUDGET out-param TN: same shape as test-bug-budget-outparam.c, but
// the callee writes 16 bytes and reports 16.  Must rc=0 — if this ever
// fires, the matcher is over-eager or the threshold is off-by-one.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__attribute__((noinline, optnone)) static void fill_honest(uint8_t *buf,
                                                           size_t  *out_n) {

  for (int i = 0; i < 16; ++i)
    buf[i] = (uint8_t)(0x40 | i);
  *out_n = 16;

}

int main(void) {

  uint8_t in[4] = {0};
  if (read(0, in, 4) != 4) return 1;

  uint8_t  buf[256] = {0};
  uint8_t *p = buf;
  size_t   n = 0;

  p += (in[0] & 3);

  fill_honest(p, &n);
  p += n;

  fprintf(
      stderr,
      "BUG_BUDGET_OUTPARAM_HONEST: reported_n=%zu, advanced_to_offset=%ld\n", n,
      (long)(p - buf));
  return 0;

}

