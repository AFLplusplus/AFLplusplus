// BUDGET out-param shape: `fill(p, &n); p += n;` — callee writes through
// buf AND through *out_n. fill_lying writes 32 bytes but reports
// *out_n = 16; ws_check_budget sees max_off (32) > ret_size (16) and
// trips.  The matcher only fires when BOTH BUDGET and SIZEFILL are
// enabled (gating).
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__attribute__((noinline, optnone)) static void fill_lying(uint8_t *buf,
                                                          size_t  *out_n) {

  for (int i = 0; i < 32; ++i)
    buf[i] = (uint8_t)(0xc0 | i);
  *out_n = 16;

}

int main(void) {

  uint8_t in[4] = {0};
  if (read(0, in, 4) != 4) return 1;

  uint8_t  buf[256] = {0};
  uint8_t *p = buf;
  size_t   n = 0;

  p += (in[0] & 3);

  fill_lying(p, &n);
  p += n;

  fprintf(stderr,
          "BUG_BUDGET_OUTPARAM: reported_n=%zu, advanced_to_offset=%ld\n", n,
          (long)(p - buf));
  return 0;

}

