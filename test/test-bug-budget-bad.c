// test/test-bug-budget-bad.c
// fill_lying always writes 2*n bytes but only returns n. Caller advances
// by n, so the "stolen" n bytes corrupt the next slot. BUDGET mode MUST crash.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__attribute__((noinline, optnone)) static uint32_t fill_lying(uint8_t *p,
                                                              uint32_t n) {

  uint32_t doubled = 2 * n;
  for (uint32_t i = 0; i < doubled; ++i)
    p[i] = (uint8_t)i;
  return n;  // lies: actually wrote 2n

}

int main(void) {

  uint8_t buf[4] = {0};
  if (read(0, buf, 4) != 4) return 1;
  uint32_t n = ((uint32_t)buf[0]) % 32;
  if (n < 2) n = 2;

  uint8_t *big = (uint8_t *)malloc(256);
  if (!big) return 2;
  uint8_t *p = big;
  uint32_t s = fill_lying(p, n);
  p += s;
  fprintf(stderr, "BUG_BUDGET_BAD: wrote=%u final=%p\n", s, (void *)p);
  free(big);
  return 0;

}

