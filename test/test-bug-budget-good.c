// test/test-bug-budget-good.c
// fill_n writes exactly n bytes through ptr and returns n. Caller does
// ptr += n. Honest contract: BUDGET mode must NOT crash this.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__attribute__((noinline, optnone)) static uint32_t fill_n(uint8_t *p,
                                                          uint32_t n) {

  uint32_t written = 0;
  for (uint32_t i = 0; i < n; ++i) {

    p[i] = (uint8_t)i;
    written++;

  }

  return written;

}

int main(void) {

  uint8_t buf[4] = {0};
  if (read(0, buf, 4) != 4) return 1;
  uint32_t n = ((uint32_t)buf[0]) % 64;  // 0..63

  uint8_t *big = (uint8_t *)malloc(256);
  if (!big) return 2;
  uint8_t *p = big;
  uint32_t s = fill_n(p, n);
  p += s;
  fprintf(stderr, "BUG_BUDGET_GOOD: wrote=%u final=%p\n", s, (void *)p);
  free(big);
  return 0;

}

