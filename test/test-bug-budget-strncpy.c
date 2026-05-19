// test/test-bug-budget-strncpy.c
// BUDGET on libc string copies: strncpy writes EXACTLY n bytes
// (NUL-padded), so a callee that does strncpy(p, src, 2*n) but
// returns n is lying about its write extent.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__attribute__((noinline, optnone)) static uint32_t fill_lying_strncpy(
    char *p, uint32_t n) {

  static const char src[] =
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  /* strncpy writes 2*n bytes deterministically (NUL-pads when src
     shorter, truncates when longer).  src has 64 chars so for n<=32
     this is exactly 2n bytes written. */
  strncpy(p, src, (size_t)n * 2);
  return n;                                      /* lies: actually wrote 2n */

}

int main(void) {

  uint8_t in[4] = {0};
  if (read(0, in, 4) != 4) return 1;
  uint32_t n = ((uint32_t)in[0]) % 16;
  if (n < 2) n = 2;

  char *big = (char *)malloc(256);
  if (!big) return 2;
  char    *p = big;
  uint32_t s = fill_lying_strncpy(p, n);
  p += s;
  fprintf(stderr, "BUG_BUDGET_STRNCPY: wrote=%u final=%p\n", s, (void *)p);
  free(big);
  return 0;

}

