// test/test-bug-allocsize-good.c
// Writes inside the bounds of a malloc'd buffer. Tripwire MUST stay silent.
//
// volatile forces the buffer + writes to survive optimization (otherwise
// clang -O3 elides the entire malloc when the pointer doesn't escape).
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static uint8_t *volatile g_sink;

int main(void) {

  uint8_t buf[4] = {0};
  if (read(0, buf, 4) != 4) return 1;
  uint32_t n = ((uint32_t)buf[0]) % 64;                            /* 0..63 */
  uint8_t *p = (uint8_t *)malloc(64);
  if (!p) return 2;
  for (uint32_t i = 0; i < n; ++i)
    p[i] = (uint8_t)i;
  g_sink = p;
  fprintf(stderr, "BUG_ALLOCSIZE_GOOD: wrote=%u\n", n);
  free(p);
  return 0;

}

