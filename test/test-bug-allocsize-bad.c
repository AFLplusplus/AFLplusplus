// test/test-bug-allocsize-bad.c
// Writes past end of a malloc'd buffer. Trip count is data-dependent so
// the optimizer can't unroll the loop into vector stores. Tripwire MUST fire.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static uint8_t *volatile g_sink;

int main(void) {

  uint8_t buf[4] = {0};
  if (read(0, buf, 4) != 4) return 1;
  /* n in [72, 87] — always past 64-byte buffer end. Data-dependent so the
     loop survives O3. */
  uint32_t n = 72u + ((uint32_t)buf[0] & 15u);
  uint8_t *p = (uint8_t *)malloc(64);
  if (!p) return 2;
  for (uint32_t i = 0; i < n; ++i)
    p[i] = (uint8_t)(buf[0] + i);
  g_sink = p;
  fprintf(stderr, "BUG_ALLOCSIZE_BAD: wrote=%u\n", n);
  free(p);
  return 0;

}

