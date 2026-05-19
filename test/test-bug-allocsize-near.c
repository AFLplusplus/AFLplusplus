// test/test-bug-allocsize-near.c
// Writes (n) bytes into a 64-byte malloc'd buffer and reports the bug-map
// max-value seen. As n approaches 64 the headroom shrinks — the runtime's
// max-rule should produce a strictly larger map value.
//
// Trip count is data-dependent so the loop survives O3.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

extern uint32_t *__afl_bug_map;
extern uint8_t   __afl_bug_active;
static uint8_t *volatile g_sink;

int main(void) {

  uint8_t buf[4] = {0};
  if (read(0, buf, 4) != 4) return 1;
  uint32_t n = ((uint32_t)buf[0]) & 63;                  /* 0..63 in-bounds */
  uint8_t *p = (uint8_t *)malloc(64);
  if (!p) return 2;
  for (uint32_t i = 0; i < n; ++i)
    p[i] = (uint8_t)(buf[0] + i);
  g_sink = p;

  uint32_t maxval = 0;
  if (__afl_bug_active && __afl_bug_map) {

    for (uint32_t i = 0; i < (1U << 14); ++i)
      if (__afl_bug_map[i] > maxval) maxval = __afl_bug_map[i];

  }

  fprintf(stderr, "BUG_ALLOCSIZE_NEAR: n=%u maxval=%u\n", n, maxval);
  free(p);
  return 0;

}

