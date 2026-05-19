// test/test-bug-sizefill-good.c
// build_table has size-only mode (NULL out → just returns size). Honest:
// returned size is always <= caller's buffer. Must NOT crash.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((noinline, optnone)) static uint32_t build_table(uint32_t *out,
                                                               uint32_t  n) {

  uint32_t sz = (n & 31) + 1;  // 1..32
  if (out == NULL) return sz;
  for (uint32_t i = 0; i < sz; ++i)
    out[i] = i * i;
  return sz;

}

int main(void) {

  uint8_t buf[4] = {0};
  if (read(0, buf, 4) != 4) return 1;
  uint32_t n = (uint32_t)buf[0];

  uint32_t need = build_table(NULL, n);
  if (need > 64) return 2;
  uint32_t *storage = (uint32_t *)malloc(64 * sizeof(uint32_t));
  if (!storage) return 3;
  uint32_t got = build_table(storage, n);
  fprintf(stderr, "BUG_SIZEFILL_GOOD: need=%u got=%u\n", need, got);
  free(storage);
  return 0;

}

