// test/test-bug-sizefill-bad.c
// build_table_bad: size-only mode returns 16, but fill mode actually writes
// 24 entries (and returns 16). Caller sized buffer to 16 entries. Must crash.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((noinline, optnone)) static uint32_t build_table_bad(
    uint32_t *out, uint32_t n) {

  if (out == NULL) return 16;  // lies about size
  for (uint32_t i = 0; i < 24; ++i)
    out[i] = (uint32_t)(i + n);
  return 16;

}

int main(void) {

  uint8_t buf[4] = {0};
  if (read(0, buf, 4) != 4) return 1;
  uint32_t n = (uint32_t)buf[0];

  uint32_t need = build_table_bad(NULL, n);
  // Caller sizes buffer to exactly the lie:
  uint32_t *storage = (uint32_t *)malloc(16 * sizeof(uint32_t));
  if (!storage) return 2;
  uint32_t got = build_table_bad(storage, n);
  fprintf(stderr, "BUG_SIZEFILL_BAD: need=%u got=%u\n", need, got);
  free(storage);
  return 0;

}

