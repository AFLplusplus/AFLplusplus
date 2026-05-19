// test/test-bug-sizefill-memset.c
// SIZEFILL must charge memset writes through the sentinel buffer argument.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

__attribute__((noinline, optnone)) static unsigned need_or_fill(
    unsigned char *out) {

  unsigned need = 16;
  if (!out) return need;
  memset(out, 0x42, need + 4);
  return need;

}

int main(void) {

  uint32_t x = 0;
  (void)fread(&x, 1, sizeof(x), stdin);
  unsigned       need = need_or_fill(NULL);
  unsigned char *buf = (unsigned char *)malloc(need);
  if (!buf) return 0;
  unsigned got = need_or_fill(buf);
  fprintf(stderr, "BUG_SIZEFILL_MEMSET: need=%u got=%u\n", need, got);
  free(buf);
  return 0;

}

