// SIZEFILL must accept 2-arg sentinel signatures `parse(buf,
// size_t *out)` (zlib/libpng/OpenSSL EVP have many such APIs).  A
// 2-arg parser that lies about size must trip SIZEFILL.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>

__attribute__((noinline, optnone)) static void parse_bad(uint8_t *buf,
                                                         size_t  *out_size) {

  if (buf == NULL) {

    *out_size = 16;
    return;

  }

  /* lies: writes 24 entries, reports 16 */
  for (int i = 0; i < 24; ++i)
    buf[i] = (uint8_t)i;
  *out_size = 16;

}

int main(void) {

  uint8_t in[4] = {0};
  if (read(0, in, 4) != 4) return 1;
  size_t need;
  parse_bad(NULL, &need);
  uint8_t *p = (uint8_t *)malloc(need);
  if (!p) return 2;
  parse_bad(p, &need);
  fprintf(stderr, "BUG_SIZEFILL_TWOARG: need=%zu\n", need);
  free(p);
  return 0;

}

