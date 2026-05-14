// test/test-bug-sizefill-u32out.c
// Bug 17: SIZEFILL must accept uint32_t* out_size args on 64-bit (most
// real targets — libpng, libxml2, OpenSSL all use `unsigned int *outlen`
// patterns). Previously `findOutSizeParam` precondition (b) required
// `bits >= ptr_bits` (=64) and silently dropped 32-bit out-params.
//
// TP path: a void-returning parser lies about size via a uint32_t* out
// and SIZEFILL must abort.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((noinline, optnone))
static void parse_bad(uint8_t *buf, int max, uint32_t *out_size) {

  (void)max;
  if (buf == NULL) { *out_size = 16; return; }
  /* lies: writes 24 entries, reports 16 */
  for (int i = 0; i < 24; ++i) buf[i] = (uint8_t)i;
  *out_size = 16;

}

int main(void) {

  uint8_t buf[4] = {0};
  if (read(0, buf, 4) != 4) return 1;
  uint32_t need;
  parse_bad(NULL, 0, &need);
  uint8_t *p = (uint8_t *)malloc(need);
  if (!p) return 2;
  parse_bad(p, 1024, &need);
  fprintf(stderr, "BUG_SIZEFILL_U32OUT: need=%u\n", need);
  free(p);
  return 0;

}
