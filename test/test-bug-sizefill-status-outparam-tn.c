// SIZEFILL TN: a nonzero integer status return is not a size when the API
// also writes an honest out-size value.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((noinline, optnone)) static int parse_status(uint8_t *buf,
                                                           size_t   max,
                                                           size_t  *out_size) {

  if (buf == NULL) {

    *out_size = 8;
    return 22;

  }

  for (size_t i = 0; i < 8 && i < max; ++i)
    buf[i] = (uint8_t)i;
  *out_size = 8;
  return 22;

}

int main(void) {

  uint8_t in[4] = {0};
  if (read(0, in, 4) != 4) return 1;
  (void)in;

  size_t need = 0;
  parse_status(NULL, 0, &need);
  uint8_t *p = (uint8_t *)malloc(need);
  if (!p) return 2;

  int rc = parse_status(p, need, &need);
  fprintf(stderr, "BUG_SIZEFILL_STATUS_OUT_TN: rc=%d need=%zu\n", rc, need);
  free(p);
  return 0;

}

