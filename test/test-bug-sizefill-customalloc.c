// SIZEFILL recognizes buffers from custom allocators registered via
// AFL_LLVM_BUG_ALLOCSIZE_FUNCS.  A parse() that lies about size, called
// with a MyAlloc-allocated buffer, must trip SIZEFILL.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>

__attribute__((noinline, optnone)) static uint8_t *MyAlloc(size_t n) {

  return (uint8_t *)malloc(n);

}

__attribute__((noinline, optnone)) static int parse_bad(uint8_t *out, int max,
                                                        size_t *out_size) {

  (void)max;
  if (out == NULL) {

    *out_size = 16;
    return 0;

  }

  for (int i = 0; i < 24; ++i)
    out[i] = (uint8_t)i;                                            /* lies */
  *out_size = 16;
  return 0;

}

int main(void) {

  uint8_t in[4] = {0};
  if (read(0, in, 4) != 4) return 1;
  size_t need;
  parse_bad(NULL, 0, &need);
  uint8_t *p = MyAlloc(need);
  if (!p) return 2;
  parse_bad(p, 1024, &need);
  fprintf(stderr, "BUG_SIZEFILL_CUSTOMALLOC: need=%zu\n", need);
  free(p);
  return 0;

}

