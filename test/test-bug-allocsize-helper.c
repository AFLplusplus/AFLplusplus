// test/test-bug-allocsize-helper.c
// ALLOCSIZE should catch writes in helper functions that receive a tracked
// allocation through an argument.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

__attribute__((noinline, optnone)) static void helper_write(unsigned char *p,
                                                            unsigned idx) {

  p[idx] = 0x43;

}

int main(void) {

  uint32_t n = 0;
  if (fread(&n, 1, sizeof(n), stdin) != sizeof(n)) return 0;
  size_t         alloc_size = 16 + ((n >> 8) & 15);
  unsigned       idx = (unsigned)alloc_size + (n & 15);
  unsigned char *p = (unsigned char *)malloc(alloc_size);
  if (!p) return 0;
  helper_write(p, idx);
  fprintf(stderr, "BUG_ALLOCSIZE_HELPER: alloc=%zu idx=%u\n", alloc_size, idx);
  free(p);
  return 0;

}

