// test/test-bug-budget-memset.c
// BUDGET must count bulk writes lowered to llvm.memset.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

__attribute__((noinline, optnone)) static unsigned fill_memset(unsigned char *p,
                                                               unsigned n) {

  memset(p, 0x41, n + 4);
  return n;

}

int main(void) {

  uint32_t n = 0;
  if (fread(&n, 1, sizeof(n), stdin) != sizeof(n)) return 0;
  n &= 31;
  unsigned char *buf = (unsigned char *)malloc(64);
  if (!buf) return 0;
  unsigned char *p = buf;
  p += fill_memset(p, n);
  fprintf(stderr, "BUG_BUDGET_MEMSET: n=%u final=%p\n", n, (void *)p);
  free(buf);
  return 0;

}

