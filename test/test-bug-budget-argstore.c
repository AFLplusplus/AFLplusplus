// test/test-bug-budget-argstore.c
// BUDGET must count stores even when the stored byte is a scalar argument.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

__attribute__((noinline, optnone)) static unsigned fill_arg(unsigned char *p,
                                                            unsigned       n,
                                                            unsigned char  c) {

  for (unsigned i = 0; i < n + 4; ++i)
    p[i] = c;
  return n;

}

int main(void) {

  uint32_t n = 0;
  if (fread(&n, 1, sizeof(n), stdin) != sizeof(n)) return 0;
  n &= 31;
  unsigned char *buf = (unsigned char *)malloc(64);
  if (!buf) return 0;
  unsigned char *p = buf;
  p += fill_arg(p, n, (unsigned char)n);
  fprintf(stderr, "BUG_BUDGET_ARGSTORE: n=%u final=%p\n", n, (void *)p);
  free(buf);
  return 0;

}

