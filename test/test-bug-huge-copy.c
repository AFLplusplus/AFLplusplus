// test/test-bug-huge-copy.c
// Compile-only regression: BUDGET/SIZEFILL must not truncate constant
// memory-write lengths that do not fit the i32 runtime hook.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define HUGE_COPY_LEN ((size_t)0x100000000ULL)

__attribute__((noinline, optnone)) static unsigned fill_budget(unsigned char *p,
                                                               unsigned n) {

  memset(p, 0x41, HUGE_COPY_LEN);
  return n;

}

__attribute__((noinline, optnone)) static size_t need_or_fill(
    unsigned char *p) {

  if (!p) return 8;
  memset(p, 0x42, HUGE_COPY_LEN);
  return 8;

}

int main(void) {

  unsigned char *p = (unsigned char *)malloc(8);
  if (!p) return 0;
  p += fill_budget(p, 8);
  size_t n = need_or_fill(NULL);
  need_or_fill(p);
  free(p - 8);
  return (int)n;

}

