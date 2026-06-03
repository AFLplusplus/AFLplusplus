// test/test-bug-allocsize-custom-free.c
// Custom allocator registrations need a matching custom-free unregister path.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "bug-pass.h"

extern AllocSizeRecord __afl_alloc_records[256];

__attribute__((noinline)) static void *MyAlloc(size_t n) {

  return malloc(n);

}

__attribute__((noinline)) static void MyFree(void *p) {

  free(p);

}

static unsigned count_tracked(void) {

  unsigned tracked = 0;
  for (unsigned i = 1; i < 256; ++i)
    if (__afl_alloc_records[i].in_use) ++tracked;
  return tracked;

}

int main(void) {

  uint32_t x = 0;
  (void)fread(&x, 1, sizeof(x), stdin);
  void *p = MyAlloc(32);
  if (!p) return 0;
  MyFree(p);
  fprintf(stderr, "BUG_ALLOCSIZE_CUSTOM_FREE: tracked=%u\n", count_tracked());
  return 0;

}

