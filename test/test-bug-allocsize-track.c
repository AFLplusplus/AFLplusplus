// test/test-bug-allocsize-track.c
// Verifies that the pass rewrites malloc/free into __afl_track_*. Without
// rewriting, the runtime's record table stays empty (all .in_use==0) and
// the helper printf reports "tracked=0". Uses the canonical struct from
// bug-pass.h so this test doesn't drift from the runtime layout.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "bug-pass.h"

extern AllocSizeRecord __afl_alloc_records[256];

int main(void) {
  void *p = malloc(64);
  void *q = malloc(128);
  unsigned tracked = 0;
  for (unsigned i = 1; i < 256; ++i)
    if (__afl_alloc_records[i].in_use) ++tracked;
  fprintf(stderr, "BUG_ALLOCSIZE_TRACK: tracked=%u p=%p q=%p\n",
          tracked, p, q);
  free(p);
  free(q);
  return 0;
}
