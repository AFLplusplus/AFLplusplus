// test/test-bug-allocsize-track.c
// Verifies that the pass rewrites malloc/free into __afl_track_*. Without
// rewriting, the runtime's record table stays empty (all .in_use==0) and
// the helper printf reports "tracked=0". Uses the canonical struct from
// bug-pass.h so this test doesn't drift from the runtime layout.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "bug-pass.h"

/* Unsized extern: the runtime sets the actual array length via
   MAP_SIZE_ALLOCRECORDS in config.h (currently 4096); declaring a fixed
   [256] bound here drifts as that constant evolves. */
extern AllocSizeRecord __afl_alloc_records[];

int main(void) {

  void    *p = malloc(64);
  void    *q = malloc(128);
  unsigned tracked = 0;
  /* 256 is a sufficient scan bound for this test: pick_idx starts at
     idx=1 and we only register two allocations, so they land in the low
     range.  Widen if the test ever registers more allocations. */
  for (unsigned i = 1; i < 256; ++i)
    if (__afl_alloc_records[i].in_use) ++tracked;
  fprintf(stderr, "BUG_ALLOCSIZE_TRACK: tracked=%u p=%p q=%p\n", tracked, p, q);
  free(p);
  free(q);
  return 0;

}

