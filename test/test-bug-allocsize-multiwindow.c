// test/test-bug-allocsize-multiwindow.c
// Bug 25 (Tier 3 item 3): the ALLOCSIZE shadow was a single 16 GiB window
// pinned at the first registered allocation's base.  Under ASLR (or with
// targets that mmap their own arenas far from the heap) subsequent
// allocations more than 16 GiB away silently failed to register, so OOB
// writes against them slipped past the oracle.  Multi-window adds up to
// 3 extra 16 GiB windows beyond the primary.
//
// TP: place two tracked allocations ~3 TiB apart (well outside one 16 GiB
// window) by hinting MAP_FIXED_NOREPLACE addresses on x86_64.  Register
// both, then do a 4-byte OOB write against the second.  Without
// multi-window the second registration's window can't open, so the OOB
// store hits a NULL shadow lookup and the oracle returns silently — rc=0.
// With multi-window the second window opens, the oracle finds the
// record, and trips on (a + sz) > end → _exit(134).
//
// We pick the second OOB so it stays inside the painted granule that
// holds the allocation (32-byte buffer, write at offset 30 spans the
// end), matching the same trick test-bug-allocsize-mmap.c uses.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "bug-pass.h"  /* __afl_alloc_register declaration */

#ifndef MAP_FIXED_NOREPLACE
#  define MAP_FIXED_NOREPLACE 0x100000
#endif

/* Hinted addresses ~3 TiB apart: comfortably > 16 GiB so they must land
   in different windows. Linux's 48-bit user VAs cover up to 0x7fff... so
   0x10000000000 (1 TiB) and 0x40000000000 (4 TiB) are both legal. */
#define HINT_A ((void *)0x10000000000ULL)
#define HINT_B ((void *)0x40000000000ULL)

static volatile uint8_t *g_sink;

int main(void) {

  uint8_t in[4] = {0};
  if (read(0, in, 4) != 4) return 1;

  /* Both regions one page each — the granule paint logic only needs the
     first granule (64 bytes) covered. */
  uint8_t *a = (uint8_t *)mmap(HINT_A, 4096, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                               -1, 0);
  uint8_t *b = (uint8_t *)mmap(HINT_B, 4096, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                               -1, 0);
  if (a == MAP_FAILED || b == MAP_FAILED) {
    fprintf(stderr,
            "BUG_ALLOCSIZE_MULTIWINDOW: mmap hint refused (a=%p b=%p); "
            "kernel/ASLR did not honor the hint, skipping\n", (void *)a, (void *)b);
    /* Don't fail the test if the kernel didn't give us the hinted
       addresses — the multi-window code path is exercised by
       test-bug-pass.sh's address spread check before running. */
    return 0;
  }

  /* Far enough apart to require separate windows. */
  uintptr_t ua = (uintptr_t)a, ub = (uintptr_t)b;
  uintptr_t diff = ua > ub ? ua - ub : ub - ua;
  if (diff < (1ULL << 34)) {
    fprintf(stderr,
            "BUG_ALLOCSIZE_MULTIWINDOW: regions only %llu bytes apart "
            "(< 16 GiB), kernel ignored the hint, skipping\n",
            (unsigned long long)diff);
    return 0;
  }

  /* Register a 32-byte tracked extent inside each region.  The oracle
     painted shadow for granule 0 (bytes 0..63) of each window. */
  __afl_alloc_register(a, 32, /*site_a=*/1);
  __afl_alloc_register(b, 32, /*site_b=*/2);

  /* Data-dependent OOB store at b[30..33]: spans the end of the 32-byte
     buffer.  Without multi-window the second registration's window
     never opened, so the oracle's _find returns NULL and the store
     slips past silently (rc=0 below).  With multi-window the window
     exists; the oracle trips and _exit(134)s. */
  uint32_t n = 30u + ((uint32_t)in[0] & 3u);
  memcpy(b + n, "OOB!", 4);
  g_sink = b;

  fprintf(stderr,
          "BUG_ALLOCSIZE_MULTIWINDOW: a=%p b=%p diff=%llu n=%u\n",
          (void *)a, (void *)b, (unsigned long long)diff, n);
  return 0;

}
