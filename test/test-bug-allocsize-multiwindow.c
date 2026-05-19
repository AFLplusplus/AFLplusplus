// ALLOCSIZE multi-window shadow: two tracked allocations placed
// > 16 GiB apart (one primary window cannot cover both) must both
// register, and OOB writes against the far allocation must trip the
// oracle.  Places two mmap regions ~3 TiB apart via MAP_FIXED_NOREPLACE
// hints; the 4-byte write at offset 30 of a 32-byte buffer stays
// inside the painted granule so the granule-shadow lookup finds the
// record.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "bug-pass.h"                   /* __afl_alloc_register declaration */

#ifndef MAP_FIXED_NOREPLACE
  #define MAP_FIXED_NOREPLACE 0x100000
#endif

/* Hinted addresses > 16 GiB apart: they must land in different
   shadow windows. Linux's 48-bit user VAs cover up to 0x7fff... */
#define HINT_A ((void *)0x10000000000ULL)
#define HINT_B ((void *)0x40000000000ULL)

static volatile uint8_t *g_sink;

int main(void) {

  uint8_t in[4] = {0};
  if (read(0, in, 4) != 4) return 1;

  uint8_t *a =
      (uint8_t *)mmap(HINT_A, 4096, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
  uint8_t *b =
      (uint8_t *)mmap(HINT_B, 4096, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
  if (a == MAP_FAILED || b == MAP_FAILED) {

    fprintf(stderr,
            "BUG_ALLOCSIZE_MULTIWINDOW: mmap hint refused (a=%p b=%p); "
            "kernel/ASLR did not honor the hint, skipping\n",
            (void *)a, (void *)b);
    return 0;

  }

  uintptr_t ua = (uintptr_t)a, ub = (uintptr_t)b;
  uintptr_t diff = ua > ub ? ua - ub : ub - ua;
  if (diff < (1ULL << 34)) {

    fprintf(stderr,
            "BUG_ALLOCSIZE_MULTIWINDOW: regions only %llu bytes apart "
            "(< 16 GiB), kernel ignored the hint, skipping\n",
            (unsigned long long)diff);
    return 0;

  }

  __afl_alloc_register(a, 32, /*site_a=*/1);
  __afl_alloc_register(b, 32, /*site_b=*/2);

  /* 4-byte write at offset 30 of a 32-byte buffer spans the end. */
  uint32_t n = 30u + ((uint32_t)in[0] & 3u);
  memcpy(b + n, "OOB!", 4);
  g_sink = b;

  fprintf(stderr, "BUG_ALLOCSIZE_MULTIWINDOW: a=%p b=%p diff=%llu n=%u\n",
          (void *)a, (void *)b, (unsigned long long)diff, n);
  return 0;

}

