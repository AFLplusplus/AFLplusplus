// DERIVE per-site slot distribution: one allocation site called with
// varied sizes must spread its (size, max_off) entries across multiple
// cmp_map slots so the per-slot CMP_MAP_RTN_H cap doesn't drop later
// sizes at hot allocators.
//
// Uses AFL_CMPLOG_DEBUG=1 so the runtime allocates cmp_map even without
// a real fuzz harness.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "types.h"
#include "cmplog.h"

extern struct cmp_map *__afl_cmp_map;
extern uint8_t         __afl_size_derive_active;

/* All allocations come from this single inlined-pinned site; the pass
   hashes the call's IR location, so one source location => one
   alloc_site_id. */
__attribute__((noinline, optnone)) static uint8_t *alloc_at_site(uint64_t n) {

  return (uint8_t *)malloc((size_t)n);

}

int main(void) {

  uint8_t buf[4] = {0};
  if (read(0, buf, 4) != 4) return 1;

  static const uint64_t sizes[8] = {8, 16, 32, 64, 128, 256, 512, 1024};
  for (uint32_t i = 0; i < 8; ++i) {

    uint64_t n = sizes[i];
    uint8_t *p = alloc_at_site(n);
    if (!p) return 2;
    p[0] = buf[0];
    p[n - 1] = buf[1];
    free(p);

  }

  if (!__afl_cmp_map) {

    fprintf(stderr, "BUG_DERIVE_SLOT_RING: cmp_map=NULL active=%u\n",
            __afl_size_derive_active);
    return 0;

  }

  uint32_t distinct = 0;
  uint32_t seen[8] = {0};
  for (uint32_t k = 0; k < CMP_MAP_W; ++k) {

    if (!__afl_cmp_map->headers[k].hits) continue;
    if (__afl_cmp_map->headers[k].type != CMP_TYPE_RTN) continue;
    struct cmpfn_operands *op =
        (struct cmpfn_operands *)&__afl_cmp_map->log[k][0];
    uint64_t s = 0;
    for (uint32_t i = 0; i < 8; ++i)
      s |= (uint64_t)op->v0[i] << (i * 8);
    for (uint32_t i = 0; i < 8; ++i) {

      if (s == sizes[i] && !seen[i]) {

        seen[i] = 1;
        ++distinct;
        break;

      }

    }

  }

  fprintf(stderr, "BUG_DERIVE_SLOT_RING: distinct=%u sizes={", distinct);
  for (uint32_t i = 0; i < 8; ++i)
    fprintf(stderr, "%c%u", seen[i] ? '+' : '-', (unsigned)sizes[i]);
  fprintf(stderr, "}\n");

  return (distinct >= 2) ? 0 : 1;

}

