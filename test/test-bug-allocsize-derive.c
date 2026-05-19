// test/test-bug-allocsize-derive.c
// Verifies that __afl_size_derive_log writes a (computed_size,
// max_observed_off) pair into cmp_map. Uses AFL_CMPLOG_DEBUG=1 which
// causes the runtime to allocate a private cmp_map even without a real
// fuzz binary so we can inspect it.
//
// Built with -I.../afl/include so we get the canonical cmplog.h definitions.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "types.h"
#include "cmplog.h"

extern struct cmp_map *__afl_cmp_map;
extern uint8_t         __afl_size_derive_active;

static volatile uint8_t *g_sink;

int main(void) {

  uint8_t buf[4] = {0};
  if (read(0, buf, 4) != 4) return 1;
  uint32_t writelen = 60u + ((uint32_t)buf[0] & 3);               /* 60..63 */

  uint8_t *p = (uint8_t *)malloc(64);
  if (!p) return 2;
  for (uint32_t i = 0; i < writelen; ++i)
    p[i] = (uint8_t)i;
  g_sink = p;
  free(p);       /* triggers __afl_alloc_unregister → __afl_size_derive_log */

  if (!__afl_cmp_map) {

    fprintf(stderr, "BUG_ALLOCSIZE_DERIVE: cmp_map=NULL active=%u\n",
            __afl_size_derive_active);
    return 0;

  }

  /* Scan cmp_map for an RTN entry with v0 == 64 (computed_size). */
  uint32_t found = 0;
  uint64_t got_size = 0, got_off = 0;
  for (uint32_t k = 0; k < CMP_MAP_W; ++k) {

    if (!__afl_cmp_map->headers[k].hits) continue;
    if (__afl_cmp_map->headers[k].type != CMP_TYPE_RTN) continue;
    /* Cast log[k][0] (a struct cmp_operands by default) to cmpfn_operands —
       same memory; we set up shape=7 so the bytes are at v0[0..7], v1[0..7]. */
    struct cmpfn_operands *op =
        (struct cmpfn_operands *)&__afl_cmp_map->log[k][0];
    uint64_t s = 0, o = 0;
    for (uint32_t i = 0; i < 8; ++i) {

      s |= (uint64_t)op->v0[i] << (i * 8);
      o |= (uint64_t)op->v1[i] << (i * 8);

    }

    if (s == 64) {

      ++found;
      got_size = s;
      got_off = o;
      break;

    }

  }

  fprintf(stderr,
          "BUG_ALLOCSIZE_DERIVE: found=%u size=%llu off=%llu writelen=%u\n",
          found, (unsigned long long)got_size, (unsigned long long)got_off,
          writelen);
  return found ? 0 : 1;

}

