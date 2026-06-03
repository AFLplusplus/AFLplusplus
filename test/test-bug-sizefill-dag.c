// test/test-bug-sizefill-dag.c
//
// Exercises SIZEFILL on a call whose sentinel-arg pointer arrives via a
// PHI whose two arms eventually re-converge on the same malloc. With a
// too-aggressive visited-set in inferBufferSizeValue, the second PHI arm
// hits a value already inserted by the first arm and returns nullptr —
// SIZEFILL silently skips the call site and the resulting OOB write is
// not flagged.
//
// build_table_bad: lies (returns 16, actually writes 18). Caller's
// effective buffer is 16 entries. A correctly-wired SIZEFILL aborts on
// the post-call check.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((noinline, optnone)) static uint32_t build_table_bad(
    uint32_t *out, uint32_t n) {

  if (out == NULL) return 16;
  for (uint32_t i = 0; i < 18; ++i)
    out[i] = (uint32_t)(i + n);
  return 16;

}

int main(void) {

  uint8_t buf[4] = {0};
  if (read(0, buf, 4) != 4) return 1;
  uint32_t n = (uint32_t)buf[0];

  uint32_t  need = build_table_bad(NULL, n);
  uint32_t *p1 = (uint32_t *)malloc(16 * sizeof(uint32_t));
  if (!p1) return 2;

  // DAG: clang at -O0 lowers the ternary `cond ? p1 : p1` to a real
  // phi whose two arms are two distinct loads from the p1 spill slot
  // — i.e. both arms eventually re-converge on the same malloc. With
  // a too-aggressive visited-set, the recursion adds the first arm's
  // load to `visited`, then refuses to walk the second arm's load
  // because that load (or the alloca it goes through) is already
  // there. inferBufferSizeValue returns nullptr and the sentinel
  // call is silently skipped.
  uint32_t *p2 = (n & 1u) ? p1 : p1;

  uint32_t got = build_table_bad(p2, n);
  fprintf(stderr, "BUG_SIZEFILL_DAG: need=%u got=%u\n", need, got);
  free(p1);
  return 0;

}

