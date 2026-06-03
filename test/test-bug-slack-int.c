// test/test-bug-slack-int.c
// Integer SLACK should reward inputs that get closer to a guarded magic value.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern uint32_t *__afl_bug_map;
extern uint8_t   __afl_bug_active;

__attribute__((noinline, optnone)) int target_cmp(uint64_t x) {

  return x == 0x12345678ULL;

}

int main(int argc, char **argv) {

  if (argc != 2) return 2;
  uint64_t x = strtoull(argv[1], NULL, 0);

  /* The bug pass deliberately ignores allow/deny lists, so every icmp in this
     process (argc!=2, strtoull internals, libc) also receives a SLACK hook and
     writes into __afl_bug_map.  To measure ONLY target_cmp's slack gradient,
     clear the map immediately before the call and snapshot it immediately
     after with memcpy (memcpy emits no icmp, so the snapshot captures exactly
     target_cmp's contribution).  Every comparison in the measurement below
     reads the frozen snapshot, so it cannot perturb the result. */
  static uint32_t snap[1U << 14];
  int             active = (__afl_bug_active && __afl_bug_map) ? 1 : 0;
  uint32_t       *bm = active ? __afl_bug_map : snap;
  memset(bm, 0, sizeof(snap));
  int r = target_cmp(x);
  memcpy(snap, bm, sizeof(snap));

  uint32_t maxval = 0;
  if (active)
    for (uint32_t i = 0; i < (1U << 14); ++i)
      if (snap[i] > maxval) maxval = snap[i];

  fprintf(stderr, "BUG_SLACK_INT: x=%llu maxval=%u result=%d\n",
          (unsigned long long)x, maxval, r);
  return 0;

}

