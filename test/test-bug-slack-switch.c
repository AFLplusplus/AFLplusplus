// SLACK on SwitchInst: inputs closer to a known case value must get a
// strictly higher SLACK map signal than inputs far from every case.
// Clang emits a `switch` terminator (not a chain of icmps) for dense
// opcode dispatchers, so SLACK must instrument SwitchInst directly.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern uint32_t *__afl_bug_map;
extern uint8_t   __afl_bug_active;

__attribute__((noinline, optnone)) int target_switch(uint32_t x) {

  switch (x) {

    case 0x1000:
      return 1;
    case 0x2000:
      return 2;
    case 0x3000:
      return 3;
    case 0x4000:
      return 4;
    case 0x5000:
      return 5;
    case 0x6000:
      return 6;
    case 0x7000:
      return 7;
    case 0x8000:
      return 8;
    case 0x9000:
      return 9;
    case 0xa000:
      return 10;
    case 0xb000:
      return 11;
    default:
      return 0;

  }

}

int main(int argc, char **argv) {

  if (argc != 2) return 2;
  uint32_t x = (uint32_t)strtoul(argv[1], NULL, 0);

  /* The bug pass deliberately ignores allow/deny lists, so every icmp/switch in
     this process also receives a SLACK hook and writes into __afl_bug_map.  To
     measure ONLY target_switch's slack gradient, clear the map immediately
     before the call and snapshot it immediately after with memcpy (no icmp), so
     the snapshot captures exactly target_switch's contribution.  The
     measurement below reads the frozen snapshot. */
  static uint32_t snap[1U << 14];
  int             active = (__afl_bug_active && __afl_bug_map) ? 1 : 0;
  uint32_t       *bm = active ? __afl_bug_map : snap;
  memset(bm, 0, sizeof(snap));
  int r = target_switch(x);
  memcpy(snap, bm, sizeof(snap));

  uint32_t maxval = 0;
  if (active)
    for (uint32_t i = 0; i < (1U << 14); ++i)
      if (snap[i] > maxval) maxval = snap[i];

  fprintf(stderr, "BUG_SLACK_SWITCH: x=0x%x maxval=%u result=%d\n", x, maxval,
          r);
  return 0;

}

