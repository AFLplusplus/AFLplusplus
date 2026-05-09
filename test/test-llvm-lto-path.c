/*
   AFL++ LTO PATH coverage test target
   ------------------------------------

   Functions with known acyclic-path counts (Ball-Larus):

   - straight()    : 1 path  (must be skipped — single-path)
   - if_chain()    : 8 paths (3 independent if/else; 2*2*2)
   - loop_path()   : 2 paths (loop body has 1 if; back-edge stripped)
   - early_exit() : 2 exit kinds (return + abort) — both must instrument
   - switch_func() : 5 paths (5-case switch); also exercises simplification
                       when forced onto a small-cap (separate test)
   - bigly_paths() : >100,000 paths (20+ independent if/else); skipped
                     after simplification with a warning

   Each non-trivial function is called from main() so it has 1 caller.
   For CALLER-composition tests we have a function called twice.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__attribute__((noinline)) int straight(unsigned char x) {

  /* No branches — single path. */
  return x + 1;

}

__attribute__((noinline)) int if_chain(unsigned char x) {

  int s = 0;
  if (x & 1) { s += 1; }
  if (x & 2) { s += 2; }
  if (x & 4) { s += 4; }
  return s;  /* 2*2*2 = 8 paths */

}

__attribute__((noinline)) int loop_path(unsigned char x) {

  int s = 0;
  for (int i = 0; i < (x & 7); i++) {

    if (i & 1) { s += 1; }
    else { s += 2; }

  }
  return s;  /* loop back-edge stripped → 2 paths through one iteration */

}

__attribute__((noinline)) int early_exit(unsigned char x) {

  if (x == 0xee) { abort(); }  /* noreturn — path-id must be written before */
  if (x & 1) return 1;
  return 0;

}

__attribute__((noinline)) int switch_func(unsigned char x) {

  switch (x & 7) {

    case 0: return 10;
    case 1: return 11;
    case 2: return 12;
    case 3: return 13;
    default: return 14;

  }
  /* 5 distinct exit BBs from a switch → 5 paths */

}

/* Big function: 20 independent if/else.  NumPaths = 2^20 = 1,048,576.
   No multi-way branches, so simplification cannot reduce it.  Must be
   skipped with a warning. */
__attribute__((noinline)) int bigly_paths(unsigned char *buf) {

  int s = 0;
#define BIT(N) if (buf[0] & (1u << ((N) & 7))) { s += (N); }
  BIT(0); BIT(1); BIT(2); BIT(3); BIT(4);
  BIT(5); BIT(6); BIT(7); BIT(8); BIT(9);
  BIT(10); BIT(11); BIT(12); BIT(13); BIT(14);
  BIT(15); BIT(16); BIT(17); BIT(18); BIT(19);
#undef BIT
  return s;

}

/* Function called twice from main() so CALLER composition kicks in. */
__attribute__((noinline)) int twocall(unsigned char x) {

  if (x & 1) { return x + 100; }
  return x + 200;
  /* 2 paths */

}

int main(int argc, char **argv) {

  unsigned char buf[1] = {0};
  if (read(0, buf, 1) <= 0) return 2;

  int sum = 0;
  sum += straight(buf[0]);
  sum += if_chain(buf[0]);
  sum += loop_path(buf[0]);
  sum += early_exit(buf[0]);
  sum += switch_func(buf[0]);
  sum += bigly_paths(buf);
  sum += twocall(buf[0]);
  sum += twocall(buf[0] ^ 0xff);

  return sum & 0xff;

}
