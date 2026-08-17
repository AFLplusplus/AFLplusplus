/*
   AFL++ LTO PATH coverage test target
   ------------------------------------

   Functions with known acyclic-path counts (Ball-Larus):

   - straight()    : 1 path  (must be skipped — single-path)
   - if_chain()    : 8 paths (3 independent if/else; 2*2*2)
   - loop_path()   : 2 paths (loop body has 1 if; back-edge stripped)
   - early_exit()  : 3 paths (abort, return 1, return 0). Both exit kinds
                       (return + noreturn call) must be instrumented.
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
  return s;                                              /* 2*2*2 = 8 paths */

}

__attribute__((noinline)) int loop_path(unsigned char x) {

  int s = 0;
  for (int i = 0; i < (x & 7); i++) {

    if (i & 1) {

      s += 1;

    } else {

      s += 2;

    }

  }

  return s;      /* loop back-edge stripped → 2 paths through one iteration */

}

__attribute__((noinline)) int early_exit(unsigned char x) {

  if (x == 0xee) { abort(); }  /* noreturn — path-id must be written before */
  if (x & 1) return 1;
  return 0;

}

__attribute__((noinline)) int switch_func(unsigned char x) {

  switch (x & 7) {

    case 0:
      return 10;
    case 1:
      return 11;
    case 2:
      return 12;
    case 3:
      return 13;
    default:
      return 14;

  }

  /* 5 distinct exit BBs from a switch → 5 paths */

}

/* Big function: 20 independent if/else.  NumPaths = 2^20 = 1,048,576.
   No multi-way branches, so simplification cannot reduce it.  Must be
   skipped with a warning. */
__attribute__((noinline)) int bigly_paths(unsigned char *buf) {

  int s = 0;
#define BIT(N) \
  if (buf[0] & (1u << ((N) & 7))) { s += (N); }
  BIT(0);
  BIT(1);
  BIT(2);
  BIT(3);
  BIT(4);
  BIT(5);
  BIT(6);
  BIT(7);
  BIT(8);
  BIT(9);
  BIT(10);
  BIT(11);
  BIT(12);
  BIT(13);
  BIT(14);
  BIT(15);
  BIT(16);
  BIT(17);
  BIT(18);
  BIT(19);
#undef BIT
  return s;

}

/* Function called twice from main() so CALLER composition kicks in. */
__attribute__((noinline)) int twocall(unsigned char x) {

  if (x & 1) { return x + 100; }
  return x + 200;
  /* 2 paths */

}

/* Has a 2-successor branch where BOTH arms perform a side-effecting call.
   The if-BB itself is guard-only (just load+and+cmp+br), but each arm
   contains a call -> the branch decision still multiplies path counts
   even under PATH=1 (relaxed). Provides a function whose path count is
   greater than 1 in ALL three modes, exercising emit on PATH=1. */
__attribute__((noinline)) int multi_path_sideeffect(unsigned char x) {

  int s = 0;
  if (x & 1) {

    s += (int)write(2, "", 0);
    s += 1;

  } else {

    s += (int)write(2, "", 0);
    s += 2;

  }

  return s;

}

/* 1500 sequentially-chained basic blocks via a switch fallthrough cascade.
   No branching after the entry switch — NumPaths(entry) collapses (level=1
   guard-only switch -> 1, or remains the switch's case count at level=3)
   but the analysis pass still has to walk every BB. If the back-edge DFS
   or NumPaths walk is recursive, this triggers stack overflow on a default
   8 MB stack. With the iterative implementation it must compile cleanly. */
#define CHAIN1(n) \
  case n:         \
    s += n;                                                  /* fallthrough */
#define CHAIN10(n) \
  CHAIN1(n + 0)    \
  CHAIN1(n + 1)    \
  CHAIN1(n + 2)    \
  CHAIN1(n + 3)    \
  CHAIN1(n + 4)    \
  CHAIN1(n + 5) CHAIN1(n + 6) CHAIN1(n + 7) CHAIN1(n + 8) CHAIN1(n + 9)
#define CHAIN100(n) \
  CHAIN10(n + 0)    \
  CHAIN10(n + 10)   \
  CHAIN10(n + 20)   \
  CHAIN10(n + 30)   \
  CHAIN10(n + 40)   \
  CHAIN10(n + 50)   \
  CHAIN10(n + 60) CHAIN10(n + 70) CHAIN10(n + 80) CHAIN10(n + 90)
__attribute__((noinline)) int deep_chain(unsigned int x) {

  int s = 0;
  switch (x % 1500) {

    CHAIN100(0)
    CHAIN100(100)
    CHAIN100(200)
    CHAIN100(300)
    CHAIN100(400)
    CHAIN100(500)
    CHAIN100(600)
    CHAIN100(700)
    CHAIN100(800)
    CHAIN100(900)
    CHAIN100(1000) CHAIN100(1100) CHAIN100(1200) CHAIN100(1300)
        CHAIN100(1400) default : s += 9999;

  }

  return s;

}

#undef CHAIN1
#undef CHAIN10
#undef CHAIN100

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
  sum += multi_path_sideeffect(buf[0]);
  sum += deep_chain(buf[0]);

  return sum & 0xff;

}

