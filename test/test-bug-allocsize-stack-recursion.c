// test/test-bug-allocsize-stack-recursion.c
// Bug 27 TN: a recursive function with a stack alloca must not exhaust
// the runtime's allocation record table.  Each recursive call's
// register/unregister pair frees its slot before the function returns,
// so live records are bounded by stack depth × allocas-per-frame.
//
// We recurse 50 levels deep with one 16-byte alloca per frame and
// touch one in-bounds byte at each level.  Must complete with rc=0.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__attribute__((noinline, optnone))
static int recurse(int depth, uint8_t key) {

  /* 64-byte buffer (one shadow granule) so registration paints exactly
     this buffer and not adjacent stack slots. */
  uint8_t buf[64] = {0};
  buf[depth & 0x3f] = key;             /* in-bounds touch */
  if (depth <= 0) return (int)buf[0];
  return recurse(depth - 1, key) + (int)buf[depth & 0x3f];

}

int main(void) {

  uint8_t in[4] = {0};
  if (read(0, in, 4) != 4) return 1;
  int v = recurse(50, in[0]);
  fprintf(stderr, "BUG_ALLOCSIZE_STACK_RECURSION: v=%d\n", v);
  return 0;

}
