// ALLOCSIZE stack-alloca TN: deep recursion with a per-frame alloca
// must not exhaust the runtime's allocation record table — each call's
// register/unregister pair frees its slot before the function returns.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__attribute__((noinline, optnone)) static int recurse(int depth, uint8_t key) {

  uint8_t buf[64] = {0};
  buf[depth & 0x3f] = key;
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

