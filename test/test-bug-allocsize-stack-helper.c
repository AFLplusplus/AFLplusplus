// test/test-bug-allocsize-stack-helper.c
// Bug 27 TN: a stack array passed to a noinline helper must be
// registered EXACTLY ONCE — by the function that declares the alloca.
// The helper sees only a pointer arg; it has no alloca of its own and
// must not re-register the buffer.
//
// We verify two ways:
//   (a) Runtime: in-bounds writes in the helper produce rc=0.
//   (b) Static IR: only one __afl_alloc_register call site lands on a
//       pointer derived from the buf[64] alloca. The test-bug-pass.sh
//       harness counts __afl_alloc_register call sites in the helper's
//       IR — must equal 0 (the alloca lives in caller_main, not helper).
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__attribute__((noinline, optnone))
static void writer_helper(uint8_t *p, uint8_t key) {

  /* Helper has no alloca of its own; it must NOT re-register p.
     Write in-bounds. */
  uint32_t off = 4u + ((uint32_t)key & 3u);
  memcpy(p + off, "HELO", 4);

}

__attribute__((noinline, optnone))
static void caller_main(uint8_t key) {

  uint8_t buf[64] = {0};                /* one alloca, one register */
  writer_helper(buf, key);
  fprintf(stderr,
          "BUG_ALLOCSIZE_STACK_HELPER: buf[5]=%02x\n",
          (unsigned)buf[5]);

}

int main(void) {

  uint8_t in[4] = {0};
  if (read(0, in, 4) != 4) return 1;
  caller_main(in[0]);
  return 0;

}
