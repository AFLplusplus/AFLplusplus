// ALLOCSIZE stack-alloca TN: a stack array passed to a noinline helper
// must be registered EXACTLY ONCE by the function that declares the
// alloca.  The helper sees only a pointer arg and must not re-register
// it.  Verified via runtime rc=0 and a static count of
// __afl_alloc_register call sites (must equal 1).
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__attribute__((noinline, optnone)) static void writer_helper(uint8_t *p,
                                                             uint8_t  key) {

  uint32_t off = 4u + ((uint32_t)key & 3u);
  memcpy(p + off, "HELO", 4);

}

__attribute__((noinline, optnone)) static void caller_main(uint8_t key) {

  uint8_t buf[64] = {0};
  writer_helper(buf, key);
  fprintf(stderr, "BUG_ALLOCSIZE_STACK_HELPER: buf[5]=%02x\n",
          (unsigned)buf[5]);

}

int main(void) {

  uint8_t in[4] = {0};
  if (read(0, in, 4) != 4) return 1;
  caller_main(in[0]);
  return 0;

}

