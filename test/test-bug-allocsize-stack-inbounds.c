// test/test-bug-allocsize-stack-inbounds.c
// Bug 27 TN: same stack-alloca shape as the OOB test, but the write
// lands strictly inside the buffer (offset 12..15 of a 32-byte
// buffer). With ALLOCSIZE+stack instrumentation the register/unregister
// pair fires and the store-oracle sees the in-bounds extent — must
// NOT abort.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__attribute__((noinline, optnone))
static void do_inbounds(uint8_t key) {

  /* 64-byte buffer: registered, write strictly inside. */
  uint8_t buf[64] = {0};
  uint32_t off = 12u + ((uint32_t)key & 3u);  /* 12..15 — well inside */
  memcpy(buf + off, "OKOK", 4);
  fprintf(stderr,
          "BUG_ALLOCSIZE_STACK_INBOUNDS: wrote_at=%u first_byte=%02x\n",
          off, (unsigned)buf[off]);

}

int main(void) {

  uint8_t in[4] = {0};
  if (read(0, in, 4) != 4) return 1;
  do_inbounds(in[0]);
  return 0;

}
