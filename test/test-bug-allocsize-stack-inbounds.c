// ALLOCSIZE stack-alloca TN: same shape as the OOB test, but the
// write lands strictly inside the buffer — must not abort.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__attribute__((noinline, optnone)) static void do_inbounds(uint8_t key) {

  uint8_t  buf[64] = {0};
  uint32_t off = 12u + ((uint32_t)key & 3u);
  memcpy(buf + off, "OKOK", 4);
  fprintf(stderr, "BUG_ALLOCSIZE_STACK_INBOUNDS: wrote_at=%u first_byte=%02x\n",
          off, (unsigned)buf[off]);

}

int main(void) {

  uint8_t in[4] = {0};
  if (read(0, in, 4) != 4) return 1;
  do_inbounds(in[0]);
  return 0;

}

