// ALLOCSIZE stack-alloca tracking: a 4-byte write spanning the end of
// a 64-byte stack buffer must trip the soft-OOB oracle.  Enabled by
// default under ALLOCSIZE; AFL_LLVM_BUG_ALLOCSIZE_STACK=0 opts out.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__attribute__((noinline, optnone)) static void do_oob(uint8_t key) {

  /* 64-byte buffer = one whole shadow granule, so registration paints
     exactly granule 0.  The 4-byte write at offset 62 spans the end. */
  uint8_t  buf[64] = {0};
  uint32_t off = 62u + ((uint32_t)key & 3u);
  memcpy(buf + off, "DEAD", 4);
  fprintf(stderr, "BUG_ALLOCSIZE_STACK_OOB: wrote_at=%u first_byte=%02x\n", off,
          (unsigned)buf[off]);

}

int main(void) {

  uint8_t in[4] = {0};
  if (read(0, in, 4) != 4) return 1;
  do_oob(in[0]);
  return 0;

}

