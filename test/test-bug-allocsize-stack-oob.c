// test/test-bug-allocsize-stack-oob.c
// Bug 27 (Tier 3 item 2): ALLOCSIZE used to register heap-class
// allocations only. A stack `uint8_t buf[32]` with a 4-byte write
// spanning the end (offset 30..33) silently slipped past the oracle.
// Stack-alloca tracking adds entry/exit __afl_alloc_register/_unregister
// pairs so the existing store-oracle catches stack OOB.
//
// TP: data-dependent 4-byte write at offset 30 spans the 32-byte
// buffer end; the per-store oracle (already inserted by ALLOCSIZE
// Phase 2) finds the registered record, sees addr+sz > end, and
// _exit(134)s with "ALLOCSIZE soft-OOB".
//
// Gated to require AFL_LLVM_BUG_ALLOCSIZE_STACK != "0" (default on
// when ALLOCSIZE is enabled). Setting it to "0" must restore the
// pre-fix behavior (silent rc=0).
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__attribute__((noinline, optnone))
static void do_oob(uint8_t key) {

  /* 64-byte buffer: a whole shadow granule, so the registration paints
     exactly granule 0 and only granule 0.  The 4-byte write at offset
     62 covers bytes 62..65; the trailing 2 bytes are past the allocated
     extent and the soft-OOB oracle trips on `addr + sz > end`. */
  uint8_t buf[64] = {0};
  uint32_t off = 62u + ((uint32_t)key & 3u);
  memcpy(buf + off, "DEAD", 4);
  /* Sink so the optimizer cannot eliminate the write. */
  fprintf(stderr,
          "BUG_ALLOCSIZE_STACK_OOB: wrote_at=%u first_byte=%02x\n",
          off, (unsigned)buf[off]);

}

int main(void) {

  uint8_t in[4] = {0};
  if (read(0, in, 4) != 4) return 1;
  do_oob(in[0]);
  return 0;

}
