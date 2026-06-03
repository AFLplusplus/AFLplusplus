// test/test-bug-allocsize-custom.c
// MyAlloc just calls malloc but the pass cannot tell that. With
// AFL_LLVM_BUG_ALLOCSIZE_FUNCS=MyAlloc, the pass should insert
// __afl_alloc_register at the call site. A 70-byte write into a 64-byte
// MyAlloc must trip the soft-OOB.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static uint8_t *volatile g_sink;

/* External linkage prevents -O3 dead-arg-elimination, mirroring how real
   custom allocators like WebPSafeMalloc would be visible from other TUs. */
__attribute__((noinline, optnone)) void *MyAlloc(uint64_t size) {

  return malloc((size_t)size);

}

__attribute__((noinline, optnone)) void MyFree(void *p) {

  free(p);

}

int main(void) {

  uint8_t buf[4] = {0};
  if (read(0, buf, 4) != 4) return 1;
  /* Runtime-dependent size for MyAlloc so IPO can't drop the arg.
     Always allocates 64 bytes (the high bits are masked). */
  uint64_t allocsz = 64u | ((uint64_t)buf[1] << 32) >> 32 << 0;       /* 64 */
  /* Force allocsz to depend on input but still equal 64. */
  allocsz = 64u + ((uint32_t)buf[1] & 0u);
  uint32_t n = 70u + ((uint32_t)buf[0] & 7u);                /* always > 64 */
  uint8_t *p = (uint8_t *)MyAlloc(allocsz);
  if (!p) return 2;
  for (uint32_t i = 0; i < n; ++i)
    p[i] = (uint8_t)(buf[0] + i);
  g_sink = p;
  fprintf(stderr, "BUG_ALLOCSIZE_CUSTOM: wrote=%u\n", n);
  MyFree(p);
  return 0;

}

