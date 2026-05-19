// ALLOCSIZE tracks anonymous mmap regions (used by v8, jemalloc
// internals, custom arenas).  A 32-byte allocation with a 4-byte
// write at offset 30 spans [30, 34); the OOB stays inside the same
// painted shadow granule as the alloc so the oracle finds the record.
// Writes ≫ granule_size past the end land in unpainted granules and
// slip past — a known granule-shadow precision limitation.
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static uint8_t *volatile g_sink;

int main(void) {

  uint8_t buf[4] = {0};
  if (read(0, buf, 4) != 4) return 1;
  /* Anonymous, fd=-1, size 32. */
  uint8_t *p = (uint8_t *)mmap(NULL, 32, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED) return 2;
  /* Data-dependent OOB store at p[30..33]: spans the buffer end (32).
     The store's address is still inside the painted granule 0, so the
     shadow lookup finds the right idx and the soft-OOB tripwire fires
     on `addr + sz > end`. */
  uint32_t n = 30u + ((uint32_t)buf[0] & 3u);
  memcpy(p + n, "DEAD", 4);
  g_sink = p;
  fprintf(stderr, "BUG_ALLOCSIZE_MMAP: wrote_at=%u\n", n);
  munmap(p, 32);
  return 0;

}

