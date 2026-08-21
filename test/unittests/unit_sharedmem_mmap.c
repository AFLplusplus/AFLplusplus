#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "types.h"
#include "cmplog.h"
#include "sharedmem.h"

#ifdef __linux__

static int mapped(void *address) {

  unsigned char value = 0;
  errno = 0;
  return mincore(address, (size_t)sysconf(_SC_PAGESIZE), &value) == 0;

}

#endif

int main(void) {

#ifndef __linux__
  return 0;
#else
  sharedmem_t shm;
  memset(&shm, 0, sizeof(shm));
  shm.cmplog_mode = 1;

  if (!afl_shm_init(&shm, 65536, 0, 0600, -1)) { return 1; }
  if (shm.map_alloc_size <= shm.map_size ||
      shm.cmp_map_alloc_size != sizeof(struct cmp_map)) {

    return 2;

  }

  size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
  void  *map_tail = (void *)((uintptr_t)shm.map + shm.map_alloc_size - 1);
  map_tail = (void *)((uintptr_t)map_tail & ~(page_size - 1));
  void *cmp_tail =
      (void *)((uintptr_t)shm.cmp_map + shm.cmp_map_alloc_size - 1);
  cmp_tail = (void *)((uintptr_t)cmp_tail & ~(page_size - 1));

  if (!mapped(map_tail) || !mapped(cmp_tail)) { return 3; }
  afl_shm_deinit(&shm);
  if (mapped(map_tail) || mapped(cmp_tail)) { return 4; }
  if (shm.map || shm.cmp_map || shm.map_alloc_size || shm.cmp_map_alloc_size ||
      shm.child_sync || shm.child_sync_offset) {

    return 5;

  }

  return 0;
#endif

}

