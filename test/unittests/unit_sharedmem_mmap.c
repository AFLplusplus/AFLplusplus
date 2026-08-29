#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
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

/* The descriptor a map was handed over on: it has to be a live, inheritable
   descriptor at or above SHM_FD_MIN that describes an object of at least
   `min_size` bytes. Returns 0 on any violation. */

static int handover_fd_ok(const char *env, size_t min_size) {

  const char *fd_str = getenv(env);
  struct stat st;
  int         fd;

  if (!fd_str || !*fd_str) {

    fprintf(stderr, "%s is not set\n", env);
    return 0;

  }

  fd = atoi(fd_str);

  if (fd < SHM_FD_MIN) {

    fprintf(stderr, "%s=%d is below SHM_FD_MIN (%d)\n", env, fd, SHM_FD_MIN);
    return 0;

  }

  if (fd == FORKSRV_FD || fd == FORKSRV_FD + 1) {

    fprintf(stderr, "%s=%d collides with the forkserver pipes\n", env, fd);
    return 0;

  }

  if (fstat(fd, &st) != 0) {

    fprintf(stderr, "%s=%d is not open: %s\n", env, fd, strerror(errno));
    return 0;

  }

  if ((size_t)st.st_size < min_size) {

    fprintf(stderr, "%s=%d is %lld bytes, expected at least %zu\n", env, fd,
            (long long)st.st_size, min_size);
    return 0;

  }

  /* Without this the descriptor would not survive the execv() into the
     target, which is the entire point of handing it over. */

  if (fcntl(fd, F_GETFD) & FD_CLOEXEC) {

    fprintf(stderr, "%s=%d has FD_CLOEXEC set\n", env, fd);
    return 0;

  }

  return 1;

}

/* The name must be gone the moment the map is handed over, so a SIGKILLed
   tool cannot leave it behind. */

static int name_is_unlinked(const char *path) {

  int fd;

  if (!path || !*path) { return 1; }

  fd = shm_open(path, O_RDWR, 0600);

  if (fd >= 0) {

    fprintf(stderr, "%s still exists\n", path);
    close(fd);
    shm_unlink(path);
    return 0;

  }

  return 1;

}

int main(void) {

  sharedmem_t shm;
  memset(&shm, 0, sizeof(shm));
  shm.cmplog_mode = 1;

  if (!afl_shm_init(&shm, 65536, 0, 0600, -1)) { return 1; }
  if (shm.map_alloc_size <= shm.map_size ||
      shm.cmp_map_alloc_size != sizeof(struct cmp_map)) {

    return 2;

  }

  /* Both maps have to reach the target as inherited descriptors, and both
     names have to be unlinked already. */

  if (!handover_fd_ok(SHM_FD_ENV_VAR, shm.map_alloc_size)) { return 6; }
  if (!handover_fd_ok(CMPLOG_SHM_FD_ENV_VAR, sizeof(struct cmp_map))) {

    return 7;

  }

  if (shm.g_shm_fd < 0 || shm.cmplog_g_shm_fd < 0) { return 8; }
  if (!name_is_unlinked(shm.g_shm_file_path)) { return 9; }
  if (!name_is_unlinked(shm.cmplog_g_shm_file_path)) { return 10; }

  /* The names are still advertised so that "am I running under AFL++?" checks
     keep working and a target built by an older afl-cc gets a readable
     shm_open() error instead of silently running uninstrumented. */

  if (strcmp(getenv(SHM_ENV_VAR), shm.g_shm_file_path) ||
      strcmp(getenv(CMPLOG_SHM_ENV_VAR), shm.cmplog_g_shm_file_path)) {

    return 11;

  }

  int trace_fd = shm.g_shm_fd, cmplog_fd = shm.cmplog_g_shm_fd;

#ifdef __linux__
  size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
  void  *map_tail = (void *)((uintptr_t)shm.map + shm.map_alloc_size - 1);
  map_tail = (void *)((uintptr_t)map_tail & ~(page_size - 1));
  void *cmp_tail =
      (void *)((uintptr_t)shm.cmp_map + shm.cmp_map_alloc_size - 1);
  cmp_tail = (void *)((uintptr_t)cmp_tail & ~(page_size - 1));

  if (!mapped(map_tail) || !mapped(cmp_tail)) { return 3; }
#endif

  afl_shm_deinit(&shm);

#ifdef __linux__
  if (mapped(map_tail) || mapped(cmp_tail)) { return 4; }
#endif

  if (shm.map || shm.cmp_map || shm.map_alloc_size || shm.cmp_map_alloc_size ||
      shm.child_sync || shm.child_sync_offset) {

    return 5;

  }

  /* deinit drops the last reference to both maps and stops advertising them. */

  if (shm.g_shm_fd != -1 || shm.cmplog_g_shm_fd != -1) { return 12; }
  if (fcntl(trace_fd, F_GETFD) != -1 || fcntl(cmplog_fd, F_GETFD) != -1) {

    return 13;

  }

  if (getenv(SHM_FD_ENV_VAR) || getenv(CMPLOG_SHM_FD_ENV_VAR) ||
      getenv(SHM_ENV_VAR)) {

    return 14;

  }

  /* afl-fuzz re-creates the maps whenever the target reports a bigger one, so
     the descriptors have to be recycled rather than climbing out of the
     reserved range with every round. */

  for (int i = 0; i < 64; ++i) {

    sharedmem_t again;
    memset(&again, 0, sizeof(again));
    again.cmplog_mode = 1;

    if (!afl_shm_init(&again, 65536, 0, 0600, -1)) { return 15; }

    if (again.g_shm_fd >= SHM_FD_MIN + SHM_FD_COUNT ||
        again.cmplog_g_shm_fd >= SHM_FD_MIN + SHM_FD_COUNT) {

      fprintf(stderr, "round %d leaked descriptors: %d / %d\n", i,
              again.g_shm_fd, again.cmplog_g_shm_fd);
      afl_shm_deinit(&again);
      return 16;

    }

    afl_shm_deinit(&again);

  }

  return 0;

}

