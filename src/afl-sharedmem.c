/*
   american fuzzy lop++ - shared memory related code
   -------------------------------------------------

   Originally written by Michal Zalewski

   Forkserver design by Jann Horn <jannhorn@googlemail.com>

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eissfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2026 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

   Shared code to handle the shared memory. This is used by the fuzzer
   as well the other components like afl-tmin, afl-showmap, etc...

 */

#define AFL_MAIN

#ifdef __ANDROID__
  #include "android-ashmem.h"
#endif
#include "config.h"
#include "types.h"
#include "debug.h"
#include "alloc-inl.h"
#include "hash.h"
#include "sharedmem.h"
#include "cmplog.h"
#include "list.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h>
#include <fcntl.h>

#include <sys/wait.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/mman.h>

#ifndef USEMMAP
  #include <sys/ipc.h>
  #include <sys/shm.h>
#endif

/* Drop the SysV segment the moment it is attached so a SIGKILLed tool cannot
   leak it. Linux only, and deliberately so: only Linux still lets a process
   shmat() a segment that is already marked for destruction. On the BSDs and
   macOS the IPC_RMID would make the target's shmat() fail, so those platforms
   get the same "nothing survives" guarantee from the POSIX shared memory /
   descriptor handover below (see afl_shm_handover_fd) instead. */

#if defined(__linux__) && !defined(__ANDROID__) && !defined(USEMMAP)
  #define AFL_SHM_AUTO_RECLAIM(id) shmctl((id), IPC_RMID, NULL)
#else
  #define AFL_SHM_AUTO_RECLAIM(id) ((void)0)
#endif

static list_t shm_list = {.element_prealloc_count = 0};

#ifdef USEMMAP

/* Should the POSIX shared memory objects keep their name for the lifetime of
   the session? Set AFL_SHM_KEEP_NAME=1 when the target was built by an afl-cc
   that predates the descriptor handover: such a target only knows how to
   shm_open() the name from SHM_ENV_VAR and cannot find an unlinked object. */

static u8 afl_shm_keep_name(void) {

  static s8 keep = -1;

  if (keep < 0) {

    char *ptr = getenv("AFL_SHM_KEEP_NAME");
    keep = (ptr && *ptr && *ptr != '0') ? 1 : 0;

  }

  return (u8)keep;

}

/* Move a freshly created shared map onto a descriptor the target can inherit.

   The duplicate is allocated at or above SHM_FD_MIN so it can never collide
   with the forkserver pipes on FORKSRV_FD / FORKSRV_FD + 1, and FD_CLOEXEC is
   cleared on it so it survives the execv() into the target. The original
   descriptor is closed on success.

   Returns the new descriptor, or -1 if the map has to be handed over by name
   after all - in which case the caller keeps the object linked. */

static int afl_shm_reserve_fd(int fd) {

  if (fd < 0) { return -1; }

  int new_fd = fcntl(fd, F_DUPFD, SHM_FD_MIN);

  if (new_fd < 0 && (errno == EMFILE || errno == EINVAL)) {

    /* The soft descriptor limit is below our range - OpenBSD hands root a
       soft limit of 128, macOS defaults to 256. Raise it once and retry. */

    struct rlimit r;

    if (!getrlimit(RLIMIT_NOFILE, &r) &&
        r.rlim_cur < (rlim_t)(SHM_FD_MIN + SHM_FD_COUNT)) {

      rlim_t want = (rlim_t)(SHM_FD_MIN + SHM_FD_COUNT);

      if (r.rlim_max != RLIM_INFINITY && want > r.rlim_max) {

        want = r.rlim_max;

      }

      if (want > r.rlim_cur) {

        r.rlim_cur = want;
        if (!setrlimit(RLIMIT_NOFILE, &r)) {

          new_fd = fcntl(fd, F_DUPFD, SHM_FD_MIN);

        }

      }

    }

  }

  if (new_fd < 0) { return -1; }

  /* F_DUPFD already hands out a descriptor with FD_CLOEXEC clear, but the whole
     point of this descriptor is that it survives the exec, so be explicit.
     Clear it before dropping the original, so that a failure here hands the
     caller back exactly the descriptor it came in with. */

  if (fcntl(new_fd, F_SETFD, 0) < 0) {

    close(new_fd);
    return -1;

  }

  close(fd);

  return new_fd;

}

/* Hand a just-mmap()ed POSIX shared memory object to the target as an
   inherited descriptor and drop its name right away, so neither a SIGKILL nor
   a crash of this process can leave anything behind in /dev/shm.

   On success *map_fd holds the inheritable descriptor and the object is
   unlinked. On failure - or when AFL_SHM_KEEP_NAME asks for it - *map_fd is
   closed and set to -1 and the object keeps its name, which is how targets
   built by an older afl-cc reach the map. afl_shm_deinit() uses exactly that
   distinction to decide whether an unlink is still owed. */

static void afl_shm_handover_fd(int *map_fd, const char *path) {

  int fd = afl_shm_keep_name() ? -1 : afl_shm_reserve_fd(*map_fd);

  if (fd < 0) {

    if (*map_fd >= 0) { close(*map_fd); }
    *map_fd = -1;
    return;

  }

  *map_fd = fd;
  shm_unlink(path);

}

#endif                                                          /* ^USEMMAP */

/* Export the number of an inheritable shared map descriptor. */

void afl_shm_env_set_fd(const char *env, int fd) {

#ifdef USEMMAP

  if (!env || fd < 0) { return; }

  u8 *fd_str = alloc_printf("%d", fd);
  setenv(env, (char *)fd_str, 1);
  ck_free(fd_str);

#else

  (void)env;
  (void)fd;

#endif

}

/* Export the handover of the shared memory test case map. Unlike the coverage
   map this one is created in non_instrumented_mode - so that afl_shm_init()
   does not clobber SHM_ENV_VAR with it - and therefore has to publish itself
   here, once the caller has settled on it. */

void afl_shm_fuzz_env_set(sharedmem_t *shm) {

  if (!shm) { return; }

#ifdef USEMMAP

  setenv(SHM_FUZZ_ENV_VAR, shm->g_shm_file_path, 1);
  afl_shm_env_set_fd(SHM_FUZZ_FD_ENV_VAR, shm->g_shm_fd);

#else

  u8 *shm_str = alloc_printf("%d", shm->shm_id);
  setenv(SHM_FUZZ_ENV_VAR, (char *)shm_str, 1);
  ck_free(shm_str);

#endif

}

void afl_shm_vp_env_unset(void) {

  unsetenv(VP_SHM_ENV_VAR);
#ifdef USEMMAP
  unsetenv(VP_SHM_FD_ENV_VAR);
#endif

}

void afl_shm_vp_env_set(sharedmem_t *shm) {

  if (!shm || !shm->vp_mode || !shm->vp_map) { return; }

#ifdef USEMMAP

  if (shm->vp_g_shm_file_path[0]) {

    setenv(VP_SHM_ENV_VAR, shm->vp_g_shm_file_path, 1);

  }

  afl_shm_env_set_fd(VP_SHM_FD_ENV_VAR, shm->vp_g_shm_fd);

#else

  u8 *shm_str = alloc_printf("%d", shm->vp_shm_id);
  setenv(VP_SHM_ENV_VAR, shm_str, 1);
  ck_free(shm_str);

#endif

}

void afl_shm_deinit_all(void) {

  element_t *head = get_head(&shm_list);
  if (!head->next) { return; }

  while (head->next != head) {

    afl_shm_deinit((sharedmem_t *)head->next->data);

  }

}

/* Get rid of shared memory. */

void afl_shm_deinit(sharedmem_t *shm) {

  if (shm == NULL) { return; }
  list_remove(&shm_list, shm);
  if (shm->shmemfuzz_mode) {

    unsetenv(SHM_FUZZ_ENV_VAR);
    unsetenv(SHM_FUZZ_MAP_SIZE_ENV_VAR);
#ifdef USEMMAP
    unsetenv(SHM_FUZZ_FD_ENV_VAR);
#endif

  } else {

    unsetenv(SHM_ENV_VAR);
#ifdef USEMMAP
    unsetenv(SHM_FD_ENV_VAR);
#endif

  }

  if (shm->vp_mode) { afl_shm_vp_env_unset(); }

#ifdef USEMMAP
  if (shm->map != NULL) {

    munmap(shm->map, shm->map_alloc_size);
    shm->map = NULL;
    shm->map_alloc_size = 0;
    shm->child_sync = NULL;
    shm->child_sync_offset = 0;

  }

  /* A live descriptor means the object was already unlinked at creation and
     only the last reference has to go; otherwise the name is still there. */

  if (shm->g_shm_fd != -1) {

    close(shm->g_shm_fd);
    shm->g_shm_fd = -1;

  } else if (shm->g_shm_file_path[0]) {

    shm_unlink(shm->g_shm_file_path);

  }

  shm->g_shm_file_path[0] = 0;

  if (shm->cmplog_mode) {

    unsetenv(CMPLOG_SHM_ENV_VAR);
    unsetenv(CMPLOG_SHM_FD_ENV_VAR);

    if (shm->cmp_map != NULL) {

      munmap(shm->cmp_map, shm->cmp_map_alloc_size);
      shm->cmp_map = NULL;
      shm->cmp_map_alloc_size = 0;

    }

    if (shm->cmplog_g_shm_fd != -1) {

      close(shm->cmplog_g_shm_fd);
      shm->cmplog_g_shm_fd = -1;

    } else if (shm->cmplog_g_shm_file_path[0]) {

      shm_unlink(shm->cmplog_g_shm_file_path);

    }

    shm->cmplog_g_shm_file_path[0] = 0;

  }

  if (shm->vp_mode) {

    if (shm->vp_map != NULL) {

      munmap(shm->vp_map, sizeof(vp_map_t));
      shm->vp_map = NULL;

    }

    if (shm->vp_g_shm_fd != -1) {

      close(shm->vp_g_shm_fd);
      shm->vp_g_shm_fd = -1;

    } else if (shm->vp_g_shm_file_path[0]) {

      shm_unlink(shm->vp_g_shm_file_path);

    }

    shm->vp_g_shm_file_path[0] = 0;

  }

#else
  shmctl(shm->shm_id, IPC_RMID, NULL);
  if (shm->cmplog_mode) { shmctl(shm->cmplog_shm_id, IPC_RMID, NULL); }
  if (shm->vp_mode) { shmctl(shm->vp_shm_id, IPC_RMID, NULL); }
#endif

  shm->map = NULL;
  shm->cmp_map = NULL;
  shm->vp_map = NULL;
  shm->child_sync = NULL;
  shm->child_sync_offset = 0;

}

#ifndef USEMMAP
/* Release every SysV segment created so far. Called from the failure paths in
   afl_shm_init(), which PFATAL before the map is registered in shm_list, so
   at_exit() cleanup would never see them. Unset ids are -1 and skipped. */
static void afl_shm_release_partial(sharedmem_t *shm) {

  if (shm->shm_id >= 0) { shmctl(shm->shm_id, IPC_RMID, NULL); }
  if (shm->cmplog_mode && shm->cmplog_shm_id >= 0) {

    shmctl(shm->cmplog_shm_id, IPC_RMID, NULL);

  }

  if (shm->vp_mode && shm->vp_shm_id >= 0) {

    shmctl(shm->vp_shm_id, IPC_RMID, NULL);

  }

}

#endif

/* Configure shared memory.
   Returns a pointer to shm->map for ease of use.
*/

u8 *afl_shm_init(sharedmem_t *shm, size_t map_size,
                 unsigned char non_instrumented_mode, mode_t permission,
                 int gid) {

  shm->map_size = 0;

  shm->map = NULL;
  shm->cmp_map = NULL;
  shm->vp_map = NULL;
#ifndef USEMMAP
  shm->shm_id = -1;
  shm->cmplog_shm_id = -1;
  shm->vp_shm_id = -1;
#endif

  shm->child_sync_offset = 0;
  shm->child_sync = NULL;

  /* The persistent-mode futex/os_sync word is embedded in the last bytes of
     the trace_bits map so no separate shared segment is needed. Only reserve
     it for real coverage maps (not the shmem-fuzz input map, and not in
     non-instrumented mode where the target receives no forkserver commands).
     map_size here is the FULL target map the forkserver reported, i.e. it
     already includes any appended IJON map and bug-pass map tail; placing the
     4-byte word (4-byte aligned) AFTER map_size and any compcov slack keeps it
     clear of coverage, IJON, bug-map and compcov writes alike. */
#if defined(__linux__) || defined(__APPLE__)
  size_t sync_extra =
      (!non_instrumented_mode && !shm->shmemfuzz_mode) ? sizeof(u32) : 0;
#else
  size_t sync_extra = 0;
#endif

#ifdef USEMMAP

  shm->g_shm_fd = -1;
  shm->cmplog_g_shm_fd = -1;
  shm->vp_g_shm_fd = -1;
  shm->map_alloc_size = 0;
  shm->cmp_map_alloc_size = 0;

  const int shmflags = O_RDWR | O_EXCL;

  /* ======
  generate random file name for multi instance

  thanks to f*cking glibc we can not use tmpnam securely, it generates a
  security warning that cannot be suppressed
  so we do this worse workaround */
  snprintf(shm->g_shm_file_path, L_tmpnam, "/afl_%d_%ld", getpid(), random());

  #ifdef SHM_LARGEPAGE_ALLOC_DEFAULT
  /* trying to get large memory segment optimised and monitorable separately as
   * such */
  static size_t sizes[4] = {(size_t)-1};
  static int    psizes = 0;
  int           i;
  if (sizes[0] == (size_t)-1) { psizes = getpagesizes(sizes, 4); }

  /* very unlikely to fail even if the arch supports only two sizes */
  if (likely(psizes > 0)) {

    for (i = psizes - 1; shm->g_shm_fd == -1 && i >= 0; --i) {

      if (sizes[i] == 0 || map_size % sizes[i]) { continue; }

      shm->g_shm_fd =
          shm_create_largepage(shm->g_shm_file_path, shmflags, i,
                               SHM_LARGEPAGE_ALLOC_DEFAULT, permission);

      if (gid != -1 && shm->g_shm_fd != -1) {

        if (fchown(shm->g_shm_fd, -1, gid) == -1) { PFATAL("fchown() failed"); }

      }

    }

  }

  #endif

  /* create the shared memory segment as if it was a file */
  if (shm->g_shm_fd == -1) {

    shm->g_shm_fd =
        shm_open(shm->g_shm_file_path, shmflags | O_CREAT, permission);

    if (gid != -1 && shm->g_shm_fd != -1) {

      if (fchown(shm->g_shm_fd, -1, gid) == -1) { PFATAL("fchown() failed"); }

    }

  }

  if (shm->g_shm_fd == -1) { PFATAL("shm_open() failed"); }

  /* Reserve the child_sync word right after the (4-byte aligned) map. */
  size_t sync_off = sync_extra ? ((map_size + 3) & ~(size_t)3) : 0;
  size_t alloc_size = sync_off ? sync_off + sizeof(u32) : map_size;

  /* configure the size of the shared memory segment */
  if (ftruncate(shm->g_shm_fd, alloc_size)) {

    PFATAL("setup_shm(): ftruncate() failed");

  }

  /* map the shared memory segment to the address space of the process */
  shm->map =
      mmap(0, alloc_size, PROT_READ | PROT_WRITE, MAP_SHARED, shm->g_shm_fd, 0);
  if (shm->map == MAP_FAILED) {

    close(shm->g_shm_fd);
    shm->g_shm_fd = -1;
    shm_unlink(shm->g_shm_file_path);
    shm->g_shm_file_path[0] = 0;
    PFATAL("mmap() failed");

  }

  shm->map_alloc_size = alloc_size;

  /* Hand the map over as an inheritable descriptor and drop its name, so a
     SIGKILLed tool leaves nothing behind in /dev/shm. The shmem input map
     (non_instrumented_mode, see setup_testcase_shmem) exports its descriptor
     later through afl_shm_fuzz_env_set(). */

  afl_shm_handover_fd(&shm->g_shm_fd, shm->g_shm_file_path);

  /* If somebody is asking us to fuzz instrumented binaries in non-instrumented
     mode, we don't want them to detect instrumentation, since we won't be
     sending fork server commands. This should be replaced with better
     auto-detection later on, perhaps? */

  if (!non_instrumented_mode) {

    setenv(SHM_ENV_VAR, shm->g_shm_file_path, 1);
    afl_shm_env_set_fd(SHM_FD_ENV_VAR, shm->g_shm_fd);

  }

  if (shm->map == (void *)-1 || !shm->map) PFATAL("mmap() failed");

  #if defined(__linux__) || defined(__APPLE__)
  if (sync_off) {

    shm->child_sync_offset = (u32)sync_off;
    shm->child_sync = (u32 *)(shm->map + sync_off);
    __atomic_store_n(shm->child_sync, AFL_CHILD_IDLE, __ATOMIC_RELEASE);

  }

  #endif

  if (shm->cmplog_mode) {

    snprintf(shm->cmplog_g_shm_file_path, L_tmpnam, "/afl_cmplog_%d_%ld",
             getpid(), random());

    /* create the shared memory segment as if it was a file */
    shm->cmplog_g_shm_fd = shm_open(shm->cmplog_g_shm_file_path,
                                    O_CREAT | O_RDWR | O_EXCL, permission);
    if (shm->cmplog_g_shm_fd == -1) { PFATAL("shm_open() failed"); }
    if (gid != -1) {

      if (fchown(shm->cmplog_g_shm_fd, -1, gid) == -1) {

        PFATAL("fchown() failed");

      }

    }

    /* configure the size of the shared memory segment */
    if (ftruncate(shm->cmplog_g_shm_fd, sizeof(struct cmp_map))) {

      PFATAL("setup_shm(): cmplog ftruncate() failed");

    }

    /* map the shared memory segment to the address space of the process */
    shm->cmp_map = mmap(0, sizeof(struct cmp_map), PROT_READ | PROT_WRITE,
                        MAP_SHARED, shm->cmplog_g_shm_fd, 0);
    if (shm->cmp_map == MAP_FAILED) {

      close(shm->cmplog_g_shm_fd);
      shm->cmplog_g_shm_fd = -1;
      shm_unlink(shm->cmplog_g_shm_file_path);
      shm->cmplog_g_shm_file_path[0] = 0;
      PFATAL("mmap() failed");

    }

    afl_shm_handover_fd(&shm->cmplog_g_shm_fd, shm->cmplog_g_shm_file_path);

    shm->cmp_map_alloc_size = sizeof(struct cmp_map);

    /* If somebody is asking us to fuzz instrumented binaries in
       non-instrumented mode, we don't want them to detect instrumentation,
       since we won't be sending fork server commands. This should be replaced
       with better auto-detection later on, perhaps? */

    if (!non_instrumented_mode) {

      setenv(CMPLOG_SHM_ENV_VAR, shm->cmplog_g_shm_file_path, 1);
      afl_shm_env_set_fd(CMPLOG_SHM_FD_ENV_VAR, shm->cmplog_g_shm_fd);

    }

    if (shm->cmp_map == (void *)-1 || !shm->cmp_map)
      PFATAL("cmplog mmap() failed");

  }

  if (shm->vp_mode) {

    snprintf(shm->vp_g_shm_file_path, L_tmpnam, "/afl_vp_%d_%ld", getpid(),
             random());

    shm->vp_g_shm_fd = shm_open(shm->vp_g_shm_file_path,
                                O_CREAT | O_RDWR | O_EXCL, permission);
    if (shm->vp_g_shm_fd == -1) { PFATAL("shm_open() failed"); }
    if (gid != -1) {

      if (fchown(shm->vp_g_shm_fd, -1, gid) == -1) {

        PFATAL("fchown() failed");

      }

    }

    if (ftruncate(shm->vp_g_shm_fd, sizeof(vp_map_t))) {

      PFATAL("setup_shm(): vp ftruncate() failed");

    }

    shm->vp_map = mmap(0, sizeof(vp_map_t), PROT_READ | PROT_WRITE, MAP_SHARED,
                       shm->vp_g_shm_fd, 0);
    if (shm->vp_map == MAP_FAILED) {

      close(shm->vp_g_shm_fd);
      shm->vp_g_shm_fd = -1;
      shm_unlink(shm->vp_g_shm_file_path);
      shm->vp_g_shm_file_path[0] = 0;
      PFATAL("vp mmap() failed");

    }

    afl_shm_handover_fd(&shm->vp_g_shm_fd, shm->vp_g_shm_file_path);

    memset((void *)shm->vp_map, 0, sizeof(vp_map_t));

    if (shm->vp_map == (void *)-1 || !shm->vp_map) PFATAL("vp mmap() failed");

  }

#else
  u8             *shm_str;
  struct shmid_ds shmid_ds;

  // for qemu+unicorn we have to increase by 8 to account for potential
  // compcov map overwrite
  size_t base_size = map_size == MAP_SIZE ? map_size + 8 : map_size;
  /* The child_sync word is 4-byte aligned and placed AFTER the compcov slack
     so neither coverage nor compcov can clobber it. */
  size_t sync_off = sync_extra ? ((base_size + 3) & ~(size_t)3) : 0;
  size_t alloc_size = sync_off ? sync_off + sizeof(u32) : base_size;
  shm->shm_id =
      shmget(IPC_PRIVATE, alloc_size, IPC_CREAT | IPC_EXCL | permission);
  if (shm->shm_id < 0) {

    afl_shm_release_partial(shm);
    PFATAL("shmget() failed, try running afl-system-config");

  }

  if (gid != -1) {

    if (shmctl(shm->shm_id, IPC_STAT, &shmid_ds) == -1) {

      afl_shm_release_partial(shm);
      PFATAL("shmctl(IPC_STAT) failed");

    }

    shmid_ds.shm_perm.gid = (gid_t)gid;
    if (shmctl(shm->shm_id, IPC_SET, &shmid_ds) == -1) {

      afl_shm_release_partial(shm);
      PFATAL("shmctl(IPC_SET) failed");

    }

  }

  if (shm->cmplog_mode) {

    shm->cmplog_shm_id = shmget(IPC_PRIVATE, sizeof(struct cmp_map),
                                IPC_CREAT | IPC_EXCL | permission);

    if (shm->cmplog_shm_id < 0) {

      afl_shm_release_partial(shm);
      PFATAL("shmget() failed, try running afl-system-config");

    }

    if (gid != -1) {

      if (shmctl(shm->cmplog_shm_id, IPC_STAT, &shmid_ds) == -1) {

        afl_shm_release_partial(shm);
        PFATAL("shmctl(IPC_STAT) failed");

      }

      shmid_ds.shm_perm.gid = (gid_t)gid;
      if (shmctl(shm->cmplog_shm_id, IPC_SET, &shmid_ds) == -1) {

        afl_shm_release_partial(shm);
        PFATAL("shmctl(IPC_SET) failed");

      }

    }

  }

  if (shm->vp_mode) {

    shm->vp_shm_id = shmget(IPC_PRIVATE, sizeof(vp_map_t),
                            IPC_CREAT | IPC_EXCL | permission);

    if (shm->vp_shm_id < 0) {

      afl_shm_release_partial(shm);
      PFATAL("shmget() failed, try running afl-system-config");

    }

    if (gid != -1) {

      if (shmctl(shm->vp_shm_id, IPC_STAT, &shmid_ds) == -1) {

        afl_shm_release_partial(shm);
        PFATAL("shmctl(IPC_STAT) failed");

      }

      shmid_ds.shm_perm.gid = (gid_t)gid;
      if (shmctl(shm->vp_shm_id, IPC_SET, &shmid_ds) == -1) {

        afl_shm_release_partial(shm);
        PFATAL("shmctl(IPC_SET) failed");

      }

    }

  }

  if (!non_instrumented_mode) {

    shm_str = alloc_printf("%d", shm->shm_id);

    /* If somebody is asking us to fuzz instrumented binaries in
       non-instrumented mode, we don't want them to detect instrumentation,
       since we won't be sending fork server commands. This should be replaced
       with better auto-detection later on, perhaps? */

    setenv(SHM_ENV_VAR, shm_str, 1);

    ck_free(shm_str);

  }

  if (shm->cmplog_mode && !non_instrumented_mode) {

    shm_str = alloc_printf("%d", shm->cmplog_shm_id);

    setenv(CMPLOG_SHM_ENV_VAR, shm_str, 1);

    ck_free(shm_str);

  }

  shm->map = shmat(shm->shm_id, NULL, 0);

  if (shm->map == (void *)-1 || !shm->map) {

    afl_shm_release_partial(shm);
    PFATAL("shmat() failed");

  }

  AFL_SHM_AUTO_RECLAIM(shm->shm_id);

  if (shm->cmplog_mode) {

    shm->cmp_map = shmat(shm->cmplog_shm_id, NULL, 0);

    if (shm->cmp_map == (void *)-1 || !shm->cmp_map) {

      shmctl(shm->shm_id, IPC_RMID, NULL);  // do not leak shmem

      shmctl(shm->cmplog_shm_id, IPC_RMID, NULL);  // do not leak shmem

      if (shm->vp_mode) { shmctl(shm->vp_shm_id, IPC_RMID, NULL); }

      PFATAL("shmat() failed");

    }

    AFL_SHM_AUTO_RECLAIM(shm->cmplog_shm_id);

  }

  if (shm->vp_mode) {

    shm->vp_map = shmat(shm->vp_shm_id, NULL, 0);

    if (shm->vp_map == (void *)-1 || !shm->vp_map) {

      afl_shm_release_partial(shm);
      PFATAL("shmat() failed");

    }

    AFL_SHM_AUTO_RECLAIM(shm->vp_shm_id);

    memset((void *)shm->vp_map, 0, sizeof(vp_map_t));

  }

  #if defined(__linux__) || defined(__APPLE__)
  if (sync_off) {

    shm->child_sync_offset = (u32)sync_off;
    shm->child_sync = (u32 *)(shm->map + sync_off);
    __atomic_store_n(shm->child_sync, AFL_CHILD_IDLE, __ATOMIC_RELEASE);

  }

  #endif

#endif

  shm->map_size = map_size;
  list_append(&shm_list, shm);

  return shm->map;

}

