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

static list_t shm_list = {.element_prealloc_count = 0};

void afl_shm_vp_env_unset(void) {

  unsetenv(VP_SHM_ENV_VAR);

}

void afl_shm_vp_env_set(sharedmem_t *shm) {

  if (!shm || !shm->vp_mode || !shm->vp_map) { return; }

#ifdef USEMMAP

  if (shm->vp_g_shm_file_path[0]) {

    setenv(VP_SHM_ENV_VAR, shm->vp_g_shm_file_path, 1);

  }

#else

  u8 *shm_str = alloc_printf("%d", shm->vp_shm_id);
  setenv(VP_SHM_ENV_VAR, shm_str, 1);
  ck_free(shm_str);

#endif

}

void afl_shm_state_env_unset(void) {

  unsetenv(STATE_SHM_ENV_VAR);

}

void afl_shm_state_env_set(sharedmem_t *shm) {

  if (!shm || !shm->state_mode || !shm->state_map) { return; }

#ifdef USEMMAP

  if (shm->state_g_shm_file_path[0]) {

    setenv(STATE_SHM_ENV_VAR, shm->state_g_shm_file_path, 1);

  }

#else

  u8 *shm_str = alloc_printf("%d", shm->state_shm_id);
  setenv(STATE_SHM_ENV_VAR, shm_str, 1);
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

  } else {

    unsetenv(SHM_ENV_VAR);

  }

  if (shm->vp_mode) { afl_shm_vp_env_unset(); }
  if (shm->state_mode) { afl_shm_state_env_unset(); }

#ifdef USEMMAP
  if (shm->map != NULL) {

    munmap(shm->map, shm->map_alloc_size);
    shm->map = NULL;
    shm->map_alloc_size = 0;
    shm->child_sync = NULL;
    shm->child_sync_offset = 0;

  }

  if (shm->g_shm_fd != -1) {

    close(shm->g_shm_fd);
    shm->g_shm_fd = -1;

  }

  if (shm->g_shm_file_path[0]) {

    shm_unlink(shm->g_shm_file_path);
    shm->g_shm_file_path[0] = 0;

  }

  if (shm->cmplog_mode) {

    unsetenv(CMPLOG_SHM_ENV_VAR);

    if (shm->cmp_map != NULL) {

      munmap(shm->cmp_map, shm->cmp_map_alloc_size);
      shm->cmp_map = NULL;
      shm->cmp_map_alloc_size = 0;

    }

    if (shm->cmplog_g_shm_fd != -1) {

      close(shm->cmplog_g_shm_fd);
      shm->cmplog_g_shm_fd = -1;

    }

    if (shm->cmplog_g_shm_file_path[0]) {

      shm_unlink(shm->cmplog_g_shm_file_path);
      shm->cmplog_g_shm_file_path[0] = 0;

    }

  }

  if (shm->vp_mode) {

    if (shm->vp_map != NULL) {

      munmap(shm->vp_map, sizeof(vp_map_t));
      shm->vp_map = NULL;

    }

    if (shm->vp_g_shm_fd != -1) {

      close(shm->vp_g_shm_fd);
      shm->vp_g_shm_fd = -1;

    }

    if (shm->vp_g_shm_file_path[0]) {

      shm_unlink(shm->vp_g_shm_file_path);
      shm->vp_g_shm_file_path[0] = 0;

    }

  }

  if (shm->state_mode) {

    if (shm->state_map != NULL) {

      munmap((void *)shm->state_map, sizeof(state_map_t));
      shm->state_map = NULL;

    }

    if (shm->state_g_shm_fd != -1) {

      close(shm->state_g_shm_fd);
      shm->state_g_shm_fd = -1;

    }

    if (shm->state_g_shm_file_path[0]) {

      shm_unlink(shm->state_g_shm_file_path);
      shm->state_g_shm_file_path[0] = 0;

    }

  }

#else
  shmctl(shm->shm_id, IPC_RMID, NULL);
  if (shm->cmplog_mode) { shmctl(shm->cmplog_shm_id, IPC_RMID, NULL); }
  if (shm->vp_mode) { shmctl(shm->vp_shm_id, IPC_RMID, NULL); }
  if (shm->state_mode) { shmctl(shm->state_shm_id, IPC_RMID, NULL); }
#endif

  shm->map = NULL;
  shm->cmp_map = NULL;
  shm->vp_map = NULL;
  shm->state_map = NULL;
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

  if (shm->state_mode && shm->state_shm_id >= 0) {

    shmctl(shm->state_shm_id, IPC_RMID, NULL);

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
  shm->state_map = NULL;
#ifndef USEMMAP
  shm->shm_id = -1;
  shm->cmplog_shm_id = -1;
  shm->vp_shm_id = -1;
  shm->state_shm_id = -1;
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
  shm->state_g_shm_fd = -1;
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
  close(shm->g_shm_fd);
  shm->g_shm_fd = -1;

  /* If somebody is asking us to fuzz instrumented binaries in non-instrumented
     mode, we don't want them to detect instrumentation, since we won't be
     sending fork server commands. This should be replaced with better
     auto-detection later on, perhaps? */

  if (!non_instrumented_mode) setenv(SHM_ENV_VAR, shm->g_shm_file_path, 1);

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

    close(shm->cmplog_g_shm_fd);
    shm->cmplog_g_shm_fd = -1;

    shm->cmp_map_alloc_size = sizeof(struct cmp_map);

    /* If somebody is asking us to fuzz instrumented binaries in
       non-instrumented mode, we don't want them to detect instrumentation,
       since we won't be sending fork server commands. This should be replaced
       with better auto-detection later on, perhaps? */

    if (!non_instrumented_mode)
      setenv(CMPLOG_SHM_ENV_VAR, shm->cmplog_g_shm_file_path, 1);

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

    close(shm->vp_g_shm_fd);
    shm->vp_g_shm_fd = -1;

    memset((void *)shm->vp_map, 0, sizeof(vp_map_t));

    if (shm->vp_map == (void *)-1 || !shm->vp_map) PFATAL("vp mmap() failed");

  }

  if (shm->state_mode) {

    snprintf(shm->state_g_shm_file_path, L_tmpnam, "/afl_state_%d_%ld",
             getpid(), random());

    shm->state_g_shm_fd = shm_open(shm->state_g_shm_file_path,
                                   O_CREAT | O_RDWR | O_EXCL, permission);
    if (shm->state_g_shm_fd == -1) { PFATAL("shm_open() failed"); }
    if (gid != -1) {

      if (fchown(shm->state_g_shm_fd, -1, gid) == -1) {

        PFATAL("fchown() failed");

      }

    }

    if (ftruncate(shm->state_g_shm_fd, sizeof(state_map_t))) {

      PFATAL("setup_shm(): state ftruncate() failed");

    }

    shm->state_map = mmap(0, sizeof(state_map_t), PROT_READ | PROT_WRITE,
                          MAP_SHARED, shm->state_g_shm_fd, 0);
    if (shm->state_map == MAP_FAILED) {

      close(shm->state_g_shm_fd);
      shm->state_g_shm_fd = -1;
      shm_unlink(shm->state_g_shm_file_path);
      shm->state_g_shm_file_path[0] = 0;
      PFATAL("state mmap() failed");

    }

    close(shm->state_g_shm_fd);
    shm->state_g_shm_fd = -1;

    memset((void *)shm->state_map, 0, sizeof(state_map_t));

    if (shm->state_map == (void *)-1 || !shm->state_map) {

      PFATAL("state mmap() failed");

    }

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

  if (shm->state_mode) {

    shm->state_shm_id = shmget(IPC_PRIVATE, sizeof(state_map_t),
                               IPC_CREAT | IPC_EXCL | permission);

    if (shm->state_shm_id < 0) {

      afl_shm_release_partial(shm);
      PFATAL("shmget() failed, try running afl-system-config");

    }

    if (gid != -1) {

      if (shmctl(shm->state_shm_id, IPC_STAT, &shmid_ds) == -1) {

        afl_shm_release_partial(shm);
        PFATAL("shmctl(IPC_STAT) failed");

      }

      shmid_ds.shm_perm.gid = (gid_t)gid;
      if (shmctl(shm->state_shm_id, IPC_SET, &shmid_ds) == -1) {

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

  if (shm->cmplog_mode) {

    shm->cmp_map = shmat(shm->cmplog_shm_id, NULL, 0);

    if (shm->cmp_map == (void *)-1 || !shm->cmp_map) {

      shmctl(shm->shm_id, IPC_RMID, NULL);  // do not leak shmem

      shmctl(shm->cmplog_shm_id, IPC_RMID, NULL);  // do not leak shmem

      if (shm->vp_mode) { shmctl(shm->vp_shm_id, IPC_RMID, NULL); }

      if (shm->state_mode) { shmctl(shm->state_shm_id, IPC_RMID, NULL); }

      PFATAL("shmat() failed");

    }

  }

  if (shm->vp_mode) {

    shm->vp_map = shmat(shm->vp_shm_id, NULL, 0);

    if (shm->vp_map == (void *)-1 || !shm->vp_map) {

      afl_shm_release_partial(shm);
      PFATAL("shmat() failed");

    }

    memset((void *)shm->vp_map, 0, sizeof(vp_map_t));

  }

  if (shm->state_mode) {

    shm->state_map = shmat(shm->state_shm_id, NULL, 0);

    if (shm->state_map == (void *)-1 || !shm->state_map) {

      afl_shm_release_partial(shm);
      PFATAL("shmat() failed");

    }

    memset((void *)shm->state_map, 0, sizeof(state_map_t));

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

