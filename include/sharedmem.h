/*
   american fuzzy lop++ - shared memory related header
   ---------------------------------------------------

   Originally written by Michal Zalewski

   Forkserver design by Jann Horn <jannhorn@googlemail.com>

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                     Heiko Eissfeldt <heiko.eissfeldt@hexco.de>,
                     Andrea Fioraldi <andreafioraldi@gmail.com>,
                     Dominik Maier <mail@dmnk.co>

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

#ifndef __AFL_SHAREDMEM_H
#define __AFL_SHAREDMEM_H

#include <unistd.h>

/* config.h decides whether this struct is the POSIX shared memory or the SysV
   flavour (USEMMAP), so it has to be seen before the struct either way. */
#include "config.h"
#include "types.h"
#include "value-profile.h"

typedef struct sharedmem {

  // extern unsigned char *trace_bits;

#ifdef USEMMAP
  /* ================ Proteas ================ */
  /* The g_shm_*fd fields hold the descriptor the target inherits (moved into
     the SHM_FD_MIN range and with FD_CLOEXEC cleared), or -1 when the map is
     handed over by name instead (AFL_SHM_KEEP_NAME, or no free descriptor).
     That is also what says whether the object is still linked: a descriptor
     means it was shm_unlink()ed at creation and afl_shm_deinit() only has to
     drop the last reference, -1 means the name is still there to remove. The
     g_shm_*file_path stays set either way - the *_SHM_ENV_VAR variables keep
     carrying it so that "am I running under AFL++?" checks keep working. */
  int    g_shm_fd;
  char   g_shm_file_path[L_tmpnam];
  int    cmplog_g_shm_fd;
  char   cmplog_g_shm_file_path[L_tmpnam];
  int    vp_g_shm_fd;
  char   vp_g_shm_file_path[L_tmpnam];
  size_t map_alloc_size;
  size_t cmp_map_alloc_size;
/* ========================================= */
#else
  s32 shm_id;                          /* ID of the SHM region              */
  s32 cmplog_shm_id;
  s32 vp_shm_id;
#endif

  u8 *map;                                          /* shared memory region */

  size_t map_size;                                    /* requested map size */

  /* The fuzzer<->child synchronization word lives in the last bytes of the
     coverage map (see afl_shm_init). child_sync_offset is its byte offset
     into ->map (0 means none). This avoids a second shared memory segment. */
  u32  child_sync_offset;           /* offset of child_sync word in map     */
  u32 *child_sync;                 /* pointer to the 4-byte sync word       */

  int             cmplog_mode;
  int             vp_mode;
  int             sanfuzz_mode;
  int             shmemfuzz_mode;
  struct cmp_map *cmp_map;
  vp_map_t       *vp_map;

} sharedmem_t;

u8  *afl_shm_init(sharedmem_t *, size_t, unsigned char non_instrumented_mode,
                  mode_t mode, int gid);
void afl_shm_deinit(sharedmem_t *);
void afl_shm_deinit_all(void);
void afl_shm_fuzz_env_set(sharedmem_t *);
/* Publish the descriptor a shared map was handed over on (see SHM_FD_ENV_VAR)
   under `env`. A no-op where the map is a SysV segment or was handed over by
   name, so callers do not need to know which of the two it is. */
void afl_shm_env_set_fd(const char *env, int fd);
void afl_shm_vp_env_set(sharedmem_t *);
void afl_shm_vp_env_unset(void);

#endif

