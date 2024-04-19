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
   Copyright 2019-2024 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   Shared code to handle the shared memory. This is used by the fuzzer
   as well the other components like afl-tmin, afl-showmap, etc...

 */

#ifndef __AFL_SHAREDMEM_H
#define __AFL_SHAREDMEM_H

#include "types.h"

typedef struct sharedmem {

  // extern unsigned char *trace_bits;

#ifdef USEMMAP
  /* ================ Proteas ================ */
  int  g_shm_fd;
  char g_shm_file_path[L_tmpnam];
  int  cmplog_g_shm_fd;
  char cmplog_g_shm_file_path[L_tmpnam];
/* ========================================= */
#else
  s32 shm_id;                          /* ID of the SHM region              */
  s32 cmplog_shm_id;
#endif

  u8 *map;                                          /* shared memory region */

  size_t map_size;                                 /* actual allocated size */

  int             cmplog_mode;
  int             shmemfuzz_mode;
  struct cmp_map *cmp_map;

} sharedmem_t;

u8  *afl_shm_init(sharedmem_t *, size_t, unsigned char non_instrumented_mode);
void afl_shm_deinit(sharedmem_t *);

#endif

