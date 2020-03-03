/*
   american fuzzy lop++ - shared memory related header
   ---------------------------------------------------

   Originally written by Michal Zalewski

   Forkserver design by Jann Horn <jannhorn@googlemail.com>

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eißfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   Shared code to handle the shared memory. This is used by the fuzzer
   as well the other components like afl-tmin, afl-showmap, etc...

 */

#ifndef __AFL_SHAREDMEM_H
#define __AFL_SHAREDMEM_H

typedef struct sharedmem {

  //extern unsigned char *trace_bits;

  #ifdef USEMMAP
  /* ================ Proteas ================ */
  int            g_shm_fd = -1;
  unsigned char *g_shm_base = NULL;
  char           g_shm_file_path[L_tmpnam];
  size_t         size_alloc; /* actual allocated size */
  size_t         size_used;  /* in use by shmem app */
  /* ========================================= */
  #else
  s32 shm_id;                     /* ID of the SHM region              */
  s32 cmplog_shm_id;
  #endif

  int             cmplog_mode;
  struct cmp_map *cmp_map;

} sharedmem_t;

void setup_shm(sharedmem_t*, size_t, u8*, unsigned char dumb_mode);
void remove_shm(void);

#endif

