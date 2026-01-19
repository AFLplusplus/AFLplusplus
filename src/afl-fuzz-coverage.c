/*
   american fuzzy lop++ - code coverage related utilities.
   ----------------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eissfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2024 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   Edge to PC and module tracking.

 */

#include "afl-fuzz.h"

#ifdef __AFL_CODE_COVERAGE

/* Initialize the pc map shared memory for tracking edge ID to PC */

void afl_pcmap_init(afl_state_t *afl, u32 map_size) {

  size_t pcmap_size = map_size * sizeof(uintptr_t);

  OKF("Creating PCMAP shared memory (%u entries, %zu bytes)", map_size,
      pcmap_size);

  u8 *pcmap = afl_shm_init(&afl->shm_pcmap, pcmap_size, 1, afl->perm,
                           afl->chown_needed ? afl->fsrv.gid : -1);

  if (!pcmap) { FATAL("BUG: Zero return from afl_shm_init."); }

  memset(afl->shm_pcmap.map, 0, pcmap_size);

  #ifdef USEMMAP
  setenv("__AFL_PCMAP_SHM_ID", afl->shm_pcmap.g_shm_file_path, 1);
  OKF("PCMAP ready at %s", afl->shm_pcmap.g_shm_file_path);
  #else
  u8 *shm_str = alloc_printf("%d", afl->shm_pcmap.shm_id);
  setenv("__AFL_PCMAP_SHM_ID", shm_str, 1);
  ck_free(shm_str);
  OKF("PCMAP ready with ID %d", afl->shm_pcmap.shm_id);
  #endif

}

/* Resize the edge map when the map size changes */

void afl_pcmap_resize(afl_state_t *afl, u32 new_map_size) {

  if (afl->shm_pcmap.map) { afl_shm_deinit(&afl->shm_pcmap); }

  afl_pcmap_init(afl, new_map_size);

}

/* Initialize the module map shared memory for exporting module info */

void afl_modmap_init(afl_state_t *afl) {

  size_t modmap_size = sizeof(module_entry_t) * MAX_AFL_MODULES;

  OKF("Creating MODMAP shared memory (%zu bytes, %d entries)", modmap_size,
      MAX_AFL_MODULES);

  u8 *modmap = afl_shm_init(&afl->shm_modmap, modmap_size, 1, afl->perm,
                            afl->chown_needed ? afl->fsrv.gid : -1);

  if (!modmap) { FATAL("BUG: Zero return from afl_shm_init."); }

  memset(afl->shm_modmap.map, 0, modmap_size);

  #ifdef USEMMAP
  setenv("__AFL_MODMAP_SHM_ID", afl->shm_modmap.g_shm_file_path, 1);
  OKF("MODMAP ready at %s", afl->shm_modmap.g_shm_file_path);
  #else
  u8 *shm_str = alloc_printf("%d", afl->shm_modmap.shm_id);
  setenv("__AFL_MODMAP_SHM_ID", shm_str, 1);
  ck_free(shm_str);
  OKF("MODMAP ready with ID %d", afl->shm_modmap.shm_id);
  #endif

}

/* Write PC map to disk with edge ID to PC mappings */

void afl_dump_pc_map(afl_state_t *afl) {

  if (!afl->shm_pcmap.map) { return; }

  char pcmap_fn[4096];
  snprintf(pcmap_fn, sizeof(pcmap_fn), "%s/pcmap.dump", afl->out_dir);

  FILE *pcmap_fd;
  if ((pcmap_fd = fopen(pcmap_fn, "w")) == NULL) {

    PFATAL("could not create '%s'", pcmap_fn);

  }

  uintptr_t *pcmap = (uintptr_t *)afl->shm_pcmap.map;
  u32        entry_count = 0;

  for (u32 i = 0; i < afl->fsrv.real_map_size; i++) {

    if (pcmap[i] != 0) {

      fprintf(pcmap_fd, "%u 0x%lx\n", i, (unsigned long)pcmap[i]);
      entry_count++;

    }

  }

  fclose(pcmap_fd);
  OKF("Wrote %u PC map entries to %s", entry_count, pcmap_fn);

}

/* Write module map to disk from shared memory */

void afl_dump_module_map(afl_state_t *afl) {

  if (!afl->shm_modmap.map) { return; }

  char mfn[4096];
  snprintf(mfn, sizeof(mfn), "%s/modinfo.txt", afl->out_dir);

  FILE *modmap_fd;
  if ((modmap_fd = fopen(mfn, "w")) == NULL) {

    PFATAL("could not create '%s'", mfn);

  }

  module_entry_t *modmap = (module_entry_t *)afl->shm_modmap.map;
  u32             entry_count = 0;

  for (u32 i = 0; i < MAX_AFL_MODULES; i++) {

    if (modmap[i].loaded) {

      fprintf(modmap_fd, "%s %u %u\n", modmap[i].name, modmap[i].start_id,
              modmap[i].stop_id);
      entry_count++;

    }

  }

  fclose(modmap_fd);

  if (entry_count > 0) {

    OKF("Wrote %u module entries to %s", entry_count, mfn);

  }

}

#endif  // __AFL_CODE_COVERAGE

