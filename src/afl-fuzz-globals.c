/*
   american fuzzy lop++ - globals declarations
   -------------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eißfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This is the real deal: the program takes an instrumented binary and
   attempts a variety of basic fuzzing tricks, paying close attention to
   how they affect the execution path.

 */

#include "afl-fuzz.h"

s8  interesting_8[] = {INTERESTING_8};
s16 interesting_16[] = {INTERESTING_8, INTERESTING_16};
s32 interesting_32[] = {INTERESTING_8, INTERESTING_16, INTERESTING_32};

char *power_names[POWER_SCHEDULES_NUM] = {"explore", "fast", "coe",
                                          "lin",     "quad", "exploit"};

u8 *doc_path = NULL;                    /* gath to documentation dir        */

/* Initialize MOpt "globals" for this afl state */

static void init_mopt_globals(afl_state_t *afl) {

  MOpt_globals_t *core = &afl->mopt_globals_pilot;
  core->finds = afl->core_operator_finds_puppet;
  core->finds_v2 = afl->core_operator_finds_puppet_v2;
  core->cycles = afl->core_operator_cycles_puppet;
  core->cycles_v2 = afl->core_operator_cycles_puppet_v2;
  core->cycles_v3 = afl->core_operator_cycles_puppet_v3;
  core->is_pilot_mode = 0;
  core->pTime = &afl->tmp_core_time;
  core->period = period_core;
  core->havoc_stagename = "MOpt-core-havoc";
  core->splice_stageformat = "MOpt-core-splice %u";
  core->havoc_stagenameshort = "MOpt_core_havoc";
  core->splice_stagenameshort = "MOpt_core_splice";

  MOpt_globals_t *pilot = &afl->mopt_globals_pilot;
  pilot->finds = afl->stage_finds_puppet[0];
  pilot->finds_v2 = afl->stage_finds_puppet_v2[0];
  pilot->cycles = afl->stage_cycles_puppet[0];
  pilot->cycles_v2 = afl->stage_cycles_puppet_v2[0];
  pilot->cycles_v3 = afl->stage_cycles_puppet_v3[0];
  pilot->is_pilot_mode = 1;
  pilot->pTime = &afl->tmp_pilot_time;
  pilot->period = period_pilot;
  pilot->havoc_stagename = "MOpt-havoc";
  pilot->splice_stageformat = "MOpt-splice %u";
  pilot->havoc_stagenameshort = "MOpt_havoc";
  pilot->splice_stagenameshort = "MOpt_splice";

}

/* A global pointer to all instances is needed (for now) for signals to arrive
 */

list_t afl_states = {0};

/* Initializes an afl_state_t. */

void afl_state_init(afl_state_t *afl) {

  afl->w_init = 0.9;
  afl->w_end = 0.3;
  afl->g_max = 5000;
  afl->period_pilot_tmp = 5000.0;
  afl->schedule = EXPLORE;              /* Power schedule (default: EXPLORE)*/
  afl->havoc_max_mult = HAVOC_MAX_MULT;

  afl->clear_screen = 1;                /* Window resized?                  */
  afl->havoc_div = 1;                   /* Cycle count divisor for havoc    */
  afl->stage_name = "init";             /* Name of the current fuzz stage   */
  afl->splicing_with = -1;              /* Splicing with which test case?   */

#ifdef HAVE_AFFINITY
  afl->cpu_aff = -1;                    /* Selected CPU core                */
#endif                                                     /* HAVE_AFFINITY */

  afl->fsrv.use_stdin = 1;

  afl->cal_cycles = CAL_CYCLES;
  afl->cal_cycles_long = CAL_CYCLES_LONG;

  afl->fsrv.exec_tmout = EXEC_TIMEOUT;
  afl->hang_tmout = EXEC_TIMEOUT;

  afl->fsrv.mem_limit = MEM_LIMIT;

  afl->stats_update_freq = 1;

#ifndef HAVE_ARC4RANDOM
  afl->fsrv.dev_urandom_fd = -1;
#endif
  afl->fsrv.dev_null_fd = -1;

  afl->fsrv.child_pid = -1;
  afl->fsrv.out_dir_fd = -1;

  init_mopt_globals(afl);

  list_append(&afl_states, afl);

}

/* Removes this afl_state instance and frees it. */

void afl_state_deinit(afl_state_t *afl) {

  list_remove(&afl_states, afl);

}
