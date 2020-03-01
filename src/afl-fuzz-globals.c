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

afl_state_init(afl_state_t *afl) {

    afl->w_init = 0.9;
    afl->w_end = 0.3;
    afl->g_max = 5000;
    afl->period_pilot_tmp = 5000.0;
    afl->schedule = EXPLORE;                 /* Power schedule (default: EXPLORE)*/
    afl->havoc_max_mult = HAVOC_MAX_MULT;

    afl->clear_screen = 1;                   /* Window resized?                  */
    afl->havoc_div = 1;                      /* Cycle count divisor for havoc    */
    afl->stage_name = &"init";               /* Name of the current fuzz stage   */
    afl->splicing_with = -1;                 /* Splicing with which test case?   */

#ifdef HAVE_AFFINITY
    afl->cpu_aff = -1;                       /* Selected CPU core                */
#endif                                                      /* HAVE_AFFINITY */

    afl->use_stdin = 1;

    afl->cal_cycles = CAL_CYCLES;
    afl->cal_cycles_long = CAL_CYCLES_LONG;

    afl->exec_tmout = EXEC_TIMEOUT;
    afl->hang_tmout = EXEC_TIMEOUT;

    afl->mem_limit = MEM_LIMIT;

    afl->stats_update_freq = 1;

#ifndef HAVE_ARC4RANDOM
    afl->dev_urandom_fd = -1;
#endif
    afl->dev_null_fd = -1;

    afl->child_pid = -1;
    afl->out_dir_fd = -1;

}

