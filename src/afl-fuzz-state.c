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
#include "envs.h"

s8  interesting_8[] = {INTERESTING_8};
s16 interesting_16[] = {INTERESTING_8, INTERESTING_16};
s32 interesting_32[] = {INTERESTING_8, INTERESTING_16, INTERESTING_32};

char *power_names[POWER_SCHEDULES_NUM] = {

    "explore", "fast", "coe", "lin", "quad", "exploit", "mmopt", "rare"};

/* Initialize MOpt "globals" for this afl state */

static void init_mopt_globals(afl_state_t *afl) {

  MOpt_globals_t *core = &afl->mopt_globals_core;
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

list_t afl_states = {.element_prealloc_count = 0};

/* Initializes an afl_state_t. */

void afl_state_init(afl_state_t *afl) {

  /* thanks to this memset, growing vars like out_buf
  and out_size are NULL/0 by default. */
  memset(afl, 0, sizeof(afl_state_t));

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

  afl->cmplog_prev_timed_out = 0;

  /* statis file */
  afl->last_bitmap_cvg = 0;
  afl->last_stability = 0;
  afl->last_eps = 0;

  /* plot file saves from last run */
  afl->plot_prev_qp = 0;
  afl->plot_prev_pf = 0;
  afl->plot_prev_pnf = 0;
  afl->plot_prev_ce = 0;
  afl->plot_prev_md = 0;
  afl->plot_prev_qc = 0;
  afl->plot_prev_uc = 0;
  afl->plot_prev_uh = 0;

  afl->stats_last_stats_ms = 0;
  afl->stats_last_plot_ms = 0;
  afl->stats_last_ms = 0;
  afl->stats_last_execs = 0;
  afl->stats_avg_exec = -1;

  init_mopt_globals(afl);

  list_append(&afl_states, afl);

}

/*This sets up the environment variables for afl-fuzz into the afl_state
 * struct*/

void read_afl_environment(afl_state_t *afl, char **envp) {

  int   index = 0, found = 0;
  char *env;
  while ((env = envp[index++]) != NULL) {

    if (strncmp(env, "ALF_", 4) == 0) {

      WARNF("Potentially mistyped AFL environment variable: %s", env);
      found++;

    } else if (strncmp(env, "AFL_", 4) == 0) {

      int i = 0, match = 0;
      while (match == 0 && afl_environment_variables[i] != NULL) {

        size_t afl_environment_variable_len =
            strlen(afl_environment_variables[i]);
        if (strncmp(env, afl_environment_variables[i],
                    afl_environment_variable_len) == 0 &&
            env[afl_environment_variable_len] == '=') {

          match = 1;
          if (!strncmp(env, "AFL_SKIP_CPUFREQ", afl_environment_variable_len)) {

            afl->afl_env.afl_skip_cpufreq =
                get_afl_env(afl_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "AFL_EXIT_WHEN_DONE",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_exit_when_done =
                get_afl_env(afl_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "AFL_NO_AFFINITY",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_no_affinity =
                get_afl_env(afl_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "AFL_SKIP_CRASHES",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_skip_crashes =
                (u8 *)get_afl_env(afl_environment_variables[i]);

          } else if (!strncmp(env, "AFL_HANG_TMOUT",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_hang_tmout =
                (u8 *)get_afl_env(afl_environment_variables[i]);

          } else if (!strncmp(env, "AFL_SKIP_BIN_CHECK",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_skip_bin_check =
                get_afl_env(afl_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "AFL_DUMB_FORKSRV",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_dumb_forksrv =
                get_afl_env(afl_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "AFL_IMPORT_FIRST",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_import_first =
                get_afl_env(afl_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "AFL_CUSTOM_MUTATOR_ONLY",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_custom_mutator_only =
                get_afl_env(afl_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "AFL_NO_UI", afl_environment_variable_len)) {

            afl->afl_env.afl_no_ui =
                get_afl_env(afl_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "AFL_FORCE_UI",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_force_ui =
                get_afl_env(afl_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_i_dont_care_about_missing_crashes =
                get_afl_env(afl_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "AFL_BENCH_JUST_ONE",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_bench_just_one =
                get_afl_env(afl_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "AFL_BENCH_UNTIL_CRASH",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_bench_until_crash =
                get_afl_env(afl_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "AFL_DEBUG_CHILD_OUTPUT",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_debug_child_output =
                get_afl_env(afl_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "AFL_AUTORESUME",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_autoresume =
                get_afl_env(afl_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "AFL_TMPDIR",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_tmpdir =
                (u8 *)get_afl_env(afl_environment_variables[i]);

          } else if (!strncmp(env, "AFL_POST_LIBRARY",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_post_library =
                (u8 *)get_afl_env(afl_environment_variables[i]);

          } else if (!strncmp(env, "AFL_CUSTOM_MUTATOR_LIBRARY",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_custom_mutator_library =
                (u8 *)get_afl_env(afl_environment_variables[i]);

          } else if (!strncmp(env, "AFL_PYTHON_MODULE",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_python_module =
                (u8 *)get_afl_env(afl_environment_variables[i]);

          } else if (!strncmp(env, "AFL_PATH", afl_environment_variable_len)) {

            afl->afl_env.afl_path =
                (u8 *)get_afl_env(afl_environment_variables[i]);

          } else if (!strncmp(env, "AFL_PRELOAD",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_preload =
                (u8 *)get_afl_env(afl_environment_variables[i]);

          }

        } else

          i++;

      }

      if (match == 0) {

        WARNF("Mistyped AFL environment variable: %s", env);
        found++;

      }

    }

  }

  if (found) sleep(2);

}

/* Removes this afl_state instance and frees it. */

void afl_state_deinit(afl_state_t *afl) {

  if (afl->post_deinit) afl->post_deinit(afl->post_data);

  free(afl->out_buf);
  free(afl->out_scratch_buf);
  free(afl->eff_buf);
  free(afl->in_buf);
  free(afl->in_scratch_buf);
  free(afl->ex_buf);

  list_remove(&afl_states, afl);

}

