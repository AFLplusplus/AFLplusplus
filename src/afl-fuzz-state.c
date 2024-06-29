/*
   american fuzzy lop++ - globals declarations
   -------------------------------------------

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

   This is the real deal: the program takes an instrumented binary and
   attempts a variety of basic fuzzing tricks, paying close attention to
   how they affect the execution path.

 */

#include <signal.h>
#include <limits.h>
#include "afl-fuzz.h"
#include "envs.h"

char *power_names[POWER_SCHEDULES_NUM] = {"explore", "mmopt", "exploit",
                                          "fast",    "coe",   "lin",
                                          "quad",    "rare",  "seek"};

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

static list_t afl_states = {.element_prealloc_count = 0};

/* Initializes an afl_state_t. */

void afl_state_init(afl_state_t *afl, uint32_t map_size) {

  /* thanks to this memset, growing vars like out_buf
  and out_size are NULL/0 by default. */
  memset(afl, 0, sizeof(afl_state_t));

  afl->shm.map_size = map_size ? map_size : MAP_SIZE;

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
  afl->cpu_to_bind = -1;
  afl->havoc_stack_pow2 = HAVOC_STACK_POW2;
  afl->hang_tmout = EXEC_TIMEOUT;
  afl->exit_on_time = 0;
  afl->stats_update_freq = 1;
  afl->stats_file_update_freq_msecs = STATS_UPDATE_SEC * 1000;
  afl->stats_avg_exec = 0;
  afl->skip_deterministic = 0;
  afl->sync_time = SYNC_TIME;
  afl->cmplog_lvl = 2;
  afl->min_length = 1;
  afl->max_length = MAX_FILE;
  afl->switch_fuzz_mode = STRATEGY_SWITCH_TIME * 1000;
#ifndef NO_SPLICING
  afl->use_splicing = 1;
#endif
  afl->q_testcase_max_cache_size = TESTCASE_CACHE_SIZE * 1048576UL;
  afl->q_testcase_max_cache_entries = 64 * 1024;

#ifdef HAVE_AFFINITY
  afl->cpu_aff = -1;                    /* Selected CPU core                */
#endif                                                     /* HAVE_AFFINITY */

  afl->virgin_bits = ck_alloc(map_size);
  afl->virgin_tmout = ck_alloc(map_size);
  afl->virgin_crash = ck_alloc(map_size);
  afl->var_bytes = ck_alloc(map_size);
  afl->top_rated = ck_alloc(map_size * sizeof(void *));
  afl->clean_trace = ck_alloc(map_size);
  afl->clean_trace_custom = ck_alloc(map_size);
  afl->first_trace = ck_alloc(map_size);
  afl->map_tmp_buf = ck_alloc(map_size);

  afl->fsrv.use_stdin = 1;
  afl->fsrv.map_size = map_size;
  // afl_state_t is not available in forkserver.c
  afl->fsrv.afl_ptr = (void *)afl;
  afl->fsrv.add_extra_func = (void (*)(void *, u8 *, u32)) & add_extra;
  afl->fsrv.exec_tmout = EXEC_TIMEOUT;
  afl->fsrv.mem_limit = MEM_LIMIT;
  afl->fsrv.dev_urandom_fd = -1;
  afl->fsrv.dev_null_fd = -1;
  afl->fsrv.child_pid = -1;
  afl->fsrv.out_dir_fd = -1;

  /* Init SkipDet */
  afl->skipdet_g =
      (struct skipdet_global *)ck_alloc(sizeof(struct skipdet_global));
  afl->skipdet_g->inf_prof =
      (struct inf_profile *)ck_alloc(sizeof(struct inf_profile));
  afl->havoc_prof =
      (struct havoc_profile *)ck_alloc(sizeof(struct havoc_profile));

  init_mopt_globals(afl);

  list_append(&afl_states, afl);

}

/*This sets up the environment variables for afl-fuzz into the afl_state
 * struct*/

void read_afl_environment(afl_state_t *afl, char **envp) {

  int   index = 0, issue_detected = 0;
  char *env;
  while ((env = envp[index++]) != NULL) {

    if (strncmp(env, "ALF_", 4) == 0) {

      WARNF("Potentially mistyped AFL environment variable: %s", env);
      issue_detected = 1;

    } else if (strncmp(env, "USE_", 4) == 0) {

      WARNF(
          "Potentially mistyped AFL environment variable: %s, did you mean "
          "AFL_%s?",
          env, env);
      issue_detected = 1;

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

          } else if (!strncmp(env, "AFL_EXIT_ON_TIME",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_exit_on_time =
                (u8 *)get_afl_env(afl_environment_variables[i]);

          } else if (!strncmp(env, "AFL_CRASHING_SEEDS_AS_NEW_CRASH",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_crashing_seeds_as_new_crash =
                atoi((u8 *)get_afl_env(afl_environment_variables[i]));

          } else if (!strncmp(env, "AFL_NO_AFFINITY",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_no_affinity =
                get_afl_env(afl_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "AFL_NO_WARN_INSTABILITY",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_no_warn_instability =
                get_afl_env(afl_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "AFL_TRY_AFFINITY",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_try_affinity =
                get_afl_env(afl_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "AFL_SKIP_CRASHES",

                              afl_environment_variable_len)) {

            // we should mark this obsolete in a few versions

          } else if (!strncmp(env, "AFL_HANG_TMOUT",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_hang_tmout =
                (u8 *)get_afl_env(afl_environment_variables[i]);

          } else if (!strncmp(env, "AFL_KEEP_TIMEOUTS",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_keep_timeouts =
                get_afl_env(afl_environment_variables[i]) ? 1 : 0;

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

          } else if (!strncmp(env, "AFL_FINAL_SYNC",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_final_sync =
                get_afl_env(afl_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "AFL_NO_SYNC",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_no_sync =
                get_afl_env(afl_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "AFL_NO_FASTRESUME",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_no_fastresume =
                get_afl_env(afl_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "AFL_CUSTOM_MUTATOR_ONLY",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_custom_mutator_only =
                get_afl_env(afl_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "AFL_CUSTOM_MUTATOR_LATE_SEND",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_custom_mutator_late_send =
                get_afl_env(afl_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "AFL_CMPLOG_ONLY_NEW",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_cmplog_only_new =
                get_afl_env(afl_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "AFL_DISABLE_REDUNDANT",

                              afl_environment_variable_len) ||
                     !strncmp(env, "AFL_NO_REDUNDANT",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_disable_redundant =
                get_afl_env(afl_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "AFL_NO_STARTUP_CALIBRATION",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_no_startup_calibration =
                get_afl_env(afl_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "AFL_NO_UI", afl_environment_variable_len)) {

            afl->afl_env.afl_no_ui =
                get_afl_env(afl_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "AFL_FORCE_UI",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_force_ui =
                get_afl_env(afl_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "AFL_IGNORE_PROBLEMS",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_ignore_problems =
                get_afl_env(afl_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "AFL_IGNORE_SEED_PROBLEMS",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_ignore_seed_problems =
                get_afl_env(afl_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "AFL_IGNORE_TIMEOUTS",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_ignore_timeouts =
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

          } else if (!strncmp(env, "AFL_DEBUG_CHILD",

                              afl_environment_variable_len) ||
                     !strncmp(env, "AFL_DEBUG_CHILD_OUTPUT",
                              afl_environment_variable_len)) {

            afl->afl_env.afl_debug_child =
                get_afl_env(afl_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "AFL_AUTORESUME",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_autoresume =
                get_afl_env(afl_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "AFL_PERSISTENT_RECORD",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_persistent_record =
                get_afl_env(afl_environment_variables[i]);

          } else if (!strncmp(env, "AFL_CYCLE_SCHEDULES",

                              afl_environment_variable_len)) {

            afl->cycle_schedules = afl->afl_env.afl_cycle_schedules =
                get_afl_env(afl_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "AFL_EXIT_ON_SEED_ISSUES",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_exit_on_seed_issues =
                get_afl_env(afl_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "AFL_EXPAND_HAVOC_NOW",

                              afl_environment_variable_len)) {

            afl->expand_havoc = afl->afl_env.afl_expand_havoc =
                get_afl_env(afl_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "AFL_CAL_FAST",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_cal_fast =
                get_afl_env(afl_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "AFL_FAST_CAL",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_cal_fast =
                get_afl_env(afl_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "AFL_STATSD",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_statsd =
                get_afl_env(afl_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "AFL_POST_PROCESS_KEEP_ORIGINAL",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_post_process_keep_original =
                get_afl_env(afl_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "AFL_TMPDIR",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_tmpdir =
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

          } else if (!strncmp(env, "AFL_MAX_DET_EXTRAS",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_max_det_extras =
                (u8 *)get_afl_env(afl_environment_variables[i]);

          } else if (!strncmp(env, "AFL_FORKSRV_INIT_TMOUT",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_forksrv_init_tmout =
                (u8 *)get_afl_env(afl_environment_variables[i]);

          } else if (!strncmp(env, "AFL_TESTCACHE_SIZE",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_testcache_size =
                (u8 *)get_afl_env(afl_environment_variables[i]);

          } else if (!strncmp(env, "AFL_TESTCACHE_ENTRIES",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_testcache_entries =
                (u8 *)get_afl_env(afl_environment_variables[i]);

          } else if (!strncmp(env, "AFL_STATSD_HOST",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_statsd_host =
                (u8 *)get_afl_env(afl_environment_variables[i]);

          } else if (!strncmp(env, "AFL_STATSD_PORT",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_statsd_port =
                (u8 *)get_afl_env(afl_environment_variables[i]);

          } else if (!strncmp(env, "AFL_STATSD_TAGS_FLAVOR",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_statsd_tags_flavor =
                (u8 *)get_afl_env(afl_environment_variables[i]);

          } else if (!strncmp(env, "AFL_CRASH_EXITCODE",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_crash_exitcode =
                (u8 *)get_afl_env(afl_environment_variables[i]);

#if defined USE_COLOR && !defined ALWAYS_COLORED

          } else if (!strncmp(env, "AFL_NO_COLOR",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_statsd_tags_flavor =
                (u8 *)get_afl_env(afl_environment_variables[i]);

          } else if (!strncmp(env, "AFL_NO_COLOUR",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_statsd_tags_flavor =
                (u8 *)get_afl_env(afl_environment_variables[i]);
#endif

          } else if (!strncmp(env, "AFL_KILL_SIGNAL",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_child_kill_signal =
                (u8 *)get_afl_env(afl_environment_variables[i]);

          } else if (!strncmp(env, "AFL_FORK_SERVER_KILL_SIGNAL",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_fsrv_kill_signal =
                (u8 *)get_afl_env(afl_environment_variables[i]);

          } else if (!strncmp(env, "AFL_TARGET_ENV",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_target_env =
                (u8 *)get_afl_env(afl_environment_variables[i]);

          } else if (!strncmp(env, "AFL_INPUT_LEN_MIN",

                              afl_environment_variable_len)) {

            afl->min_length =
                atoi((u8 *)get_afl_env(afl_environment_variables[i]));

          } else if (!strncmp(env, "AFL_INPUT_LEN_MAX",

                              afl_environment_variable_len)) {

            afl->max_length =
                atoi((u8 *)get_afl_env(afl_environment_variables[i]));

          } else if (!strncmp(env, "AFL_PIZZA_MODE",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_pizza_mode =
                atoi((u8 *)get_afl_env(afl_environment_variables[i]));

          } else if (!strncmp(env, "AFL_NO_CRASH_README",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_no_crash_readme =
                atoi((u8 *)get_afl_env(afl_environment_variables[i]));

          } else if (!strncmp(env, "AFL_SYNC_TIME",

                              afl_environment_variable_len)) {

            int time = atoi((u8 *)get_afl_env(afl_environment_variables[i]));
            if (time > 0) {

              afl->sync_time = time * (60 * 1000LL);

            } else {

              WARNF(
                  "incorrect value for AFL_SYNC_TIME environment variable, "
                  "used default value %lld instead.",
                  afl->sync_time / 60 / 1000);

            }

          } else if (!strncmp(env, "AFL_FUZZER_STATS_UPDATE_INTERVAL",

                              afl_environment_variable_len)) {

            u64 stats_update_freq_sec =
                strtoull(get_afl_env(afl_environment_variables[i]), NULL, 0);
            if (stats_update_freq_sec >= UINT_MAX ||
                0 == stats_update_freq_sec) {

              WARNF(
                  "Incorrect value given to AFL_FUZZER_STATS_UPDATE_INTERVAL, "
                  "using default of %d seconds\n",
                  STATS_UPDATE_SEC);

            } else {

              afl->stats_file_update_freq_msecs = stats_update_freq_sec * 1000;

            }

          } else if (!strncmp(env, "AFL_SHA1_FILENAMES",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_sha1_filenames =
                get_afl_env(afl_environment_variables[i]) ? 1 : 0;

          }

        } else {

          i++;

        }

      }

      i = 0;
      while (match == 0 && afl_environment_variables[i] != NULL) {

        if (strncmp(env, afl_environment_variables[i],
                    strlen(afl_environment_variables[i])) == 0 &&
            env[strlen(afl_environment_variables[i])] == '=') {

          match = 1;

        } else {

          i++;

        }

      }

      i = 0;
      while (match == 0 && afl_environment_deprecated[i] != NULL) {

        if (strncmp(env, afl_environment_deprecated[i],
                    strlen(afl_environment_deprecated[i])) == 0 &&
            env[strlen(afl_environment_deprecated[i])] == '=') {

          match = 1;

          WARNF("AFL environment variable %s is deprecated!",
                afl_environment_deprecated[i]);
          issue_detected = 1;

        } else {

          i++;

        }

      }

      if (match == 0) {

        WARNF("Mistyped AFL environment variable: %s", env);
        issue_detected = 1;

        print_suggested_envs(env);

      }

    }

  }

  if (afl->afl_env.afl_pizza_mode > 0) {

    afl->pizza_is_served = 1;

  } else if (afl->afl_env.afl_pizza_mode < 0) {

    OKF("Pizza easter egg mode is now disabled.");

  }

  if (issue_detected) { sleep(2); }

}

/* Removes this afl_state instance and frees it. */

void afl_state_deinit(afl_state_t *afl) {

  if (afl->in_place_resume) { ck_free(afl->in_dir); }
  if (afl->sync_id) { ck_free(afl->out_dir); }
  if (afl->pass_stats) { ck_free(afl->pass_stats); }
  if (afl->orig_cmp_map) { ck_free(afl->orig_cmp_map); }
  if (afl->cmplog_binary) { ck_free(afl->cmplog_binary); }

  afl_free(afl->queue_buf);
  afl_free(afl->out_buf);
  afl_free(afl->out_scratch_buf);
  afl_free(afl->eff_buf);
  afl_free(afl->in_buf);
  afl_free(afl->in_scratch_buf);
  afl_free(afl->ex_buf);

  ck_free(afl->virgin_bits);
  ck_free(afl->virgin_tmout);
  ck_free(afl->virgin_crash);
  ck_free(afl->var_bytes);
  ck_free(afl->top_rated);
  ck_free(afl->clean_trace);
  ck_free(afl->clean_trace_custom);
  ck_free(afl->first_trace);
  ck_free(afl->map_tmp_buf);

  list_remove(&afl_states, afl);

}

void afl_states_stop(void) {

  /* We may be inside a signal handler.
   Set flags first, send kill signals to child proceses later. */
  LIST_FOREACH(&afl_states, afl_state_t, {

    el->stop_soon = 1;

  });

  LIST_FOREACH(&afl_states, afl_state_t, {

    /* NOTE: We need to make sure that the parent (the forkserver) reap the
     * child (see below). */
    if (el->fsrv.child_pid > 0)
      kill(el->fsrv.child_pid, el->fsrv.child_kill_signal);
    if (el->fsrv.fsrv_pid > 0) {

      kill(el->fsrv.fsrv_pid, el->fsrv.fsrv_kill_signal);
      usleep(100);
      /* Make sure the forkserver does not end up as zombie. */
      waitpid(el->fsrv.fsrv_pid, NULL, WNOHANG);

    }

  });

}

void afl_states_clear_screen(void) {

  LIST_FOREACH(&afl_states, afl_state_t, { el->clear_screen = 1; });

}

void afl_states_request_skip(void) {

  LIST_FOREACH(&afl_states, afl_state_t, { el->skip_requested = 1; });

}

