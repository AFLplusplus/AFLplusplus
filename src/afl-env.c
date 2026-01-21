/*
   american fuzzy lop++ - environment variable handling implementation
   --------------------------------------------------------------------

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

   This provides a unified interface for handling AFL++ environment variables
   across all tools, decoupled from afl_state_t for broader usage.

 */

#include "afl-env.h"
#include "debug.h"
#include "envs.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

extern u8 be_quiet;

/* Initialize environment variables structure to defaults */
void afl_env_init(afl_env_vars_t *env) {

  if (!env) { return; }

  memset(env, 0, sizeof(afl_env_vars_t));

}

/* Helper function to get environment variable value (same as get_afl_env) */
static char *get_env_value(const char *env_name) {

  char *val;

  if ((val = getenv(env_name))) {

    if (*val) {

      if (!be_quiet) {

        OKF("Enabled environment variable %s with value %s", env_name, val);

      }

      return val;

    }

  }

  return NULL;

}

/* Read and parse AFL environment variables */
void afl_env_read(afl_env_vars_t *env, char **envp) {

  if (!env) { return; }

  int   index = 0, issue_detected = 0;
  char *env_str;

  /* If envp is provided, iterate through it. Otherwise fall back to getenv */
  if (envp) {

    while ((env_str = envp[index++]) != NULL) {

      if (strncmp(env_str, "ALF_", 4) == 0) {

        WARNF("Potentially mistyped AFL environment variable: %s", env_str);
        issue_detected = 1;

      } else if (strncmp(env_str, "USE_", 4) == 0) {

        WARNF(
            "Potentially mistyped AFL environment variable: %s, did you mean "
            "AFL_%s?",
            env_str, env_str);
        issue_detected = 1;

      } else if (strncmp(env_str, "AFL_", 4) == 0) {

        int i = 0, match = 0;
        while (match == 0 && afl_environment_variables[i] != NULL) {

          size_t afl_environment_variable_len =
              strlen(afl_environment_variables[i]);
          if (strncmp(env_str, afl_environment_variables[i],
                      afl_environment_variable_len) == 0 &&
              env_str[afl_environment_variable_len] == '=') {

            match = 1;

          }

          ++i;

        }

        if (!match) {

          char *ignore = getenv("AFL_IGNORE_UNKNOWN_ENVS");
          if (ignore) {

            WARNF("Unrecognized environment variable: %s (ignored)", env_str);

          } else {

            WARNF("Unrecognized environment variable: %s", env_str);

          }

          issue_detected = 1;

        }

      }

    }

  }

  /* Now parse the specific variables we care about */
  if (!strncmp((env_str = get_env_value("AFL_SKIP_CPUFREQ")) ? env_str : "",
               "", 1)) {

    env->afl_skip_cpufreq = get_env_value("AFL_SKIP_CPUFREQ") ? 1 : 0;

  }

  if ((env_str = get_env_value("AFL_EXIT_WHEN_DONE"))) {

    env->afl_exit_when_done = 1;

  }

  if ((env_str = get_env_value("AFL_EXIT_ON_TIME"))) {

    env->afl_exit_on_time = (u8 *)env_str;

  }

  if ((env_str = get_env_value("AFL_CRASHING_SEEDS_AS_NEW_CRASH"))) {

    env->afl_crashing_seeds_as_new_crash = atoi(env_str);

  }

  if ((env_str = get_env_value("AFL_NO_AFFINITY"))) {

    env->afl_no_affinity = 1;

  }

  if ((env_str = get_env_value("AFL_NO_WARN_INSTABILITY"))) {

    env->afl_no_warn_instability = 1;

  }

  if ((env_str = get_env_value("AFL_TRY_AFFINITY"))) {

    env->afl_try_affinity = 1;

  }

  if ((env_str = get_env_value("AFL_HANG_TMOUT"))) {

    env->afl_hang_tmout = (u8 *)env_str;

  }

  if ((env_str = get_env_value("AFL_KEEP_TIMEOUTS"))) {

    env->afl_keep_timeouts = 1;

  }

  if ((env_str = get_env_value("AFL_SKIP_BIN_CHECK"))) {

    env->afl_skip_bin_check = 1;

  }

  if ((env_str = get_env_value("AFL_DUMB_FORKSRV"))) {

    env->afl_dumb_forksrv = 1;

  }

  if ((env_str = get_env_value("AFL_IMPORT_FIRST"))) {

    env->afl_import_first = 1;

  }

  if ((env_str = get_env_value("AFL_FINAL_SYNC"))) {

    env->afl_final_sync = 1;

  }

  if ((env_str = get_env_value("AFL_NO_SYNC"))) {

    env->afl_no_sync = 1;

  }

  if ((env_str = get_env_value("AFL_NO_FASTRESUME"))) {

    env->afl_no_fastresume = 1;

  }

  if ((env_str = get_env_value("AFL_FORCE_FASTRESUME"))) {

    env->afl_force_fastresume = 1;

  }

  if ((env_str = get_env_value("AFL_CUSTOM_MUTATOR_ONLY"))) {

    env->afl_custom_mutator_only = 1;

  }

  if ((env_str = get_env_value("AFL_CUSTOM_MUTATOR_LATE_SEND"))) {

    env->afl_custom_mutator_late_send = 1;

  }

  if ((env_str = get_env_value("AFL_CMPLOG_ONLY_NEW"))) {

    env->afl_cmplog_only_new = 1;

  }

  if ((env_str = get_env_value("AFL_DISABLE_REDUNDANT")) ||
      (env_str = get_env_value("AFL_NO_REDUNDANT"))) {

    env->afl_disable_redundant = 1;

  }

  if ((env_str = get_env_value("AFL_NO_STARTUP_CALIBRATION"))) {

    env->afl_no_startup_calibration = 1;

  }

  if ((env_str = get_env_value("AFL_NO_UI"))) {

    env->afl_no_ui = 1;

  }

  if ((env_str = get_env_value("AFL_FORCE_UI"))) {

    env->afl_force_ui = 1;

  }

  if ((env_str = get_env_value("AFL_IGNORE_PROBLEMS"))) {

    env->afl_ignore_problems = 1;

  }

  if ((env_str = get_env_value("AFL_IGNORE_SEED_PROBLEMS"))) {

    env->afl_ignore_seed_problems = 1;

  }

  if ((env_str = get_env_value("AFL_IGNORE_TIMEOUTS"))) {

    env->afl_ignore_timeouts = 1;

  }

  if ((env_str = get_env_value("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES"))) {

    env->afl_i_dont_care_about_missing_crashes = 1;

  }

  if ((env_str = get_env_value("AFL_BENCH_JUST_ONE"))) {

    env->afl_bench_just_one = 1;

  }

  if ((env_str = get_env_value("AFL_BENCH_UNTIL_CRASH"))) {

    env->afl_bench_until_crash = 1;

  }

  if ((env_str = get_env_value("AFL_DEBUG_CHILD")) ||
      (env_str = get_env_value("AFL_DEBUG_CHILD_OUTPUT"))) {

    env->afl_debug_child = 1;

  }

  if ((env_str = get_env_value("AFL_AUTORESUME"))) {

    env->afl_autoresume = 1;

  }

  if ((env_str = get_env_value("AFL_PERSISTENT_RECORD"))) {

    env->afl_persistent_record = (u8 *)env_str;

  }

  if ((env_str = get_env_value("AFL_CYCLE_SCHEDULES"))) {

    env->afl_cycle_schedules = 1;

  }

  if ((env_str = get_env_value("AFL_EXIT_ON_SEED_ISSUES"))) {

    env->afl_exit_on_seed_issues = 1;

  }

  if ((env_str = get_env_value("AFL_EXPAND_HAVOC_NOW"))) {

    env->afl_expand_havoc = 1;

  }

  if ((env_str = get_env_value("AFL_CAL_FAST")) ||
      (env_str = get_env_value("AFL_FAST_CAL"))) {

    env->afl_cal_fast = 1;

  }

  if ((env_str = get_env_value("AFL_STATSD"))) {

    env->afl_statsd = 1;

  }

  if ((env_str = get_env_value("AFL_POST_PROCESS_KEEP_ORIGINAL"))) {

    env->afl_post_process_keep_original = 1;

  }

  if ((env_str = get_env_value("AFL_TMPDIR"))) {

    env->afl_tmpdir = (u8 *)env_str;

  }

  if ((env_str = get_env_value("AFL_CUSTOM_MUTATOR_LIBRARY"))) {

    env->afl_custom_mutator_library = (u8 *)env_str;

  }

  if ((env_str = get_env_value("AFL_PYTHON_MODULE"))) {

    env->afl_python_module = (u8 *)env_str;

  }

  if ((env_str = get_env_value("AFL_PATH"))) {

    env->afl_path = (u8 *)env_str;

  }

  if ((env_str = get_env_value("AFL_PRELOAD"))) {

    env->afl_preload = (u8 *)env_str;

  }

  if ((env_str = get_env_value("AFL_MAX_DET_EXTRAS"))) {

    env->afl_max_det_extras = (u8 *)env_str;

  }

  if ((env_str = get_env_value("AFL_FORKSRV_INIT_TMOUT"))) {

    env->afl_forksrv_init_tmout = (u8 *)env_str;

  }

  if ((env_str = get_env_value("AFL_TESTCACHE_SIZE"))) {

    env->afl_testcache_size = (u8 *)env_str;

  }

  if ((env_str = get_env_value("AFL_TESTCACHE_ENTRIES"))) {

    env->afl_testcache_entries = (u8 *)env_str;

  }

  if ((env_str = get_env_value("AFL_STATSD_HOST"))) {

    env->afl_statsd_host = (u8 *)env_str;

  }

  if ((env_str = get_env_value("AFL_STATSD_PORT"))) {

    env->afl_statsd_port = (u8 *)env_str;

  }

  if ((env_str = get_env_value("AFL_STATSD_TAGS_FLAVOR"))) {

    env->afl_statsd_tags_flavor = (u8 *)env_str;

  }

  if ((env_str = get_env_value("AFL_CRASH_EXITCODE"))) {

    env->afl_crash_exitcode = (u8 *)env_str;

  }

#if defined USE_COLOR && !defined ALWAYS_COLORED
  /* Note: AFL_NO_COLOR and AFL_NO_COLOUR are handled elsewhere */
#endif

  if ((env_str = get_env_value("AFL_KILL_SIGNAL"))) {

    env->afl_child_kill_signal = (u8 *)env_str;

  }

  if ((env_str = get_env_value("AFL_FORK_SERVER_KILL_SIGNAL"))) {

    env->afl_fsrv_kill_signal = (u8 *)env_str;

  }

  if ((env_str = get_env_value("AFL_TARGET_ENV"))) {

    env->afl_target_env = (u8 *)env_str;

  }

  if ((env_str = get_env_value("AFL_IJON_HISTORY_LIMIT"))) {

    env->afl_ijon_history_limit = atoi(env_str);
    if (env->afl_ijon_history_limit < 0) { env->afl_ijon_history_limit = 0; }

  }

  if ((env_str = get_env_value("AFL_PIZZA_MODE"))) {

    env->afl_pizza_mode = atoi(env_str);

  }

  if ((env_str = get_env_value("AFL_SHA1_FILENAMES"))) {

    env->afl_sha1_filenames = 1;

  }

  if ((env_str = get_env_value("AFL_NO_CRASH_README"))) {

    env->afl_no_crash_readme = 1;

  }

  /* Handle UID/GID settings */
  if ((env_str = get_env_value("AFL_FORKSRV_UID"))) {

    env->afl_forksrv_uid = (uid_t)atoi(env_str);
    env->afl_forksrv_uid_set = 1;

  }

  if ((env_str = get_env_value("AFL_FORKSRV_GID"))) {

    env->afl_forksrv_gid = (gid_t)atoi(env_str);
    env->afl_forksrv_gid_set = 1;

  }

  if (issue_detected) { SAYF("\n"); }

}

/* Free any allocated memory in the environment structure */
void afl_env_free(afl_env_vars_t *env) {

  if (!env) { return; }

  /* Note: String pointers in the structure point to environment variables
     which are managed by the system, so we don't free them.
     If we allocated any supplementary arrays, we'd free them here. */

  if (env->afl_forksrv_supl_gids) {

    free(env->afl_forksrv_supl_gids);
    env->afl_forksrv_supl_gids = NULL;

  }

}

/* Get a specific environment variable value with logging */
char *afl_getenv(const char *env) {

  return get_env_value(env);

}
