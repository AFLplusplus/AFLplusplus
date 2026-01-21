/*
   american fuzzy lop++ - environment variable handling
   -----------------------------------------------------

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

#ifndef _AFL_ENV_H
#define _AFL_ENV_H

#include "types.h"
#include <sys/types.h>

/* Environment variables structure - standalone and reusable */

typedef struct afl_env_vars {

  u8 afl_skip_cpufreq, afl_exit_when_done, afl_no_affinity, afl_skip_bin_check,
      afl_dumb_forksrv, afl_import_first, afl_custom_mutator_only,
      afl_custom_mutator_late_send, afl_no_ui, afl_force_ui,
      afl_i_dont_care_about_missing_crashes, afl_bench_just_one,
      afl_bench_until_crash, afl_debug_child, afl_autoresume, afl_cal_fast,
      afl_cycle_schedules, afl_expand_havoc, afl_statsd, afl_cmplog_only_new,
      afl_exit_on_seed_issues, afl_try_affinity, afl_ignore_problems,
      afl_keep_timeouts, afl_no_crash_readme, afl_ignore_timeouts,
      afl_no_startup_calibration, afl_no_warn_instability,
      afl_post_process_keep_original, afl_crashing_seeds_as_new_crash,
      afl_final_sync, afl_ignore_seed_problems, afl_disable_redundant,
      afl_sha1_filenames, afl_no_sync, afl_no_fastresume, afl_force_fastresume,
      afl_forksrv_uid_set, afl_forksrv_gid_set;

  u16 afl_forksrv_nb_supl_gids;

  u8 *afl_tmpdir, *afl_custom_mutator_library, *afl_python_module, *afl_path,
      *afl_hang_tmout, *afl_forksrv_init_tmout, *afl_preload,
      *afl_max_det_extras, *afl_statsd_host, *afl_statsd_port,
      *afl_crash_exitcode, *afl_statsd_tags_flavor, *afl_testcache_size,
      *afl_testcache_entries, *afl_child_kill_signal, *afl_fsrv_kill_signal,
      *afl_target_env, *afl_persistent_record, *afl_exit_on_time;

  s32 afl_pizza_mode, afl_ijon_history_limit;

  uid_t afl_forksrv_uid;

  gid_t afl_forksrv_gid;

  gid_t *afl_forksrv_supl_gids;

} afl_env_vars_t;

/* Function prototypes */

/* Initialize environment variables structure to defaults */
void afl_env_init(afl_env_vars_t *env);

/* Read and parse AFL environment variables from envp or current environment
   If envp is NULL, uses the current process environment via getenv() */
void afl_env_read(afl_env_vars_t *env, char **envp);

/* Free any allocated memory in the environment structure */
void afl_env_free(afl_env_vars_t *env);

/* Get a specific environment variable value with logging
   This is a convenience wrapper around getenv() that provides
   consistent logging behavior */
char *afl_getenv(const char *env);

#endif                                                         /* _AFL_ENV_H */
