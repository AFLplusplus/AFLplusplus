/*
   american fuzzy lop++ - fuzzer header
   ------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                     Dominik Maier <mail@dmnk.co>,
                     Andrea Fioraldi <andreafioraldi@gmail.com>, and
                     Heiko Eissfeldt <heiko.eissfeldt@hexco.de>

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

#ifndef _AFL_FUZZ_H
#define _AFL_FUZZ_H

#define AFL_MAIN
#define MESSAGES_TO_STDOUT

#ifndef _GNU_SOURCE
  #define _GNU_SOURCE
#endif
#ifndef _FILE_OFFSET_BITS
  #define _FILE_OFFSET_BITS 64
#endif

#include "config.h"
#include "types.h"
#include "debug.h"
#include "alloc-inl.h"
#include "hash.h"
#include "sharedmem.h"
#include "forkserver.h"
#include "common.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h>
#include <ctype.h>
#include <fcntl.h>
#include <termios.h>
#include <dlfcn.h>
#include <sched.h>

#include <netdb.h>
#include <netinet/in.h>

#include <sys/wait.h>
#include <sys/time.h>
#ifndef USEMMAP
  #include <sys/shm.h>
#endif
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/file.h>
#include <sys/types.h>

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || \
    defined(__NetBSD__) || defined(__DragonFly__)
  #include <sys/sysctl.h>
#endif                           /* __APPLE__ || __FreeBSD__ || __OpenBSD__ */

#if defined(__HAIKU__)
  #include <kernel/OS.h>
  #include <kernel/scheduler.h>
#endif

/* For systems that have sched_setaffinity; right now just Linux, but one
   can hope... */

#if defined(__linux__) || defined(__FreeBSD__) || defined(__NetBSD__) || \
    defined(__DragonFly__) || defined(__sun)
  #define HAVE_AFFINITY 1
  #if defined(__FreeBSD__) || defined(__DragonFly__)
    #include <sys/param.h>
    #if defined(__FreeBSD__)
      #include <sys/cpuset.h>
    #endif
    #include <sys/user.h>
    #include <pthread.h>
    #include <pthread_np.h>
    #define cpu_set_t cpuset_t
  #elif defined(__NetBSD__)
    #include <pthread.h>
  #elif defined(__sun)
    #include <sys/types.h>
    #include <kstat.h>
    #include <sys/sysinfo.h>
    #include <sys/pset.h>
    #include <strings.h>
  #endif
#endif                                                         /* __linux__ */

#ifdef __APPLE__
  #include <TargetConditionals.h>
#endif

#undef LIST_FOREACH                                 /* clashes with FreeBSD */
#include "list.h"
#ifndef SIMPLE_FILES
  #define CASE_PREFIX "id:"
#else
  #define CASE_PREFIX "id_"
#endif                                                    /* ^!SIMPLE_FILES */

#ifdef AFL_PERSISTENT_RECORD
  #define RECORD_PREFIX "RECORD:"
#endif

#define STAGE_BUF_SIZE (64)  /* usable size for stage name buf in afl_state */

// Little helper to access the ptr to afl->##name_buf - for use in afl_realloc.
#define AFL_BUF_PARAM(name) ((void **)&afl->name##_buf)

#ifdef WORD_SIZE_64
  #define AFL_RAND_RETURN u64
#else
  #define AFL_RAND_RETURN u32
#endif

#ifndef INTERESTING_32_LEN
  #error INTERESTING_32_LEN not defined - BUG!
#endif

extern s8  interesting_8[INTERESTING_8_LEN];
extern s16 interesting_16[INTERESTING_8_LEN + INTERESTING_16_LEN];
extern s32
    interesting_32[INTERESTING_8_LEN + INTERESTING_16_LEN + INTERESTING_32_LEN];

struct tainted {

  u32             pos;
  u32             len;
  struct tainted *next;
  struct tainted *prev;

};

struct inf_profile {

  u32 inf_skipped_bytes;               /* Inference Stage Profiling         */
  u64 inf_execs_cost, inf_time_cost;

};

/* ToDo: add cmplog profile as well */
struct havoc_profile {

  u32 queued_det_stage,                 /* Det/Havoc Stage Profiling        */
      queued_havoc_stage, total_queued_det, edge_det_stage, edge_havoc_stage,
      total_det_edge;

  u64 det_stage_time, havoc_stage_time, total_det_time;

};

struct skipdet_entry {

  u8  continue_inf, done_eff;
  u32 undet_bits, quick_eff_bytes;

  u8 *skip_eff_map,                     /* we'v finish the eff_map          */
      *done_inf_map;                    /* some bytes are not done yet      */

};

struct skipdet_global {

  u8 use_skip_havoc;

  u32 undet_bits_threshold;

  u64 last_cov_undet;

  u8 *virgin_det_bits;                  /* global fuzzed bits               */

  struct inf_profile *inf_prof;

};

struct queue_entry {

  u8 *fname;                            /* File name for the test case      */
  u32 len;                              /* Input length                     */
  u32 id;                               /* entry number in queue_buf        */

  u8 colorized,                         /* Do not run redqueen stage again  */
      cal_failed;                       /* Calibration failed?              */

  bool trim_done,                       /* Trimmed?                         */
      was_fuzzed,                       /* historical, but needed for MOpt  */
      passed_det,                       /* Deterministic stages passed?     */
      has_new_cov,                      /* Triggers new coverage?           */
      var_behavior,                     /* Variable behavior?               */
      favored,                          /* Currently favored?               */
      fs_redundant,                     /* Marked as redundant in the fs?   */
      is_ascii,                         /* Is the input just ascii text?    */
      disabled;                         /* Is disabled from fuzz selection  */

  u32 bitmap_size,                      /* Number of bits set in bitmap     */
#ifdef INTROSPECTION
      stats_selected,                   /* stats: how often selected        */
      stats_skipped,                    /* stats: how often skipped         */
      stats_finds,                      /* stats: # of saved finds          */
      stats_crashes,                    /* stats: # of saved crashes        */
      stats_tmouts,                     /* stats: # of saved timeouts       */
#endif
      fuzz_level,                       /* Number of fuzzing iterations     */
      n_fuzz_entry;                     /* offset in n_fuzz                 */

  u64 exec_us,                          /* Execution time (us)              */
      handicap,                         /* Number of queue cycles behind    */
      depth,                            /* Path depth                       */
      exec_cksum,                       /* Checksum of the execution trace  */
      custom,                           /* Marker for custom mutators       */
      stats_mutated;                    /* stats: # of mutations performed  */

  u8 *trace_mini;                       /* Trace bytes, if kept             */
  u32 tc_ref;                           /* Trace bytes ref count            */

#ifdef INTROSPECTION
  u32 bitsmap_size;
#endif

  double perf_score,                    /* performance score                */
      weight;

  u8 *testcase_buf;                     /* The testcase buffer, if loaded.  */

  u8             *cmplog_colorinput;    /* the result buf of colorization   */
  struct tainted *taint;                /* Taint information from CmpLog    */

  struct queue_entry *mother;           /* queue entry this based on        */

  struct skipdet_entry *skipdet_e;

};

struct extra_data {

  u8 *data;                             /* Dictionary token data            */
  u32 len;                              /* Dictionary token length          */
  u32 hit_cnt;                          /* Use count in the corpus          */

};

struct auto_extra_data {

  u8  data[MAX_AUTO_EXTRA];             /* Dictionary token data            */
  u32 len;                              /* Dictionary token length          */
  u32 hit_cnt;                          /* Use count in the corpus          */

};

/* Fuzzing stages */

enum {

  /* 00 */ STAGE_FLIP1,
  /* 01 */ STAGE_FLIP2,
  /* 02 */ STAGE_FLIP4,
  /* 03 */ STAGE_FLIP8,
  /* 04 */ STAGE_FLIP16,
  /* 05 */ STAGE_FLIP32,
  /* 06 */ STAGE_ARITH8,
  /* 07 */ STAGE_ARITH16,
  /* 08 */ STAGE_ARITH32,
  /* 09 */ STAGE_INTEREST8,
  /* 10 */ STAGE_INTEREST16,
  /* 11 */ STAGE_INTEREST32,
  /* 12 */ STAGE_EXTRAS_UO,
  /* 13 */ STAGE_EXTRAS_UI,
  /* 14 */ STAGE_EXTRAS_AO,
  /* 15 */ STAGE_EXTRAS_AI,
  /* 16 */ STAGE_HAVOC,
  /* 17 */ STAGE_SPLICE,
  /* 18 */ STAGE_PYTHON,
  /* 19 */ STAGE_CUSTOM_MUTATOR,
  /* 20 */ STAGE_COLORIZATION,
  /* 21 */ STAGE_ITS,
  /* 22 */ STAGE_INF,
  /* 23 */ STAGE_QUICK,

  STAGE_NUM_MAX

};

/* Stage value types */

enum {

  /* 00 */ STAGE_VAL_NONE,
  /* 01 */ STAGE_VAL_LE,
  /* 02 */ STAGE_VAL_BE

};

#define operator_num 19
#define swarm_num 5
#define period_core 500000

#define RAND_C (rand() % 1000 * 0.001)
#define v_max 1
#define v_min 0.05
#define limit_time_bound 1.1
#define SPLICE_CYCLES_puppet_up 25
#define SPLICE_CYCLES_puppet_low 5
#define STAGE_RANDOMBYTE 12
#define STAGE_DELETEBYTE 13
#define STAGE_Clone75 14
#define STAGE_OverWrite75 15
#define STAGE_OverWriteExtra 16
#define STAGE_InsertExtra 17
#define STAGE_Splice 18
#define period_pilot 50000

enum {

  /* 00 */ EXPLORE, /* AFL default, Exploration-based constant schedule */
  /* 01 */ MMOPT,   /* Modified MOPT schedule           */
  /* 02 */ EXPLOIT, /* AFL's exploitation-based const.  */
  /* 03 */ FAST,    /* Exponential schedule             */
  /* 04 */ COE,     /* Cut-Off Exponential schedule     */
  /* 05 */ LIN,     /* Linear schedule                  */
  /* 06 */ QUAD,    /* Quadratic schedule               */
  /* 07 */ RARE,    /* Rare edges                       */
  /* 08 */ SEEK,    /* EXPLORE that ignores timings     */

  POWER_SCHEDULES_NUM

};

/* Python stuff */
#ifdef USE_PYTHON

  // because Python sets stuff it should not ...
  #ifdef _POSIX_C_SOURCE
    #define _SAVE_POSIX_C_SOURCE _POSIX_C_SOURCE
    #undef _POSIX_C_SOURCE
  #endif
  #ifdef _XOPEN_SOURCE
    #define _SAVE_XOPEN_SOURCE _XOPEN_SOURCE
    #undef _XOPEN_SOURCE
  #endif

  #include <Python.h>

  #ifdef _SAVE_POSIX_C_SOURCE
    #ifdef _POSIX_C_SOURCE
      #undef _POSIX_C_SOURCE
    #endif
    #define _POSIX_C_SOURCE _SAVE_POSIX_C_SOURCE
  #endif
  #ifdef _SAVE_XOPEN_SOURCE
    #ifdef _XOPEN_SOURCE
      #undef _XOPEN_SOURCE
    #endif
    #define _XOPEN_SOURCE _SAVE_XOPEN_SOURCE
  #endif

enum {

  /* 00 */ PY_FUNC_INIT,
  /* 01 */ PY_FUNC_DEINIT,
  /* FROM HERE ON BELOW ALL ARE OPTIONAL */
  /* 02 */ PY_OPTIONAL = 2,
  /* 02 */ PY_FUNC_FUZZ = 2,
  /* 03 */ PY_FUNC_FUZZ_COUNT,
  /* 04 */ PY_FUNC_POST_PROCESS,
  /* 05 */ PY_FUNC_INIT_TRIM,
  /* 06 */ PY_FUNC_POST_TRIM,
  /* 07 */ PY_FUNC_TRIM,
  /* 08 */ PY_FUNC_HAVOC_MUTATION,
  /* 09 */ PY_FUNC_HAVOC_MUTATION_PROBABILITY,
  /* 10 */ PY_FUNC_QUEUE_GET,
  /* 11 */ PY_FUNC_QUEUE_NEW_ENTRY,
  /* 12 */ PY_FUNC_INTROSPECTION,
  /* 13 */ PY_FUNC_DESCRIBE,
  /* 14 */ PY_FUNC_FUZZ_SEND,
  /* 15 */ PY_FUNC_SPLICE_OPTOUT,
  /* 16 */ PY_FUNC_POST_RUN,
  PY_FUNC_COUNT

};

typedef struct py_mutator {

  PyObject *py_module;
  PyObject *py_functions[PY_FUNC_COUNT];
  void     *afl_state;
  void     *py_data;

  u8    *fuzz_buf;
  size_t fuzz_size;

  Py_buffer post_process_buf;

  u8    *trim_buf;
  size_t trim_size;

  u8    *havoc_buf;
  size_t havoc_size;

} py_mutator_t;

#endif

typedef struct MOpt_globals {

  u64  *finds;
  u64  *finds_v2;
  u64  *cycles;
  u64  *cycles_v2;
  u64  *cycles_v3;
  u32   is_pilot_mode;
  u64  *pTime;
  u64   period;
  char *havoc_stagename;
  char *splice_stageformat;
  char *havoc_stagenameshort;
  char *splice_stagenameshort;

} MOpt_globals_t;

extern char *power_names[POWER_SCHEDULES_NUM];

typedef struct afl_env_vars {

  u8 afl_skip_cpufreq, afl_exit_when_done, afl_no_affinity, afl_skip_bin_check,
      afl_dumb_forksrv, afl_import_first, afl_custom_mutator_only, afl_no_ui,
      afl_force_ui, afl_i_dont_care_about_missing_crashes, afl_bench_just_one,
      afl_bench_until_crash, afl_debug_child, afl_autoresume, afl_cal_fast,
      afl_cycle_schedules, afl_expand_havoc, afl_statsd, afl_cmplog_only_new,
      afl_exit_on_seed_issues, afl_try_affinity, afl_ignore_problems,
      afl_keep_timeouts, afl_no_crash_readme, afl_ignore_timeouts,
      afl_no_startup_calibration, afl_no_warn_instability,
      afl_post_process_keep_original, afl_crashing_seeds_as_new_crash,
      afl_final_sync, afl_ignore_seed_problems, afl_disable_redundant,
      afl_sha1_filenames, afl_no_sync;

  u8 *afl_tmpdir, *afl_custom_mutator_library, *afl_python_module, *afl_path,
      *afl_hang_tmout, *afl_forksrv_init_tmout, *afl_preload,
      *afl_max_det_extras, *afl_statsd_host, *afl_statsd_port,
      *afl_crash_exitcode, *afl_statsd_tags_flavor, *afl_testcache_size,
      *afl_testcache_entries, *afl_child_kill_signal, *afl_fsrv_kill_signal,
      *afl_target_env, *afl_persistent_record, *afl_exit_on_time;

  s32 afl_pizza_mode;

} afl_env_vars_t;

struct afl_pass_stat {

  u8 total;
  u8 faileds;

};

struct foreign_sync {

  u8    *dir;
  time_t mtime;

};

typedef struct afl_state {

  /* Position of this state in the global states list */
  u32 _id;

  afl_forkserver_t fsrv;
  sharedmem_t      shm;
  sharedmem_t     *shm_fuzz;
  afl_env_vars_t   afl_env;

  char **argv;                                            /* argv if needed */

  /* MOpt:
    Lots of globals, but mostly for the status UI and other things where it
    really makes no sense to haul them around as function parameters. */
  u64 orig_hit_cnt_puppet, last_limit_time_start, tmp_pilot_time,
      total_pacemaker_time, total_puppet_find, temp_puppet_find, most_time_key,
      most_time, most_execs_key, most_execs, old_hit_count, force_ui_update,
      prev_run_time;

  MOpt_globals_t mopt_globals_core, mopt_globals_pilot;

  s32 limit_time_puppet, SPLICE_CYCLES_puppet, limit_time_sig, key_puppet,
      key_module;

  double w_init, w_end, w_now;

  s32 g_now;
  s32 g_max;

  u64 tmp_core_time;
  s32 swarm_now;

  double x_now[swarm_num][operator_num], L_best[swarm_num][operator_num],
      eff_best[swarm_num][operator_num], G_best[operator_num],
      v_now[swarm_num][operator_num], probability_now[swarm_num][operator_num],
      swarm_fitness[swarm_num];

  u64 stage_finds_puppet[swarm_num][operator_num], /* Patterns found per
                                                            fuzz stage    */
      stage_finds_puppet_v2[swarm_num][operator_num],
      stage_cycles_puppet_v2[swarm_num][operator_num],
      stage_cycles_puppet_v3[swarm_num][operator_num],
      stage_cycles_puppet[swarm_num][operator_num],
      operator_finds_puppet[operator_num],
      core_operator_finds_puppet[operator_num],
      core_operator_finds_puppet_v2[operator_num],
      core_operator_cycles_puppet[operator_num],
      core_operator_cycles_puppet_v2[operator_num],
      core_operator_cycles_puppet_v3[operator_num]; /* Execs per fuzz stage */

  double period_pilot_tmp;
  s32    key_lv;

  u8 *in_dir,                           /* Input directory with test cases  */
      *out_dir,                         /* Working & output directory       */
      *tmp_dir,                         /* Temporary directory for input    */
      *sync_dir,                        /* Synchronization directory        */
      *sync_id,                         /* Fuzzer ID                        */
      *power_name,                      /* Power schedule name              */
      *use_banner,                      /* Display banner                   */
      *in_bitmap,                       /* Input bitmap                     */
      *file_extension,                  /* File extension                   */
      *orig_cmdline,                    /* Original command line            */
      *infoexec;                       /* Command to execute on a new crash */

  u32 hang_tmout,                       /* Timeout used for hang det (ms)   */
      stats_update_freq;                /* Stats update frequency (execs)   */

  u8 havoc_stack_pow2,                  /* HAVOC_STACK_POW2                 */
      no_unlink,                        /* do not unlink cur_input          */
      debug,                            /* Debug mode                       */
      custom_only,                      /* Custom mutator only mode         */
      custom_splice_optout,             /* Custom mutator no splice buffer  */
      is_main_node,                     /* if this is the main node         */
      is_secondary_node,                /* if this is a secondary instance  */
      pizza_is_served,                  /* pizza mode                       */
      input_mode,                       /* target wants text inputs         */
      fuzz_mode,          /* coverage/exploration or crash/exploitation mode */
      schedule,                         /* Power schedule (default: EXPLORE)*/
      havoc_max_mult,                   /* havoc multiplier                 */
      skip_deterministic,               /* Skip deterministic stages?       */
      use_splicing,                     /* Recombine input files?           */
      non_instrumented_mode,            /* Run in non-instrumented mode?    */
      score_changed,                    /* Scoring for favorites changed?   */
      resuming_fuzz,                    /* Resuming an older fuzzing job?   */
      timeout_given,                    /* Specific timeout given?          */
      not_on_tty,                       /* stdout is not a tty              */
      term_too_small,                   /* terminal dimensions too small    */
      no_forkserver,                    /* Disable forkserver?              */
      crash_mode,                       /* Crash mode! Yeah!                */
      in_place_resume,                  /* Attempt in-place resume?         */
      autoresume,                       /* Resume if afl->out_dir exists?   */
      auto_changed,                     /* Auto-generated tokens changed?   */
      no_cpu_meter_red,                 /* Feng shui on the status screen   */
      no_arith,                         /* Skip most arithmetic ops         */
      shuffle_queue,                    /* Shuffle input queue?             */
      bitmap_changed,                   /* Time to update bitmap?           */
      unicorn_mode,                     /* Running in Unicorn mode?         */
      use_wine,                         /* Use WINE with QEMU mode          */
      skip_requested,                   /* Skip request, via SIGUSR1        */
      run_over10m,                      /* Run time over 10 minutes?        */
      persistent_mode,                  /* Running in persistent mode?      */
      deferred_mode,                    /* Deferred forkserver mode?        */
      fixed_seed,                       /* do not reseed                    */
      fast_cal,                         /* Try to calibrate faster?         */
      disable_trim,                     /* Never trim in fuzz_one           */
      shmem_testcase_mode,              /* If sharedmem testcases are used  */
      expand_havoc,                /* perform expensive havoc after no find */
      cycle_schedules,                  /* cycle power schedules?           */
      old_seed_selection,               /* use vanilla afl seed selection   */
      reinit_table;                     /* reinit the queue weight table    */

  u8 *virgin_bits,                      /* Regions yet untouched by fuzzing */
      *virgin_tmout,                    /* Bits we haven't seen in tmouts   */
      *virgin_crash;                    /* Bits we haven't seen in crashes  */

  double *alias_probability;            /* alias weighted probabilities     */
  u32    *alias_table;                /* alias weighted random lookup table */
  u32     active_items;                 /* enabled entries in the queue     */

  u8 *var_bytes;                        /* Bytes that appear to be variable */

#define N_FUZZ_SIZE (1 << 21)
  u32 *n_fuzz;

  volatile u8 stop_soon,                /* Ctrl-C pressed?                  */
      clear_screen;                     /* Window resized?                  */

  u32 queued_items,                     /* Total number of queued testcases */
      queued_variable,                  /* Testcases with variable behavior */
      queued_at_start,                  /* Total number of initial inputs   */
      queued_discovered,                /* Items discovered during this run */
      queued_imported,                  /* Items imported via -S            */
      queued_favored,                   /* Paths deemed favorable           */
      queued_with_cov,                  /* Paths with new coverage bytes    */
      pending_not_fuzzed,               /* Queued but not done yet          */
      pending_favored,                  /* Pending favored paths            */
      cur_skipped_items,                /* Abandoned inputs in cur cycle    */
      cur_depth,                        /* Current path depth               */
      max_depth,                        /* Max path depth                   */
      useless_at_start,                 /* Number of useless starting paths */
      var_byte_count,                   /* Bitmap bytes with var behavior   */
      current_entry,                    /* Current queue entry ID           */
      havoc_div,                        /* Cycle count divisor for havoc    */
      max_det_extras;                   /* deterministic extra count (dicts)*/

  u64 total_crashes,                    /* Total number of crashes          */
      saved_crashes,                    /* Crashes with unique signatures   */
      total_tmouts,                     /* Total number of timeouts         */
      saved_tmouts,                     /* Timeouts with unique signatures  */
      saved_hangs,                      /* Hangs with unique signatures     */
      last_crash_execs,                 /* Exec counter at last crash       */
      queue_cycle,                      /* Queue round counter              */
      cycles_wo_finds,                  /* Cycles without any new paths     */
      trim_execs,                       /* Execs done to trim input files   */
      bytes_trim_in,                    /* Bytes coming into the trimmer    */
      bytes_trim_out,                   /* Bytes coming outa the trimmer    */
      blocks_eff_total,                 /* Blocks subject to effector maps  */
      blocks_eff_select,                /* Blocks selected as fuzzable      */
      start_time,                       /* Unix start time (ms)             */
      last_sync_time,                   /* Time of last sync                */
      last_sync_cycle,                  /* Cycle no. of the last sync       */
      last_find_time,                   /* Time for most recent path (ms)   */
      last_crash_time,                  /* Time for most recent crash (ms)  */
      last_hang_time,                   /* Time for most recent hang (ms)   */
      longest_find_time,                /* Longest time taken for a find    */
      exit_on_time,                     /* Delay to exit if no new paths    */
      sync_time,                        /* Sync time (ms)                   */
      switch_fuzz_mode,                 /* auto or fixed fuzz mode          */
      calibration_time_us,              /* Time spend on calibration        */
      sync_time_us,                     /* Time spend on sync               */
      trim_time_us;                     /* Time spend on trimming           */

  u32 slowest_exec_ms,                  /* Slowest testcase non hang in ms  */
      subseq_tmouts;                    /* Number of timeouts in a row      */

  u8 *stage_name,                       /* Name of the current fuzz stage   */
      *stage_short,                     /* Short stage name                 */
      *syncing_party;                   /* Currently syncing with...        */

  u8 stage_name_buf[STAGE_BUF_SIZE];    /* reused stagename buf with len 64 */

  u32 stage_cur, stage_max;             /* Stage progression                */
  s32 splicing_with;                    /* Splicing with which test case?   */
  s64 smallest_favored;                 /* smallest queue id favored        */

  u32 main_node_id, main_node_max;      /*   Main instance job splitting    */

  u32 syncing_case;                     /* Syncing with case #...           */

  s32 stage_cur_byte,                   /* Byte offset of current stage op  */
      stage_cur_val;                    /* Value used for stage op          */

  u8 stage_val_type;                    /* Value type (STAGE_VAL_*)         */

  u64 stage_finds[32],                  /* Patterns found per fuzz stage    */
      stage_cycles[32];                 /* Execs per fuzz stage             */

  u32 rand_cnt;                         /* Random number counter            */

  /*  unsigned long rand_seed[3]; would also work */
  AFL_RAND_RETURN rand_seed[3];
  s64             init_seed;

  u64 total_cal_us,                     /* Total calibration time (us)      */
      total_cal_cycles;                 /* Total calibration cycles         */

  u64 total_bitmap_size,                /* Total bit count for all bitmaps  */
      total_bitmap_entries;             /* Number of bitmaps counted        */

  s32 cpu_core_count,                   /* CPU core count                   */
      cpu_to_bind;                      /* bind to specific CPU             */

#ifdef HAVE_AFFINITY
  s32 cpu_aff;                          /* Selected CPU core                */
#endif                                                     /* HAVE_AFFINITY */

  struct queue_entry *queue,            /* Fuzzing queue (linked list)      */
      *queue_cur,                       /* Current offset within the queue  */
      *queue_top;                       /* Top of the list                  */

  // growing buf
  struct queue_entry **queue_buf;

  struct queue_entry **top_rated;           /* Top entries for bitmap bytes */

  struct extra_data *extras;            /* Extra tokens to fuzz with        */
  u32                extras_cnt;        /* Total number of tokens read      */

  struct auto_extra_data
      a_extras[MAX_AUTO_EXTRAS];        /* Automatically selected extras    */
  u32 a_extras_cnt;                     /* Total number of tokens available */

  /* afl_postprocess API - Now supported via custom mutators */

  /* CmpLog */

  char            *cmplog_binary;
  afl_forkserver_t cmplog_fsrv;     /* cmplog has its own little forkserver */

  /* Custom mutators */
  struct custom_mutator *mutator;

  /* cmplog forkserver ids */
  s32 cmplog_fsrv_ctl_fd, cmplog_fsrv_st_fd;
  u32 cmplog_prev_timed_out;
  u32 cmplog_max_filesize;
  u32 cmplog_lvl;
  u32 colorize_success;
  u8  cmplog_enable_arith, cmplog_enable_transform, cmplog_enable_scale,
      cmplog_enable_xtreme_transform, cmplog_random_colorization;

  struct afl_pass_stat *pass_stats;
  struct cmp_map       *orig_cmp_map;

  u8 describe_op_buf_256[256]; /* describe_op will use this to return a string
                                  up to 256 */

  unsigned long long int last_avg_exec_update;
  u32                    last_avg_execs;
  double                 last_avg_execs_saved;

/* foreign sync */
#define FOREIGN_SYNCS_MAX 32U
  u8                  foreign_sync_cnt;
  struct foreign_sync foreign_syncs[FOREIGN_SYNCS_MAX];

#ifdef _AFL_DOCUMENT_MUTATIONS
  u8  do_document;
  u32 document_counter;
#endif

  /* statistics file */
  double last_bitmap_cvg, last_stability, last_eps;
  u64    stats_file_update_freq_msecs;  /* Stats update frequency (msecs)   */

  /* plot file saves from last run */
  u32 plot_prev_qp, plot_prev_pf, plot_prev_pnf, plot_prev_ce, plot_prev_md;
  u64 plot_prev_qc, plot_prev_uc, plot_prev_uh, plot_prev_ed;

  u64 stats_last_stats_ms, stats_last_plot_ms, stats_last_queue_ms,
      stats_last_ms, stats_last_execs;

  /* StatsD */
  u64                statsd_last_send_ms;
  struct sockaddr_in statsd_server;
  int                statsd_sock;
  char              *statsd_tags_flavor;
  char              *statsd_tags_format;
  char              *statsd_metric_format;
  int                statsd_metric_format_type;

  double stats_avg_exec;

  u8 *clean_trace;
  u8 *clean_trace_custom;
  u8 *first_trace;

  /*needed for afl_fuzz_one */
  // TODO: see which we can reuse
  u8 *out_buf;

  u8 *out_scratch_buf;

  u8 *eff_buf;

  u8 *in_buf;

  u8 *in_scratch_buf;

  u8 *ex_buf;

  u8 *testcase_buf, *splicecase_buf;

  u32 custom_mutators_count;

  struct custom_mutator *current_custom_fuzz;

  list_t custom_mutator_list;

  /* this is a fixed buffer of size map_size that can be used by any function if
   * they do not call another function */
  u8 *map_tmp_buf;

  /* queue entries ready for splicing count (len > 4) */
  u32 ready_for_splicing_count;

  /* min/max length for generated fuzzing inputs */
  u32 min_length, max_length;

  /* This is the user specified maximum size to use for the testcase cache */
  u64 q_testcase_max_cache_size;

  /* This is the user specified maximum entries in the testcase cache */
  u32 q_testcase_max_cache_entries;

  /* How much of the testcase cache is used so far */
  u64 q_testcase_cache_size;

  /* highest cache count so far */
  u32 q_testcase_max_cache_count;

  /* How many queue entries currently have cached testcases */
  u32 q_testcase_cache_count;

  /* the smallest id currently known free entry */
  u32 q_testcase_smallest_free;

  /* How often did we evict from the cache (for statistics only) */
  u32 q_testcase_evictions;

  /* Refs to each queue entry with cached testcase (for eviction, if cache_count
   * is too large) */
  struct queue_entry **q_testcase_cache;

  /* Global Profile Data for deterministic/havoc-splice stage */
  struct havoc_profile *havoc_prof;

  struct skipdet_global *skipdet_g;

#ifdef INTROSPECTION
  char  mutation[8072];
  char  m_tmp[4096];
  FILE *introspection_file;
  u32   bitsmap_size;
#endif

} afl_state_t;

struct custom_mutator {

  const char *name;
  char       *name_short;
  void       *dh;
  u8         *post_process_buf;
  u8          stacked_custom_prob, stacked_custom;

  void *data;                                    /* custom mutator data ptr */

  /* hooks for the custom mutator function */

  /**
   * Initialize the custom mutator.
   *
   * @param afl AFL instance.
   * @param seed Seed used for the mutation.
   * @return pointer to internal data or NULL on error
   */
  void *(*afl_custom_init)(afl_state_t *afl, unsigned int seed);

  /**
   * When afl-fuzz was compiled with INTROSPECTION=1 then custom mutators can
   * also give introspection information back with this function.
   *
   * @param data pointer returned in afl_custom_init by this custom mutator
   * @return pointer to a text string (const char*)
   */
  const char *(*afl_custom_introspection)(void *data);

  /**
   * This method is called just before fuzzing a queue entry with the custom
   * mutator, and receives the initial buffer. It should return the number of
   * fuzzes to perform.
   *
   * A value of 0 means no fuzzing of this queue entry.
   *
   * The function is now allowed to change the data.
   *
   * (Optional)
   *
   * @param data pointer returned in afl_custom_init by this custom mutator
   * @param buf Buffer containing the test case
   * @param buf_size Size of the test case
   * @return The amount of fuzzes to perform on this queue entry, 0 = skip
   */
  u32 (*afl_custom_fuzz_count)(void *data, const u8 *buf, size_t buf_size);

  /**
   * Opt-out of a splicing input for the fuzz mutator
   *
   * Empty dummy function. It's presence tells afl-fuzz not to pass a
   * splice data pointer and len.
   *
   * @param data pointer returned in afl_custom_init by this custom mutator
   * @noreturn
   */
  void (*afl_custom_splice_optout)(void *data);

  /**
   * Perform custom mutations on a given input
   *
   * (Optional)
   *
   * Getting an add_buf can be skipped by using afl_custom_splice_optout().
   *
   * @param[in] data Pointer returned in afl_custom_init by this custom mutator
   * @param[in] buf Pointer to the input data to be mutated and the mutated
   *     output
   * @param[in] buf_size Size of the input/output data
   * @param[out] out_buf The new buffer, under your memory mgmt.
   * @param[in] add_buf Buffer containing an additional test case (splicing)
   * @param[in] add_buf_size Size of the additional test case
   * @param[in] max_size Maximum size of the mutated output. The mutation must
   * not produce data larger than max_size.
   * @return Size of the mutated output.
   */
  size_t (*afl_custom_fuzz)(void *data, u8 *buf, size_t buf_size, u8 **out_buf,
                            u8 *add_buf, size_t add_buf_size, size_t max_size);

  /**
   * Describe the current testcase, generated by the last mutation.
   * This will be called, for example, to give the written testcase a name
   * after a crash ocurred. It can help to reproduce crashing mutations.
   *
   * (Optional)
   *
   * @param data pointer returned by afl_customm_init for this custom mutator
   * @paramp[in] max_description_len maximum size avaliable for the description.
   *             A longer return string is legal, but will be truncated.
   * @return A valid ptr to a 0-terminated string.
   *         An empty or NULL return will result in a default description
   */
  const char *(*afl_custom_describe)(void *data, size_t max_description_len);

  /**
   * A post-processing function to use right before AFL writes the test case to
   * disk in order to execute the target.
   *
   * NOTE: Do not do any random changes to the data in this function!
   *
   * PERFORMANCE: If you can modify the data in-place you will have a better
   *              performance. Modify *data and set `*out_buf = data`.
   *
   * (Optional) If this functionality is not needed, simply do not define this
   * function.
   *
   * @param[in] data pointer returned in afl_custom_init by this custom mutator
   * @param[in] buf Buffer containing the test case to be executed
   * @param[in] buf_size Size of the test case
   * @param[out] out_buf Pointer to the buffer storing the test case after
   *     processing. The external library should allocate memory for out_buf.
   *     It can chose to alter buf in-place, if the space is large enough.
   * @return Size of the output buffer.
   */
  size_t (*afl_custom_post_process)(void *data, u8 *buf, size_t buf_size,
                                    u8 **out_buf);

  /**
   * This method is called at the start of each trimming operation and receives
   * the initial buffer. It should return the amount of iteration steps possible
   * on this input (e.g. if your input has n elements and you want to remove
   * them one by one, return n, if you do a binary search, return log(n),
   * and so on...).
   *
   * If your trimming algorithm doesn't allow you to determine the amount of
   * (remaining) steps easily (esp. while running), then you can alternatively
   * return 1 here and always return 0 in post_trim until you are finished and
   * no steps remain. In that case, returning 1 in post_trim will end the
   * trimming routine. The whole current index/max iterations stuff is only used
   * to show progress.
   *
   * (Optional)
   *
   * @param data pointer returned in afl_custom_init by this custom mutator
   * @param buf Buffer containing the test case
   * @param buf_size Size of the test case
   * @return The amount of possible iteration steps to trim the input.
   *        Negative on error.
   */
  s32 (*afl_custom_init_trim)(void *data, u8 *buf, size_t buf_size);

  /**
   * This method is called for each trimming operation. It doesn't have any
   * arguments because we already have the initial buffer from init_trim and we
   * can memorize the current state in global variables. This can also save
   * reparsing steps for each iteration. It should return the trimmed input
   * buffer, where the returned data must not exceed the initial input data in
   * length. Returning anything that is larger than the original data (passed
   * to init_trim) will result in a fatal abort of AFLFuzz.
   *
   * (Optional)
   *
   * @param data pointer returned in afl_custom_init by this custom mutator
   * @param[out] out_buf Pointer to the buffer containing the trimmed test case.
   *             The library can reuse a buffer for each call
   *             and will have to free the buf (for example in deinit)
   * @return the size of the trimmed test case
   */
  size_t (*afl_custom_trim)(void *data, u8 **out_buf);

  /**
   * This method is called after each trim operation to inform you if your
   * trimming step was successful or not (in terms of coverage). If you receive
   * a failure here, you should reset your input to the last known good state.
   *
   * (Optional)
   *
   * @param data pointer returned in afl_custom_init by this custom mutator
   * @param success Indicates if the last trim operation was successful.
   * @return The next trim iteration index (from 0 to the maximum amount of
   *     steps returned in init_trim). Negative on error.
   */
  s32 (*afl_custom_post_trim)(void *data, u8 success);

  /**
   * Perform a single custom mutation on a given input.
   * This mutation is stacked with the other muatations in havoc.
   *
   * (Optional)
   *
   * @param[in] data pointer returned in afl_custom_init by this custom mutator
   * @param[in] buf Pointer to the input data to be mutated and the mutated
   *     output
   * @param[in] buf_size Size of input data
   * @param[out] out_buf The new buffer. It's legal to reuse *buf if it's <
   * buf_size.
   * @param[in] max_size Maximum size of the mutated output. The mutation must
   *     not produce data larger than max_size.
   * @return Size of the mutated output (out_size).
   */
  size_t (*afl_custom_havoc_mutation)(void *data, u8 *buf, size_t buf_size,
                                      u8 **out_buf, size_t max_size);

  /**
   * Return the probability (in percentage) that afl_custom_havoc_mutation
   * is called in havoc. By default it is 6 %.
   *
   * (Optional)
   *
   * @param data pointer returned in afl_custom_init by this custom mutator
   * @return The probability (0-100).
   */
  u8 (*afl_custom_havoc_mutation_probability)(void *data);

  /**
   * Determine whether the fuzzer should fuzz the current queue entry or not.
   *
   * (Optional)
   *
   * @param data pointer returned in afl_custom_init by this custom mutator
   * @param filename File name of the test case in the queue entry
   * @return Return True(1) if the fuzzer will fuzz the queue entry, and
   *     False(0) otherwise.
   */
  u8 (*afl_custom_queue_get)(void *data, const u8 *filename);

  /**
   * This method can be used if you want to send data to the target yourself,
   * e.g. via IPC. This replaces some usage of utils/afl_proxy but requires
   * that you start the target with afl-fuzz.
   *
   * (Optional)
   *
   * @param data pointer returned in afl_custom_init by this custom mutator
   * @param buf Buffer containing the test case
   * @param buf_size Size of the test case
   */
  void (*afl_custom_fuzz_send)(void *data, const u8 *buf, size_t buf_size);

  /**
   * This method can be used if you want to run some code or scripts each time
   * AFL++ executes the target with afl-fuzz.
   *
   * (Optional)
   *
   * @param data pointer returned in afl_custom_init by this custom mutator
   */
  void (*afl_custom_post_run)(void *data);

  /**
   * Allow for additional analysis (e.g. calling a different tool that does a
   * different kind of coverage and saves this for the custom mutator).
   *
   * (Optional)
   *
   * @param data pointer returned in afl_custom_init by this custom mutator
   * @param filename_new_queue File name of the new queue entry
   * @param filename_orig_queue File name of the original queue entry. This
   *     argument can be NULL while initializing the fuzzer
   */
  u8 (*afl_custom_queue_new_entry)(void *data, const u8 *filename_new_queue,
                                   const u8 *filename_orig_queue);
  /**
   * Deinitialize the custom mutator.
   *
   * @param data pointer returned in afl_custom_init by this custom mutator
   */
  void (*afl_custom_deinit)(void *data);

};

void afl_state_init(afl_state_t *, uint32_t map_size);
void afl_state_deinit(afl_state_t *);

/* Set stop_soon flag on all childs, kill all childs */
void afl_states_stop(void);
/* Set clear_screen flag on all states */
void afl_states_clear_screen(void);
/* Sets the skip flag on all states */
void afl_states_request_skip(void);

/* Setup shmem for testcase delivery */
void setup_testcase_shmem(afl_state_t *afl);

void read_afl_environment(afl_state_t *, char **);

/**** Prototypes ****/

/* Custom mutators */
void setup_custom_mutators(afl_state_t *);
void destroy_custom_mutators(afl_state_t *);
u8   trim_case_custom(afl_state_t *, struct queue_entry *q, u8 *in_buf,
                      struct custom_mutator *mutator);
void run_afl_custom_queue_new_entry(afl_state_t *, struct queue_entry *, u8 *,
                                    u8 *);

/* Python */
#ifdef USE_PYTHON

struct custom_mutator *load_custom_mutator_py(afl_state_t *, char *);
void                   finalize_py_module(void *);

u32         fuzz_count_py(void *, const u8 *, size_t);
void        fuzz_send_py(void *, const u8 *, size_t);
void        post_run_py(void *);
size_t      post_process_py(void *, u8 *, size_t, u8 **);
s32         init_trim_py(void *, u8 *, size_t);
s32         post_trim_py(void *, u8);
size_t      trim_py(void *, u8 **);
size_t      havoc_mutation_py(void *, u8 *, size_t, u8 **, size_t);
u8          havoc_mutation_probability_py(void *);
u8          queue_get_py(void *, const u8 *);
const char *introspection_py(void *);
u8          queue_new_entry_py(void *, const u8 *, const u8 *);
void        splice_optout(void *);
void        deinit_py(void *);

#endif

/* Queue */

void mark_as_det_done(afl_state_t *, struct queue_entry *);
void mark_as_variable(afl_state_t *, struct queue_entry *);
void mark_as_redundant(afl_state_t *, struct queue_entry *, u8);
void add_to_queue(afl_state_t *, u8 *, u32, u8);
void destroy_queue(afl_state_t *);
void update_bitmap_score(afl_state_t *, struct queue_entry *);
void cull_queue(afl_state_t *);
u32  calculate_score(afl_state_t *, struct queue_entry *);

/* Bitmap */

void write_bitmap(afl_state_t *);
u32  count_bits(afl_state_t *, u8 *);
u32  count_bytes(afl_state_t *, u8 *);
u32  count_non_255_bytes(afl_state_t *, u8 *);
void simplify_trace(afl_state_t *, u8 *);
#ifdef WORD_SIZE_64
void discover_word(u8 *ret, u64 *current, u64 *virgin);
#else
void discover_word(u8 *ret, u32 *current, u32 *virgin);
#endif
void init_count_class16(void);
void minimize_bits(afl_state_t *, u8 *, u8 *);
#ifndef SIMPLE_FILES
u8 *describe_op(afl_state_t *, u8, size_t);
#endif
u8 save_if_interesting(afl_state_t *, void *, u32, u8);
u8 has_new_bits(afl_state_t *, u8 *);
u8 has_new_bits_unclassified(afl_state_t *, u8 *);
#ifndef AFL_SHOWMAP
void classify_counts(afl_forkserver_t *);
#endif

/* Extras */

void load_extras_file(afl_state_t *, u8 *, u32 *, u32 *, u32);
void load_extras(afl_state_t *, u8 *);
void dedup_extras(afl_state_t *);
void deunicode_extras(afl_state_t *);
void add_extra(afl_state_t *afl, u8 *mem, u32 len);
void maybe_add_auto(afl_state_t *, u8 *, u32);
void save_auto(afl_state_t *);
void load_auto(afl_state_t *);
void destroy_extras(afl_state_t *);

/* Stats */

void load_stats_file(afl_state_t *);
void write_setup_file(afl_state_t *, u32, char **);
void write_stats_file(afl_state_t *, u32, double, double, double);
void maybe_update_plot_file(afl_state_t *, u32, double, double);
void write_queue_stats(afl_state_t *);
void show_stats(afl_state_t *);
void show_stats_normal(afl_state_t *);
void show_stats_pizza(afl_state_t *);
void show_init_stats(afl_state_t *);

void update_calibration_time(afl_state_t *afl, u64 *time);
void update_trim_time(afl_state_t *afl, u64 *time);
void update_sync_time(afl_state_t *afl, u64 *time);

/* StatsD */

void statsd_setup_format(afl_state_t *afl);
int  statsd_socket_init(afl_state_t *afl);
int  statsd_send_metric(afl_state_t *afl);
int  statsd_format_metric(afl_state_t *afl, char *buff, size_t bufflen);

/* Run */

void sync_fuzzers(afl_state_t *);
u32  write_to_testcase(afl_state_t *, void **, u32, u32);
u8   calibrate_case(afl_state_t *, struct queue_entry *, u8 *, u32, u8);
u8   trim_case(afl_state_t *, struct queue_entry *, u8 *);
u8   common_fuzz_stuff(afl_state_t *, u8 *, u32);
fsrv_run_result_t fuzz_run_target(afl_state_t *, afl_forkserver_t *fsrv, u32);

/* Fuzz one */

u8   fuzz_one_original(afl_state_t *);
u8   pilot_fuzzing(afl_state_t *);
u8   core_fuzzing(afl_state_t *);
void pso_updating(afl_state_t *);
u8   fuzz_one(afl_state_t *);

/* Init */

#ifdef HAVE_AFFINITY
void bind_to_free_cpu(afl_state_t *);
#endif
void   setup_post(afl_state_t *);
void   read_testcases(afl_state_t *, u8 *);
void   perform_dry_run(afl_state_t *);
void   pivot_inputs(afl_state_t *);
u32    find_start_position(afl_state_t *);
void   find_timeout(afl_state_t *);
double get_runnable_processes(void);
void   nuke_resume_dir(afl_state_t *);
int    check_main_node_exists(afl_state_t *);
u32    select_next_queue_entry(afl_state_t *afl);
void   create_alias_table(afl_state_t *afl);
void   setup_dirs_fds(afl_state_t *);
void   setup_cmdline_file(afl_state_t *, char **);
void   setup_stdio_file(afl_state_t *);
void   check_crash_handling(void);
void   check_cpu_governor(afl_state_t *);
void   get_core_count(afl_state_t *);
void   fix_up_sync(afl_state_t *);
void   check_asan_opts(afl_state_t *);
void   check_binary(afl_state_t *, u8 *);
void   check_if_tty(afl_state_t *);
void   save_cmdline(afl_state_t *, u32, char **);
void   read_foreign_testcases(afl_state_t *, int);
void   write_crash_readme(afl_state_t *afl);
u8     check_if_text_buf(u8 *buf, u32 len);
#ifndef AFL_SHOWMAP
void setup_signal_handlers(void);
#endif
char *get_fuzzing_state(afl_state_t *afl);

/* CmpLog */

u8 common_fuzz_cmplog_stuff(afl_state_t *afl, u8 *out_buf, u32 len);

/* RedQueen */
u8 input_to_state_stage(afl_state_t *afl, u8 *orig_buf, u8 *buf, u32 len);

/* our RNG wrapper */
AFL_RAND_RETURN rand_next(afl_state_t *afl);

/* probability between 0.0 and 1.0 */
double rand_next_percent(afl_state_t *afl);

/* SkipDet Functions */

u8 skip_deterministic_stage(afl_state_t *, u8 *, u8 *, u32, u64);
u8 is_det_timeout(u64, u8);

void plot_profile_data(afl_state_t *, struct queue_entry *);

/**** Inline routines ****/

/* Generate a random number (from 0 to limit - 1). This may
   have slight bias. */

static inline u32 rand_below(afl_state_t *afl, u32 limit) {

  if (unlikely(limit <= 1)) return 0;

  /* The boundary not being necessarily a power of 2,
     we need to ensure the result uniformity. */
  if (unlikely(!afl->rand_cnt--) && likely(!afl->fixed_seed)) {

    ck_read(afl->fsrv.dev_urandom_fd, &afl->rand_seed, sizeof(afl->rand_seed),
            "/dev/urandom");
    // srandom(afl->rand_seed[0]);
    afl->rand_cnt = (RESEED_RNG / 2) + (afl->rand_seed[1] % RESEED_RNG);

  }

  /* Modulo is biased - we don't want our fuzzing to be biased so let's do it
   right. See:
   https://stackoverflow.com/questions/10984974/why-do-people-say-there-is-modulo-bias-when-using-a-random-number-generator
   */
  u64 unbiased_rnd;
  do {

    unbiased_rnd = rand_next(afl);

  } while (unlikely(unbiased_rnd >= (UINT64_MAX - (UINT64_MAX % limit))));

  return unbiased_rnd % limit;

}

/* we prefer lower range values here */
/* this is only called with normal havoc, not MOpt, to have an equalizer for
   expand havoc mode */
static inline u32 rand_below_datalen(afl_state_t *afl, u32 limit) {

  if (unlikely(limit <= 1)) return 0;

  switch (rand_below(afl, 3)) {

    case 2:
      return (rand_below(afl, limit) % (1 + rand_below(afl, limit - 1))) %
             (1 + rand_below(afl, limit - 1));
      break;
    case 1:
      return rand_below(afl, limit) % (1 + rand_below(afl, limit - 1));
      break;
    case 0:
      return rand_below(afl, limit);
      break;

  }

  return 1;  // cannot be reached

}

static inline s64 rand_get_seed(afl_state_t *afl) {

  if (unlikely(afl->fixed_seed)) { return afl->init_seed; }
  return afl->rand_seed[0];

}

/* initialize randomness with a given seed. Can be called again at any time. */
void rand_set_seed(afl_state_t *afl, s64 init_seed);

/* Find first power of two greater or equal to val (assuming val under
   2^63). */

static inline u64 next_p2(u64 val) {

  u64 ret = 1;
  while (val > ret) {

    ret <<= 1;

  }

  return ret;

}

/* Returns the testcase buf from the file behind this queue entry.
  Increases the refcount. */
u8 *queue_testcase_get(afl_state_t *afl, struct queue_entry *q);

/* If trimming changes the testcase size we have to reload it */
void queue_testcase_retake(afl_state_t *afl, struct queue_entry *q,
                           u32 old_len);

/* If trimming changes the testcase size we have to replace it  */
void queue_testcase_retake_mem(afl_state_t *afl, struct queue_entry *q, u8 *in,
                               u32 len, u32 old_len);

/* Add a new queue entry directly to the cache */

void queue_testcase_store_mem(afl_state_t *afl, struct queue_entry *q, u8 *mem);

/* Compute the SHA1 hash of `data`, which is of `len` bytes, and return the
 * result as a `\0`-terminated hex string, which the caller much `ck_free`. */
char *sha1_hex(const u8 *data, size_t len);

/* Apply `sha1_hex` to the first `len` bytes of data of the file at `fname`. */
char *sha1_hex_for_file(const char *fname, u32 len);

/* Create file `fn`, but allow it to already exist if `AFL_SHA1_FILENAMES` is
 * enabled. */
static inline int permissive_create(afl_state_t *afl, const char *fn) {

  int fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, DEFAULT_PERMISSION);
  if (unlikely(fd < 0)) {

    if (!(afl->afl_env.afl_sha1_filenames && errno == EEXIST)) {

      PFATAL("Unable to create '%s'", fn);

    }

  }

  return fd;

}

#if TESTCASE_CACHE == 1
  #error define of TESTCASE_CACHE must be zero or larger than 1
#endif

#endif

