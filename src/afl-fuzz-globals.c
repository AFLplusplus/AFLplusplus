/*
   american fuzzy lop++ - globals declarations
   -------------------------------------------

   Originally written by Michal Zalewski

   Now maintained by by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eißfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This is the real deal: the program takes an instrumented binary and
   attempts a variety of basic fuzzing tricks, paying close attention to
   how they affect the execution path.

 */

#include "afl-fuzz.h"

/* MOpt:
   Lots of globals, but mostly for the status UI and other things where it
   really makes no sense to haul them around as function parameters. */
u64 limit_time_puppet, orig_hit_cnt_puppet, last_limit_time_start,
    tmp_pilot_time, total_pacemaker_time, total_puppet_find, temp_puppet_find,
    most_time_key, most_time, most_execs_key, most_execs, old_hit_count;

s32 SPLICE_CYCLES_puppet, limit_time_sig, key_puppet, key_module;

double w_init = 0.9, w_end = 0.3, w_now;

s32 g_now;
s32 g_max = 5000;

u64 tmp_core_time;
s32 swarm_now;

double x_now[swarm_num][operator_num], L_best[swarm_num][operator_num],
    eff_best[swarm_num][operator_num], G_best[operator_num],
    v_now[swarm_num][operator_num], probability_now[swarm_num][operator_num],
    swarm_fitness[swarm_num];

u64 stage_finds_puppet[swarm_num]
                      [operator_num],   /* Patterns found per fuzz stage    */
    stage_finds_puppet_v2[swarm_num][operator_num],
    stage_cycles_puppet_v2[swarm_num][operator_num],
    stage_cycles_puppet_v3[swarm_num][operator_num],
    stage_cycles_puppet[swarm_num][operator_num],
    operator_finds_puppet[operator_num],
    core_operator_finds_puppet[operator_num],
    core_operator_finds_puppet_v2[operator_num],
    core_operator_cycles_puppet[operator_num],
    core_operator_cycles_puppet_v2[operator_num],
    core_operator_cycles_puppet_v3[operator_num];   /* Execs per fuzz stage */

double period_pilot_tmp = 5000.0;
s32    key_lv;

u8 *in_dir,                             /* Input directory with test cases  */
    *out_dir,                           /* Working & output directory       */
    *tmp_dir,                           /* Temporary directory for input    */
    *sync_dir,                          /* Synchronization directory        */
    *sync_id,                           /* Fuzzer ID                        */
    *power_name,                        /* Power schedule name              */
    *use_banner,                        /* Display banner                   */
    *in_bitmap,                         /* Input bitmap                     */
    *file_extension,                    /* File extension                   */
    *orig_cmdline;                      /* Original command line            */
u8 *doc_path,                           /* Path to documentation dir        */
    *infoexec,                         /* Command to execute on a new crash */
    *out_file;                          /* File to fuzz, if any             */

u32 exec_tmout = EXEC_TIMEOUT;          /* Configurable exec timeout (ms)   */
u32 hang_tmout = EXEC_TIMEOUT;          /* Timeout used for hang det (ms)   */

u64 mem_limit = MEM_LIMIT;              /* Memory cap for child (MB)        */

u8 cal_cycles = CAL_CYCLES,             /* Calibration cycles defaults      */
    cal_cycles_long = CAL_CYCLES_LONG, debug,                 /* Debug mode */
    custom_only,                        /* Custom mutator only mode         */
    python_only;                        /* Python-only mode                 */

u32 stats_update_freq = 1;              /* Stats update frequency (execs)   */

char *power_names[POWER_SCHEDULES_NUM] = {"explore", "fast", "coe",
                                          "lin",     "quad", "exploit"};

u8 schedule = EXPLORE;                  /* Power schedule (default: EXPLORE)*/
u8 havoc_max_mult = HAVOC_MAX_MULT;

u8 use_radamsa;
size_t (*radamsa_mutate_ptr)(u8*, size_t, u8*, size_t, u32);

u8 skip_deterministic,                  /* Skip deterministic stages?       */
    force_deterministic,                /* Force deterministic stages?      */
    use_splicing,                       /* Recombine input files?           */
    dumb_mode,                          /* Run in non-instrumented mode?    */
    score_changed,                      /* Scoring for favorites changed?   */
    kill_signal,                        /* Signal that killed the child     */
    resuming_fuzz,                      /* Resuming an older fuzzing job?   */
    timeout_given,                      /* Specific timeout given?          */
    not_on_tty,                         /* stdout is not a tty              */
    term_too_small,                     /* terminal dimensions too small    */
    no_forkserver,                      /* Disable forkserver?              */
    crash_mode,                         /* Crash mode! Yeah!                */
    in_place_resume,                    /* Attempt in-place resume?         */
    auto_changed,                       /* Auto-generated tokens changed?   */
    no_cpu_meter_red,                   /* Feng shui on the status screen   */
    no_arith,                           /* Skip most arithmetic ops         */
    shuffle_queue,                      /* Shuffle input queue?             */
    bitmap_changed = 1,                 /* Time to update bitmap?           */
    qemu_mode,                          /* Running in QEMU mode?            */
    unicorn_mode,                       /* Running in Unicorn mode?         */
    use_wine,                           /* Use WINE with QEMU mode          */
    skip_requested,                     /* Skip request, via SIGUSR1        */
    run_over10m,                        /* Run time over 10 minutes?        */
    persistent_mode,                    /* Running in persistent mode?      */
    deferred_mode,                      /* Deferred forkserver mode?        */
    fixed_seed,                         /* do not reseed                    */
    fast_cal,                           /* Try to calibrate faster?         */
    uses_asan,                          /* Target uses ASAN?                */
    disable_trim;                       /* Never trim in fuzz_one           */

s32 out_fd,                             /* Persistent fd for out_file       */
#ifndef HAVE_ARC4RANDOM
    dev_urandom_fd = -1,                /* Persistent fd for /dev/urandom   */
#endif
    dev_null_fd = -1,                   /* Persistent fd for /dev/null      */
    fsrv_ctl_fd,                        /* Fork server control pipe (write) */
    fsrv_st_fd;                         /* Fork server status pipe (read)   */

s32 forksrv_pid,                        /* PID of the fork server           */
    child_pid = -1,                     /* PID of the fuzzed program        */
    out_dir_fd = -1;                    /* FD of the lock file              */

u8 *trace_bits;                         /* SHM with instrumentation bitmap  */

u8 virgin_bits[MAP_SIZE],               /* Regions yet untouched by fuzzing */
    virgin_tmout[MAP_SIZE],             /* Bits we haven't seen in tmouts   */
    virgin_crash[MAP_SIZE];             /* Bits we haven't seen in crashes  */

u8 var_bytes[MAP_SIZE];                 /* Bytes that appear to be variable */

volatile u8 stop_soon,                  /* Ctrl-C pressed?                  */
    clear_screen = 1,                   /* Window resized?                  */
    child_timed_out;                    /* Traced process timed out?        */

u32 queued_paths,                       /* Total number of queued testcases */
    queued_variable,                    /* Testcases with variable behavior */
    queued_at_start,                    /* Total number of initial inputs   */
    queued_discovered,                  /* Items discovered during this run */
    queued_imported,                    /* Items imported via -S            */
    queued_favored,                     /* Paths deemed favorable           */
    queued_with_cov,                    /* Paths with new coverage bytes    */
    pending_not_fuzzed,                 /* Queued but not done yet          */
    pending_favored,                    /* Pending favored paths            */
    cur_skipped_paths,                  /* Abandoned inputs in cur cycle    */
    cur_depth,                          /* Current path depth               */
    max_depth,                          /* Max path depth                   */
    useless_at_start,                   /* Number of useless starting paths */
    var_byte_count,                     /* Bitmap bytes with var behavior   */
    current_entry,                      /* Current queue entry ID           */
    havoc_div = 1;                      /* Cycle count divisor for havoc    */

u64 total_crashes,                      /* Total number of crashes          */
    unique_crashes,                     /* Crashes with unique signatures   */
    total_tmouts,                       /* Total number of timeouts         */
    unique_tmouts,                      /* Timeouts with unique signatures  */
    unique_hangs,                       /* Hangs with unique signatures     */
    total_execs,                        /* Total execve() calls             */
    slowest_exec_ms,                    /* Slowest testcase non hang in ms  */
    start_time,                         /* Unix start time (ms)             */
    last_path_time,                     /* Time for most recent path (ms)   */
    last_crash_time,                    /* Time for most recent crash (ms)  */
    last_hang_time,                     /* Time for most recent hang (ms)   */
    last_crash_execs,                   /* Exec counter at last crash       */
    queue_cycle,                        /* Queue round counter              */
    cycles_wo_finds,                    /* Cycles without any new paths     */
    trim_execs,                         /* Execs done to trim input files   */
    bytes_trim_in,                      /* Bytes coming into the trimmer    */
    bytes_trim_out,                     /* Bytes coming outa the trimmer    */
    blocks_eff_total,                   /* Blocks subject to effector maps  */
    blocks_eff_select;                  /* Blocks selected as fuzzable      */

u32 subseq_tmouts;                      /* Number of timeouts in a row      */

u8 *stage_name = "init",                /* Name of the current fuzz stage   */
    *stage_short,                       /* Short stage name                 */
    *syncing_party;                     /* Currently syncing with...        */

s32 stage_cur, stage_max;               /* Stage progression                */
s32 splicing_with = -1;                 /* Splicing with which test case?   */

u32 master_id, master_max;              /* Master instance job splitting    */

u32 syncing_case;                       /* Syncing with case #...           */

s32 stage_cur_byte,                     /* Byte offset of current stage op  */
    stage_cur_val;                      /* Value used for stage op          */

u8 stage_val_type;                      /* Value type (STAGE_VAL_*)         */

u64 stage_finds[32],                    /* Patterns found per fuzz stage    */
    stage_cycles[32];                   /* Execs per fuzz stage             */

#ifndef HAVE_ARC4RANDOM
u32 rand_cnt;                           /* Random number counter            */
#endif

u32 rand_seed[2];
s64    init_seed;

u64 total_cal_us,                       /* Total calibration time (us)      */
    total_cal_cycles;                   /* Total calibration cycles         */

u64 total_bitmap_size,                  /* Total bit count for all bitmaps  */
    total_bitmap_entries;               /* Number of bitmaps counted        */

s32 cpu_core_count;                     /* CPU core count                   */

#ifdef HAVE_AFFINITY

s32 cpu_aff = -1;                       /* Selected CPU core                */

#endif                                                     /* HAVE_AFFINITY */

FILE *plot_file;                        /* Gnuplot output file              */

struct queue_entry *queue,              /* Fuzzing queue (linked list)      */
    *queue_cur,                         /* Current offset within the queue  */
    *queue_top,                         /* Top of the list                  */
    *q_prev100;                         /* Previous 100 marker              */

struct queue_entry *top_rated[MAP_SIZE]; /* Top entries for bitmap bytes     */

struct extra_data *extras;              /* Extra tokens to fuzz with        */
u32                extras_cnt;          /* Total number of tokens read      */

struct extra_data *a_extras;            /* Automatically selected extras    */
u32                a_extras_cnt;        /* Total number of tokens available */

u8 *(*post_handler)(u8 *buf, u32 *len);

/* hooks for the custom mutator function */
size_t (*custom_mutator)(u8 *data, size_t size, u8 *mutated_out,
                         size_t max_size, unsigned int seed);
size_t (*pre_save_handler)(u8 *data, size_t size, u8 **new_data);

/* Interesting values, as per config.h */

s8  interesting_8[] = {INTERESTING_8};
s16 interesting_16[] = {INTERESTING_8, INTERESTING_16};
s32 interesting_32[] = {INTERESTING_8, INTERESTING_16, INTERESTING_32};

/* Python stuff */
#ifdef USE_PYTHON

PyObject *py_module;
PyObject *py_functions[PY_FUNC_COUNT];

#endif

#ifdef _AFL_DOCUMENT_MUTATIONS
u8  do_document;
u32 document_counter;
#endif

