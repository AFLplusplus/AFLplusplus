/*
   american fuzzy lop++ - fuzzer header
   ------------------------------------

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

#ifndef _AFL_FUZZ_H
#define _AFL_FUZZ_H

#define AFL_MAIN
#define MESSAGES_TO_STDOUT

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#define _FILE_OFFSET_BITS 64

#ifdef __ANDROID__
#include "android-ashmem.h"
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

#include <sys/wait.h>
#include <sys/time.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/file.h>

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || \
    defined(__NetBSD__) || defined(__DragonFly__)
#include <sys/sysctl.h>
#endif                           /* __APPLE__ || __FreeBSD__ || __OpenBSD__ */

/* For systems that have sched_setaffinity; right now just Linux, but one
   can hope... */

#if defined(__linux__) || defined(__FreeBSD__) || defined(__NetBSD__) || \
    defined(__DragonFly__)
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
#endif
#endif                                                         /* __linux__ */

#ifdef __APPLE__
#include <TargetConditionals.h>
#endif

#ifndef SIMPLE_FILES
#define CASE_PREFIX "id:"
#else
#define CASE_PREFIX "id_"
#endif                                                    /* ^!SIMPLE_FILES */

struct queue_entry {

  u8* fname;                            /* File name for the test case      */
  u32 len;                              /* Input length                     */

  u8 cal_failed,                        /* Calibration failed?              */
      trim_done,                        /* Trimmed?                         */
      was_fuzzed,                       /* historical, but needed for MOpt  */
      passed_det,                       /* Deterministic stages passed?     */
      has_new_cov,                      /* Triggers new coverage?           */
      var_behavior,                     /* Variable behavior?               */
      favored,                          /* Currently favored?               */
      fs_redundant,                     /* Marked as redundant in the fs?   */
      fully_colorized;                  /* Do not run redqueen stage again  */

  u32 bitmap_size,                      /* Number of bits set in bitmap     */
      fuzz_level,                       /* Number of fuzzing iterations     */
      exec_cksum;                       /* Checksum of the execution trace  */

  u64 exec_us,                          /* Execution time (us)              */
      handicap,                         /* Number of queue cycles behind    */
      n_fuzz,                          /* Number of fuzz, does not overflow */
      depth;                            /* Path depth                       */

  u8* trace_mini;                       /* Trace bytes, if kept             */
  u32 tc_ref;                           /* Trace bytes ref count            */

  struct queue_entry *next,             /* Next element, if any             */
      *next_100;                        /* 100 elements ahead               */

};

struct extra_data {

  u8* data;                             /* Dictionary token data            */
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
  /* 15 */ STAGE_HAVOC,
  /* 16 */ STAGE_SPLICE,
  /* 17 */ STAGE_PYTHON,
  /* 18 */ STAGE_RADAMSA,
  /* 19 */ STAGE_CUSTOM_MUTATOR,
  /* 20 */ STAGE_COLORIZATION,
  /* 21 */ STAGE_ITS,

};

/* Stage value types */

enum {

  /* 00 */ STAGE_VAL_NONE,
  /* 01 */ STAGE_VAL_LE,
  /* 02 */ STAGE_VAL_BE

};

/* Execution status fault codes */

enum {

  /* 00 */ FAULT_NONE,
  /* 01 */ FAULT_TMOUT,
  /* 02 */ FAULT_CRASH,
  /* 03 */ FAULT_ERROR,
  /* 04 */ FAULT_NOINST,
  /* 05 */ FAULT_NOBITS

};

/* MOpt:
   Lots of globals, but mostly for the status UI and other things where it
   really makes no sense to haul them around as function parameters. */
extern u64 limit_time_puppet, orig_hit_cnt_puppet, last_limit_time_start,
    tmp_pilot_time, total_pacemaker_time, total_puppet_find, temp_puppet_find,
    most_time_key, most_time, most_execs_key, most_execs, old_hit_count;

extern s32 SPLICE_CYCLES_puppet, limit_time_sig, key_puppet, key_module;

extern double w_init, w_end, w_now;

extern s32 g_now;
extern s32 g_max;

#define operator_num 16
#define swarm_num 5
#define period_core 500000

extern u64 tmp_core_time;
extern s32 swarm_now;

extern double x_now[swarm_num][operator_num], L_best[swarm_num][operator_num],
    eff_best[swarm_num][operator_num], G_best[operator_num],
    v_now[swarm_num][operator_num], probability_now[swarm_num][operator_num],
    swarm_fitness[swarm_num];

extern u64 stage_finds_puppet[swarm_num][operator_num], /* Patterns found per
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
    core_operator_cycles_puppet_v3[operator_num];   /* Execs per fuzz stage */

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
#define period_pilot 50000

extern double period_pilot_tmp;
extern s32    key_lv;

extern u8 *in_dir,                      /* Input directory with test cases  */
    *out_dir,                           /* Working & output directory       */
    *tmp_dir,                           /* Temporary directory for input    */
    *sync_dir,                          /* Synchronization directory        */
    *sync_id,                           /* Fuzzer ID                        */
    *power_name,                        /* Power schedule name              */
    *use_banner,                        /* Display banner                   */
    *in_bitmap,                         /* Input bitmap                     */
    *file_extension,                    /* File extension                   */
    *orig_cmdline,                      /* Original command line            */
    *doc_path,                          /* Path to documentation dir        */
    *infoexec,                         /* Command to execute on a new crash */
    *out_file;                          /* File to fuzz, if any             */

extern u32 exec_tmout;                  /* Configurable exec timeout (ms)   */
extern u32 hang_tmout;                  /* Timeout used for hang det (ms)   */

extern u64 mem_limit;                   /* Memory cap for child (MB)        */

extern u8 cal_cycles,                   /* Calibration cycles defaults      */
    cal_cycles_long,                    /* Calibration cycles defaults      */
    no_unlink,                          /* do not unlink cur_input          */
    use_stdin,                          /* use stdin for sending data       */
    debug,                              /* Debug mode                       */
    custom_only;                        /* Custom mutator only mode         */

extern u32 stats_update_freq;           /* Stats update frequency (execs)   */

enum {

  /* 00 */ EXPLORE, /* AFL default, Exploration-based constant schedule */
  /* 01 */ FAST,    /* Exponential schedule             */
  /* 02 */ COE,     /* Cut-Off Exponential schedule     */
  /* 03 */ LIN,     /* Linear schedule                  */
  /* 04 */ QUAD,    /* Quadratic schedule               */
  /* 05 */ EXPLOIT, /* AFL's exploitation-based const.  */

  POWER_SCHEDULES_NUM

};

extern char* power_names[POWER_SCHEDULES_NUM];

extern u8 schedule;                     /* Power schedule (default: EXPLORE)*/
extern u8 havoc_max_mult;

extern u8 use_radamsa;
extern size_t (*radamsa_mutate_ptr)(u8*, size_t, u8*, size_t, u32);

extern u8 skip_deterministic,           /* Skip deterministic stages?       */
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
    autoresume,                         /* Resume if out_dir exists?        */
    auto_changed,                       /* Auto-generated tokens changed?   */
    no_cpu_meter_red,                   /* Feng shui on the status screen   */
    no_arith,                           /* Skip most arithmetic ops         */
    shuffle_queue,                      /* Shuffle input queue?             */
    bitmap_changed,                     /* Time to update bitmap?           */
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

extern s32 out_fd,                      /* Persistent fd for out_file       */
#ifndef HAVE_ARC4RANDOM
    dev_urandom_fd,                     /* Persistent fd for /dev/urandom   */
#endif
    dev_null_fd,                        /* Persistent fd for /dev/null      */
    fsrv_ctl_fd,                        /* Fork server control pipe (write) */
    fsrv_st_fd;                         /* Fork server status pipe (read)   */

extern s32 forksrv_pid,                 /* PID of the fork server           */
    child_pid,                          /* PID of the fuzzed program        */
    out_dir_fd;                         /* FD of the lock file              */

extern u8* trace_bits;                  /* SHM with instrumentation bitmap  */

extern u8 virgin_bits[MAP_SIZE],        /* Regions yet untouched by fuzzing */
    virgin_tmout[MAP_SIZE],             /* Bits we haven't seen in tmouts   */
    virgin_crash[MAP_SIZE];             /* Bits we haven't seen in crashes  */

extern u8 var_bytes[MAP_SIZE];          /* Bytes that appear to be variable */

extern volatile u8 stop_soon,           /* Ctrl-C pressed?                  */
    clear_screen,                       /* Window resized?                  */
    child_timed_out;                    /* Traced process timed out?        */

extern u32 queued_paths,                /* Total number of queued testcases */
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
    havoc_div;                          /* Cycle count divisor for havoc    */

extern u64 total_crashes,               /* Total number of crashes          */
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

extern u32 subseq_tmouts;               /* Number of timeouts in a row      */

extern u8 *stage_name,                  /* Name of the current fuzz stage   */
    *stage_short,                       /* Short stage name                 */
    *syncing_party;                     /* Currently syncing with...        */

extern s32 stage_cur, stage_max;        /* Stage progression                */
extern s32 splicing_with;               /* Splicing with which test case?   */

extern u32 master_id, master_max;       /* Master instance job splitting    */

extern u32 syncing_case;                /* Syncing with case #...           */

extern s32 stage_cur_byte,              /* Byte offset of current stage op  */
    stage_cur_val;                      /* Value used for stage op          */

extern u8 stage_val_type;               /* Value type (STAGE_VAL_*)         */

extern u64 stage_finds[32],             /* Patterns found per fuzz stage    */
    stage_cycles[32];                   /* Execs per fuzz stage             */

#ifndef HAVE_ARC4RANDOM
extern u32 rand_cnt;                    /* Random number counter            */
#endif

extern u32 rand_seed[2];
extern s64 init_seed;

extern u64 total_cal_us,                /* Total calibration time (us)      */
    total_cal_cycles;                   /* Total calibration cycles         */

extern u64 total_bitmap_size,           /* Total bit count for all bitmaps  */
    total_bitmap_entries;               /* Number of bitmaps counted        */

extern s32 cpu_core_count;              /* CPU core count                   */

#ifdef HAVE_AFFINITY

extern s32 cpu_aff;                     /* Selected CPU core                */

#endif                                                     /* HAVE_AFFINITY */

extern FILE* plot_file;                 /* Gnuplot output file              */

extern struct queue_entry *queue,       /* Fuzzing queue (linked list)      */
    *queue_cur,                         /* Current offset within the queue  */
    *queue_top,                         /* Top of the list                  */
    *q_prev100;                         /* Previous 100 marker              */

extern struct queue_entry*
    top_rated[MAP_SIZE];                /* Top entries for bitmap bytes     */

extern struct extra_data* extras;       /* Extra tokens to fuzz with        */
extern u32                extras_cnt;   /* Total number of tokens read      */

extern struct extra_data* a_extras;     /* Automatically selected extras    */
extern u32                a_extras_cnt; /* Total number of tokens available */

u8* (*post_handler)(u8* buf, u32* len);

/* CmpLog */

extern u8* cmplog_binary;
extern s32 cmplog_child_pid, cmplog_forksrv_pid;

/* Custom mutators */

struct custom_mutator {
  const char* name;
  void* dh;

  /* hooks for the custom mutator function */

  /**
   * Initialize the custom mutator.
   *
   * (Optional)
   *
   * @param seed Seed used for the mutation.
   */
  void (*afl_custom_init)(unsigned int seed);

  /**
   * Perform custom mutations on a given input
   *
   * (Optional for now. Required in the future)
   *
   * @param[inout] buf Pointer to the input data to be mutated and the mutated
   *     output
   * @param[in] buf_size Size of the input/output data
   * @param[in] add_buf Buffer containing the additional test case
   * @param[in] add_buf_size Size of the additional test case
   * @param[in] max_size Maximum size of the mutated output. The mutation must not
   *     produce data larger than max_size.
   * @return Size of the mutated output.
   */
  size_t (*afl_custom_fuzz)(u8** buf, size_t buf_size, u8* add_buf,
                            size_t add_buf_size, size_t max_size);

  /**
   * A post-processing function to use right before AFL writes the test case to
   * disk in order to execute the target.
   *
   * (Optional) If this functionality is not needed, simply don't define this
   * function.
   *
   * @param[in] buf Buffer containing the test case to be executed
   * @param[in] buf_size Size of the test case
   * @param[out] out_buf Pointer to the buffer of storing the test case after
   *     processing. External library should allocate memory for out_buf. AFL++
   *     will release the memory after saving the test case.
   * @return Size of the output buffer after processing
   */
  size_t (*afl_custom_pre_save)(u8* buf, size_t buf_size, u8** out_buf);

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
   * @param buf Buffer containing the test case
   * @param buf_size Size of the test case
   * @return The amount of possible iteration steps to trim the input
   */
  u32 (*afl_custom_init_trim)(u8* buf, size_t buf_size);

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
   * @param[out] out_buf Pointer to the buffer containing the trimmed test case.
   *     External library should allocate memory for out_buf. AFL++ will release
   *     the memory after saving the test case.
   * @param[out] out_buf_size Pointer to the size of the trimmed test case
   */
  void (*afl_custom_trim)(u8** out_buf, size_t* out_buf_size);

  /**
   * This method is called after each trim operation to inform you if your
   * trimming step was successful or not (in terms of coverage). If you receive
   * a failure here, you should reset your input to the last known good state.
   *
   * (Optional)
   *
   * @param success Indicates if the last trim operation was successful.
   * @return The next trim iteration index (from 0 to the maximum amount of
   *     steps returned in init_trim)
   */
  u32 (*afl_custom_post_trim)(u8 success);
  
  /**
   * Perform a single custom mutation on a given input.
   * This mutation is stacked with the other muatations in havoc.
   *
   * (Optional)
   *
   * @param[inout] buf Pointer to the input data to be mutated and the mutated
   *     output
   * @param[in] buf_size Size of input data
   * @param[in] max_size Maximum size of the mutated output. The mutation must
   *     not produce data larger than max_size.
   * @return Size of the mutated output.
   */
  size_t (*afl_custom_havoc_mutation)(u8** buf, size_t buf_size, size_t max_size);
  
  /**
   * Return the probability (in percentage) that afl_custom_havoc_mutation
   * is called in havoc. By default it is 6 %.
   *
   * (Optional)
   *
   * @return The probability (0-100).
   */
  u8 (*afl_custom_havoc_mutation_probability)(void);

  /**
   * Determine whether the fuzzer should fuzz the current queue entry or not.
   *
   * (Optional)
   *
   * @param filename File name of the test case in the queue entry
   * @return Return True(1) if the fuzzer will fuzz the queue entry, and
   *     False(0) otherwise.
   */
  u8 (*afl_custom_queue_get)(const u8* filename);

  /**
   * Allow for additional analysis (e.g. calling a different tool that does a 
   * different kind of coverage and saves this for the custom mutator).
   *
   * (Optional)
   *
   * @param filename_new_queue File name of the new queue entry
   * @param filename_orig_queue File name of the original queue entry. This
   *     argument can be NULL while initializing the fuzzer
   */
  void (*afl_custom_queue_new_entry)(const u8* filename_new_queue,
                                     const u8* filename_orig_queue);
};

extern struct custom_mutator* mutator;

/* Interesting values, as per config.h */

extern s8  interesting_8[INTERESTING_8_LEN];
extern s16 interesting_16[INTERESTING_8_LEN + INTERESTING_16_LEN];
extern s32
    interesting_32[INTERESTING_8_LEN + INTERESTING_16_LEN + INTERESTING_32_LEN];

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

extern PyObject* py_module;

enum {

  /* 00 */ PY_FUNC_INIT,
  /* 01 */ PY_FUNC_FUZZ,
  /* 02 */ PY_FUNC_PRE_SAVE,
  /* 03 */ PY_FUNC_INIT_TRIM,
  /* 04 */ PY_FUNC_POST_TRIM,
  /* 05 */ PY_FUNC_TRIM,
  /* 06 */ PY_FUNC_HAVOC_MUTATION,
  /* 07 */ PY_FUNC_HAVOC_MUTATION_PROBABILITY,
  /* 08 */ PY_FUNC_QUEUE_GET,
  /* 09 */ PY_FUNC_QUEUE_NEW_ENTRY,
  PY_FUNC_COUNT

};

extern PyObject* py_functions[PY_FUNC_COUNT];

#endif

/**** Prototypes ****/

/* Custom mutators */
void setup_custom_mutator(void);
void destroy_custom_mutator(void);
u8   trim_case_custom(char** argv, struct queue_entry* q, u8* in_buf);

/* Python */
#ifdef USE_PYTHON

int    init_py_module(u8*);
void   finalize_py_module();

void   init_py(unsigned int);
size_t fuzz_py(u8**, size_t, u8*, size_t, size_t);
size_t pre_save_py(u8*, size_t, u8**);
u32    init_trim_py(u8*, size_t);
u32    post_trim_py(u8);
void   trim_py(u8**, size_t*);
size_t havoc_mutation_py(u8**, size_t, size_t);
u8     havoc_mutation_probability_py(void);
u8     queue_get_py(const u8*);
void   queue_new_entry_py(const u8*, const u8*);

#endif

/* Queue */

void mark_as_det_done(struct queue_entry*);
void mark_as_variable(struct queue_entry*);
void mark_as_redundant(struct queue_entry*, u8);
void add_to_queue(u8*, u32, u8);
void destroy_queue(void);
void update_bitmap_score(struct queue_entry*);
void cull_queue(void);
u32  calculate_score(struct queue_entry*);

/* Bitmap */

void write_bitmap(void);
void read_bitmap(u8*);
u8   has_new_bits(u8*);
u32  count_bits(u8*);
u32  count_bytes(u8*);
u32  count_non_255_bytes(u8*);
#ifdef WORD_SIZE_64
void simplify_trace(u64*);
void classify_counts(u64*);
#else
void simplify_trace(u32*);
void classify_counts(u32*);
#endif
void init_count_class16(void);
void minimize_bits(u8*, u8*);
#ifndef SIMPLE_FILES
u8* describe_op(u8);
#endif
u8 save_if_interesting(char**, void*, u32, u8);

/* Misc */

u8* DI(u64);
u8* DF(double);
u8* DMS(u64);
u8* DTD(u64, u64);

/* Extras */

void load_extras_file(u8*, u32*, u32*, u32);
void load_extras(u8*);
void maybe_add_auto(u8*, u32);
void save_auto(void);
void load_auto(void);
void destroy_extras(void);

/* Stats */

void write_stats_file(double, double, double);
void maybe_update_plot_file(double, double);
void show_stats(void);
void show_init_stats(void);

/* Run */

u8   run_target(char**, u32);
void write_to_testcase(void*, u32);
void write_with_gap(void*, u32, u32, u32);
u8   calibrate_case(char**, struct queue_entry*, u8*, u32, u8);
void sync_fuzzers(char**);
u8   trim_case(char**, struct queue_entry*, u8*);
u8   common_fuzz_stuff(char**, u8*, u32);

/* Fuzz one */

u8   fuzz_one_original(char**);
u8   pilot_fuzzing(char**);
u8   core_fuzzing(char**);
void pso_updating(void);
u8   fuzz_one(char**);

/* Init */

#ifdef HAVE_AFFINITY
void bind_to_free_cpu(void);
#endif
void   setup_post(void);
void   read_testcases(void);
void   perform_dry_run(char**);
void   pivot_inputs(void);
u32    find_start_position(void);
void   find_timeout(void);
double get_runnable_processes(void);
void   nuke_resume_dir(void);
void   setup_dirs_fds(void);
void   setup_cmdline_file(char**);
void   setup_stdio_file(void);
void   check_crash_handling(void);
void   check_cpu_governor(void);
void   get_core_count(void);
void   fix_up_sync(void);
void   check_asan_opts(void);
void   check_binary(u8*);
void   fix_up_banner(u8*);
void   check_if_tty(void);
void   setup_signal_handlers(void);
char** get_qemu_argv(u8*, char**, int);
char** get_wine_argv(u8*, char**, int);
void   save_cmdline(u32, char**);

/* CmpLog */

void init_cmplog_forkserver(char** argv);
u8   common_fuzz_cmplog_stuff(char** argv, u8* out_buf, u32 len);

/* RedQueen */

u8 input_to_state_stage(char** argv, u8* orig_buf, u8* buf, u32 len,
                        u32 exec_cksum);

/**** Inline routines ****/

/* Generate a random number (from 0 to limit - 1). This may
   have slight bias. */

static inline u32 UR(u32 limit) {

#ifdef HAVE_ARC4RANDOM
  if (fixed_seed) { return random() % limit; }

  /* The boundary not being necessarily a power of 2,
     we need to ensure the result uniformity. */
  return arc4random_uniform(limit);
#else
  if (!fixed_seed && unlikely(!rand_cnt--)) {

    ck_read(dev_urandom_fd, &rand_seed, sizeof(rand_seed), "/dev/urandom");
    srandom(rand_seed[0]);
    rand_cnt = (RESEED_RNG / 2) + (rand_seed[1] % RESEED_RNG);

  }

  return random() % limit;
#endif

}

static inline u32 get_rand_seed() {

  if (fixed_seed) return (u32)init_seed;
  return rand_seed[0];

}

/* Find first power of two greater or equal to val (assuming val under
   2^63). */

static u64 next_p2(u64 val) {

  u64 ret = 1;
  while (val > ret)
    ret <<= 1;
  return ret;

}

/* Get unix time in milliseconds */

static u64 get_cur_time(void) {

  struct timeval  tv;
  struct timezone tz;

  gettimeofday(&tv, &tz);

  return (tv.tv_sec * 1000ULL) + (tv.tv_usec / 1000);

}

/* Get unix time in microseconds */

static u64 get_cur_time_us(void) {

  struct timeval  tv;
  struct timezone tz;

  gettimeofday(&tv, &tz);

  return (tv.tv_sec * 1000000ULL) + tv.tv_usec;

}

#ifdef _AFL_DOCUMENT_MUTATIONS
extern u8  do_document;
extern u32 document_counter;
#endif

#endif

