/*
   american fuzzy lop++ - fuzzer code
   --------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                     Dominik Meier <mail@dmnk.co>,
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

#include "afl-fuzz.h"
#include "cmplog.h"
#include "common.h"
#include <limits.h>
#include <stdlib.h>
#ifndef USEMMAP
  #include <sys/mman.h>
  #include <sys/stat.h>
  #include <fcntl.h>
  #include <sys/ipc.h>
  #include <sys/shm.h>
#endif
#ifdef HAVE_ZLIB

  #define ck_gzread(fd, buf, len, fn)                            \
    do {                                                         \
                                                                 \
      s32 _len = (s32)(len);                                     \
      s32 _res = gzread(fd, buf, _len);                          \
      if (_res != _len) RPFATAL(_res, "Short read from %s", fn); \
                                                                 \
    } while (0)

  #define ck_gzwrite(fd, buf, len, fn)                                    \
    do {                                                                  \
                                                                          \
      if (len <= 0) break;                                                \
      s32 _written = 0, _off = 0, _len = (s32)(len);                      \
                                                                          \
      do {                                                                \
                                                                          \
        s32 _res = gzwrite(fd, (buf) + _off, _len);                       \
        if (_res != _len && (_res > 0 && _written + _res != _len)) {      \
                                                                          \
          if (_res > 0) {                                                 \
                                                                          \
            _written += _res;                                             \
            _len -= _res;                                                 \
            _off += _res;                                                 \
                                                                          \
          } else {                                                        \
                                                                          \
            RPFATAL(_res, "Short write to %s (%d of %d bytes)", fn, _res, \
                    _len);                                                \
                                                                          \
          }                                                               \
                                                                          \
        } else {                                                          \
                                                                          \
          break;                                                          \
                                                                          \
        }                                                                 \
                                                                          \
      } while (1);                                                        \
                                                                          \
                                                                          \
                                                                          \
    } while (0)

  #include <zlib.h>
  #define ZLIBOPEN gzopen
  #define ZLIBREAD ck_gzread
  #define NZLIBREAD gzread
  #define ZLIBWRITE ck_gzwrite
  #define ZLIBCLOSE gzclose
  #define ZLIB_EXTRA "9"
#else
  #define ZLIBOPEN open
  #define NZLIBREAD read
  #define ZLIBREAD ck_read
  #define ZLIBWRITE ck_write
  #define ZLIBCLOSE close
#endif

#ifdef __APPLE__
  #include <sys/qos.h>
  #include <pthread/qos.h>
#endif

#ifdef PROFILING
extern u64 time_spent_working;
#endif

static void at_exit() {

  s32   i, pid1 = 0, pid2 = 0, pgrp = -1;
  char *list[4] = {SHM_ENV_VAR, SHM_FUZZ_ENV_VAR, CMPLOG_SHM_ENV_VAR, NULL};
  char *ptr;

  ptr = getenv("__AFL_TARGET_PID2");
  if (ptr && *ptr && (pid2 = atoi(ptr)) > 0) {

    pgrp = getpgid(pid2);
    if (pgrp > 0) { killpg(pgrp, SIGTERM); }
    kill(pid2, SIGTERM);

  }

  ptr = getenv("__AFL_TARGET_PID1");
  if (ptr && *ptr && (pid1 = atoi(ptr)) > 0) {

    pgrp = getpgid(pid1);
    if (pgrp > 0) { killpg(pgrp, SIGTERM); }
    kill(pid1, SIGTERM);

  }

  ptr = getenv(CPU_AFFINITY_ENV_VAR);
  if (ptr && *ptr) unlink(ptr);

  i = 0;
  while (list[i] != NULL) {

    ptr = getenv(list[i]);
    if (ptr && *ptr) {

#ifdef USEMMAP

      shm_unlink(ptr);

#else

      shmctl(atoi(ptr), IPC_RMID, NULL);

#endif

    }

    i++;

  }

  int kill_signal = SIGKILL;
  /* AFL_KILL_SIGNAL should already be a valid int at this point */
  if ((ptr = getenv("AFL_KILL_SIGNAL"))) { kill_signal = atoi(ptr); }

  if (pid1 > 0) {

    pgrp = getpgid(pid1);
    if (pgrp > 0) { killpg(pgrp, kill_signal); }
    kill(pid1, kill_signal);

  }

  if (pid2 > 0) {

    pgrp = getpgid(pid1);
    if (pgrp > 0) { killpg(pgrp, kill_signal); }
    kill(pid2, kill_signal);

  }

}

/* Display usage hints. */

static void usage(u8 *argv0, int more_help) {

  SAYF(
      "\n%s [ options ] -- /path/to/fuzzed_app [ ... ]\n\n"

      "Required parameters:\n"
      "  -i dir        - input directory with test cases (or '-' to resume, "
      "also see \n"
      "                  AFL_AUTORESUME)\n"
      "  -o dir        - output directory for fuzzer findings\n\n"

      "Execution control settings:\n"
      "  -P strategy   - set fix mutation strategy: explore (focus on new "
      "coverage),\n"
      "                  exploit (focus on triggering crashes). You can also "
      "set a\n"
      "                  number of seconds after without any finds it switches "
      "to\n"
      "                  exploit mode, and back on new coverage (default: %u)\n"
      "  -p schedule   - power schedules compute a seed's performance score:\n"
      "                  explore(default), fast, exploit, seek, rare, mmopt, "
      "coe, lin\n"
      "                  quad -- see docs/FAQ.md for more information\n"
      "  -f file       - location read by the fuzzed program (default: stdin "
      "or @@)\n"
      "  -t msec       - timeout for each run (auto-scaled, default %u ms). "
      "Add a '+'\n"
      "                  to auto-calculate the timeout, the value being the "
      "maximum.\n"
      "  -m megs       - memory limit for child process (%u MB, 0 = no limit "
      "[default])\n"
#if defined(__linux__) && defined(__aarch64__)
      "  -A            - use binary-only instrumentation (ARM CoreSight mode)\n"
#endif
      "  -O            - use binary-only instrumentation (FRIDA mode)\n"
#if defined(__linux__)
      "  -Q            - use binary-only instrumentation (QEMU mode)\n"
      "  -U            - use unicorn-based instrumentation (Unicorn mode)\n"
      "  -W            - use qemu-based instrumentation with Wine (Wine mode)\n"
#endif
#if defined(__linux__)
      "  -X            - use VM fuzzing (NYX mode - standalone mode)\n"
      "  -Y            - use VM fuzzing (NYX mode - multiple instances mode)\n"
#endif
      "\n"

      "Mutator settings:\n"
      "  -a type       - target input format, \"text\" or \"binary\" (default: "
      "generic)\n"
      "  -g minlength  - set min length of generated fuzz input (default: 1)\n"
      "  -G maxlength  - set max length of generated fuzz input (default: "
      "%lu)\n"
      "  -L minutes    - use MOpt(imize) mode and set the time limit for "
      "entering the\n"
      "                  pacemaker mode (minutes of no new finds). 0 = "
      "immediately,\n"
      "                  -1 = immediately and together with normal mutation.\n"
      "                  Note: this option is usually not very effective\n"
      "  -c program    - enable CmpLog by specifying a binary compiled for "
      "it.\n"
      "                  if using QEMU/FRIDA or the fuzzing target is "
      "compiled\n"
      "                  for CmpLog then use '-c 0'. To disable CMPLOG use '-c "
      "-'.\n"
      "  -l cmplog_opts - CmpLog configuration values (e.g. \"2ATR\"):\n"
      "                  1=small files, 2=larger files (default), 3=all "
      "files,\n"
      "                  A=arithmetic solving, T=transformational solving,\n"
      "                  X=extreme transform solving, R=random colorization "
      "bytes.\n\n"
      "Fuzzing behavior settings:\n"
      "  -Z            - sequential queue selection instead of weighted "
      "random\n"
      "  -N            - do not unlink the fuzzing input file (for devices "
      "etc.)\n"
      "  -n            - fuzz without instrumentation (non-instrumented mode)\n"
      "  -x dict_file  - fuzzer dictionary (see README.md, specify up to 4 "
      "times)\n\n"

      "Test settings:\n"
      "  -s seed       - use a fixed seed for the RNG\n"
      "  -V seconds    - fuzz for a specified time then terminate (fuzz time "
      "only!)\n"
      "  -E execs      - fuzz for an approx. no. of total executions then "
      "terminate\n"
      "                  Note: not precise and can have several more "
      "executions.\n\n"

      "Other stuff:\n"
      "  -M/-S id      - distributed mode (-M sets -Z and disables trimming)\n"
      "                  see docs/fuzzing_in_depth.md#c-using-multiple-cores\n"
      "                  for effective recommendations for parallel fuzzing.\n"
      "  -F path       - sync to a foreign fuzzer queue directory (requires "
      "-M, can\n"
      "                  be specified up to %u times)\n"
      "  -z            - skip the enhanced deterministic fuzzing\n"
      "                  (note that the old -d and -D flags are ignored.)\n"
      "  -T text       - text banner to show on the screen\n"
      "  -I command    - execute this command/script when a new crash is "
      "found\n"
      //"  -B bitmap.txt - mutate a specific test case, use the
      // out/default/fuzz_bitmap file\n"
      "  -C            - crash exploration mode (the peruvian rabbit thing)\n"
      "  -b cpu_id     - bind the fuzzing process to the specified CPU core "
      "(0-...)\n"
      "  -e ext        - file extension for the fuzz test input file (if "
      "needed)\n"
      "\n",
      argv0, STRATEGY_SWITCH_TIME, EXEC_TIMEOUT, MEM_LIMIT, MAX_FILE,
      FOREIGN_SYNCS_MAX);

  if (more_help > 1) {

#if defined USE_COLOR && !defined ALWAYS_COLORED
  #define DYN_COLOR \
    "AFL_NO_COLOR or AFL_NO_COLOUR: switch colored console output off\n"
#else
  #define DYN_COLOR
#endif

#ifdef AFL_PERSISTENT_RECORD
  #define PERSISTENT_MSG                                                 \
    "AFL_PERSISTENT_RECORD: record the last X inputs to every crash in " \
    "out/crashes\n"
#else
  #define PERSISTENT_MSG
#endif

    SAYF(
      "Environment variables used:\n"
      "LD_BIND_LAZY: do not set LD_BIND_NOW env var for target\n"
      "ASAN_OPTIONS: custom settings for ASAN\n"
      "              (must contain abort_on_error=1 and symbolize=0)\n"
      "MSAN_OPTIONS: custom settings for MSAN\n"
      "              (must contain exitcode="STRINGIFY(MSAN_ERROR)" and symbolize=0)\n"
      "AFL_AUTORESUME: resume fuzzing if directory specified by -o already exists\n"
      "AFL_BENCH_JUST_ONE: run the target just once\n"
      "AFL_BENCH_UNTIL_CRASH: exit soon when the first crashing input has been found\n"
      "AFL_CMPLOG_ONLY_NEW: do not run cmplog on initial testcases (good for resumes!)\n"
      "AFL_CRASH_EXITCODE: optional child exit code to be interpreted as crash\n"
      "AFL_CUSTOM_MUTATOR_LIBRARY: lib with afl_custom_fuzz() to mutate inputs\n"
      "AFL_CUSTOM_MUTATOR_ONLY: avoid AFL++'s internal mutators\n"
      "AFL_CYCLE_SCHEDULES: after completing a cycle, switch to a different -p schedule\n"
      "AFL_DEBUG: extra debugging output for Python mode trimming\n"
      "AFL_DEBUG_CHILD: do not suppress stdout/stderr from target\n"
      "AFL_DISABLE_REDUNDANT: disable any queue item that is redundant\n"
      "AFL_DISABLE_TRIM: disable the trimming of test cases\n"
      "AFL_DUMB_FORKSRV: use fork server without feedback from target\n"
      "AFL_EXIT_WHEN_DONE: exit when all inputs are run and no new finds are found\n"
      "AFL_EXIT_ON_TIME: exit when no new coverage is found within the specified time\n"
      "AFL_EXIT_ON_SEED_ISSUES: exit on any kind of seed issues\n"
      "AFL_EXPAND_HAVOC_NOW: immediately enable expand havoc mode (default: after 60\n"
      "                      minutes and a cycle without finds)\n"
      "AFL_FAST_CAL: limit the calibration stage to three cycles for speedup\n"
      "AFL_FORCE_UI: force showing the status screen (for virtual consoles)\n"
      "AFL_FORKSRV_INIT_TMOUT: time spent waiting for forkserver during startup (in ms)\n"
      "AFL_HANG_TMOUT: override timeout value (in milliseconds)\n"
      "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES: don't warn about core dump handlers\n"
      "AFL_IGNORE_PROBLEMS: do not abort fuzzing if an incorrect setup is detected\n"
      "AFL_IGNORE_PROBLEMS_COVERAGE: if set in addition to AFL_IGNORE_PROBLEMS - also\n"
      "                              ignore those libs for coverage\n"
      "AFL_IGNORE_SEED_PROBLEMS: skip over crashes and timeouts in the seeds instead of\n"
      "                          exiting\n"
      "AFL_IGNORE_TIMEOUTS: do not process or save any timeouts\n"
      "AFL_IGNORE_UNKNOWN_ENVS: don't warn on unknown env vars\n"
      "AFL_IMPORT_FIRST: sync and import test cases from other fuzzer instances first\n"
      "AFL_INPUT_LEN_MIN/AFL_INPUT_LEN_MAX: like -g/-G set min/max fuzz length produced\n"
      "AFL_PIZZA_MODE: 1 - enforce pizza mode, -1 - disable for April 1st,\n"
      "                0 (default) - activate on April 1st\n"
      "AFL_KILL_SIGNAL: Signal ID delivered to child processes on timeout, etc.\n"
      "                 (default: SIGKILL)\n"
      "AFL_FORK_SERVER_KILL_SIGNAL: Kill signal for the fork server on termination\n"
      "                             (default: SIGTERM). If unset and AFL_KILL_SIGNAL is\n"
      "                             set, that value will be used.\n"
      "AFL_MAP_SIZE: the shared memory size for that target. must be >= the size\n"
      "              the target was compiled for\n"
      "AFL_MAX_DET_EXTRAS: if more entries are in the dictionary list than this value\n"
      "                    then they are randomly selected instead all of them being\n"
      "                    used. Defaults to 200.\n"
      "AFL_NO_AFFINITY: do not check for an unused cpu core to use for fuzzing\n"
      "AFL_TRY_AFFINITY: try to bind to an unused core, but don't fail if unsuccessful\n"
      "AFL_NO_ARITH: skip arithmetic mutations in deterministic stage\n"
      "AFL_NO_AUTODICT: do not load an offered auto dictionary compiled into a target\n"
      "AFL_NO_CPU_RED: avoid red color for showing very high cpu usage\n"
      "AFL_NO_FORKSRV: run target via execve instead of using the forkserver\n"
      "AFL_NO_SNAPSHOT: do not use the snapshot feature (if the snapshot lkm is loaded)\n"
      "AFL_NO_STARTUP_CALIBRATION: no initial seed calibration, start fuzzing at once\n"
      "AFL_NO_WARN_INSTABILITY: no warn about instability issues on startup calibration\n"
      "AFL_NO_UI: switch status screen off\n"
      "AFL_NYX_AUX_SIZE: size of the Nyx auxiliary buffer. Must be a multiple of 4096.\n"
      "                  Increase this value in case the crash reports are truncated.\n"
      "                  Default value is 4096.\n"
      "AFL_NYX_DISABLE_SNAPSHOT_MODE: disable snapshot mode (must be supported by the agent)\n"
      "AFL_NYX_LOG: output NYX hprintf messages to another file\n"
      "AFL_NYX_REUSE_SNAPSHOT: reuse an existing Nyx root snapshot\n"
      DYN_COLOR

      "AFL_PATH: path to AFL support binaries\n"
      "AFL_PYTHON_MODULE: mutate and trim inputs with the specified Python module\n"
      "AFL_QUIET: suppress forkserver status messages\n"

      PERSISTENT_MSG

      "AFL_POST_PROCESS_KEEP_ORIGINAL: save the file as it was prior post-processing to\n"
      "                                the queue, but execute the post-processed one\n"
      "AFL_PRELOAD: LD_PRELOAD / DYLD_INSERT_LIBRARIES settings for target\n"
      "AFL_TARGET_ENV: pass extra environment variables to target\n"
      "AFL_SHUFFLE_QUEUE: reorder the input queue randomly on startup\n"
      "AFL_SKIP_BIN_CHECK: skip afl compatibility checks, also disables auto map size\n"
      "AFL_SKIP_CPUFREQ: do not warn about variable cpu clocking\n"
      //"AFL_SKIP_CRASHES: during initial dry run do not terminate for crashing inputs\n"
      "AFL_STATSD: enables StatsD metrics collection\n"
      "AFL_STATSD_HOST: change default statsd host (default 127.0.0.1)\n"
      "AFL_STATSD_PORT: change default statsd port (default: 8125)\n"
      "AFL_STATSD_TAGS_FLAVOR: set statsd tags format (default: disable tags)\n"
      "                        suported formats: dogstatsd, librato, signalfx, influxdb\n"
      "AFL_NO_FASTRESUME: do not read or write a fast resume file\n"
      "AFL_NO_SYNC: disables all syncing\n"
      "AFL_SYNC_TIME: sync time between fuzzing instances (in minutes)\n"
      "AFL_FINAL_SYNC: sync a final time when exiting (will delay the exit!)\n"
      "AFL_NO_CRASH_README: do not create a README in the crashes directory\n"
      "AFL_TESTCACHE_SIZE: use a cache for testcases, improves performance (in MB)\n"
      "AFL_TMPDIR: directory to use for input file generation (ramdisk recommended)\n"
      "AFL_EARLY_FORKSERVER: force an early forkserver in an afl-clang-fast/\n"
      "                      afl-clang-lto/afl-gcc-fast target\n"
      "AFL_PERSISTENT: enforce persistent mode (if __AFL_LOOP is in a shared lib)\n"
      "AFL_DEFER_FORKSRV: enforced deferred forkserver (__AFL_INIT is in a shared lib)\n"
      "AFL_FUZZER_STATS_UPDATE_INTERVAL: interval to update fuzzer_stats file in\n"
      "                                  seconds (default: 60, minimum: 1)\n"
      "\n"
    );

  } else {

    SAYF(
        "To view also the supported environment variables of afl-fuzz please "
        "use \"-hh\".\n\n");

  }

#ifdef USE_PYTHON
  SAYF("Compiled with %s module support, see docs/custom_mutators.md\n",
       (char *)PYTHON_VERSION);
#else
  SAYF("Compiled without Python module support.\n");
#endif

#ifdef AFL_PERSISTENT_RECORD
  SAYF("Compiled with AFL_PERSISTENT_RECORD support.\n");
#else
  SAYF("Compiled without AFL_PERSISTENT_RECORD support.\n");
#endif

#ifdef USEMMAP
  SAYF("Compiled with shm_open support.\n");
#else
  SAYF("Compiled with shmat support.\n");
#endif

#ifdef ASAN_BUILD
  SAYF("Compiled with ASAN_BUILD.\n");
#endif

#ifdef NO_SPLICING
  SAYF("Compiled with NO_SPLICING.\n");
#endif

#ifdef FANCY_BOXES_NO_UTF
  SAYF("Compiled without UTF-8 support for line rendering in status screen.\n");
#endif

#ifdef PROFILING
  SAYF("Compiled with PROFILING.\n");
#endif

#ifdef INTROSPECTION
  SAYF("Compiled with INTROSPECTION.\n");
#endif

#ifdef _DEBUG
  SAYF("Compiled with _DEBUG.\n");
#endif

#ifdef _AFL_DOCUMENT_MUTATIONS
  SAYF("Compiled with _AFL_DOCUMENT_MUTATIONS.\n");
#endif

#ifdef _AFL_SPECIAL_PERFORMANCE
  SAYF(
      "Compiled with special performance options for this specific system, it "
      "might not work on other platforms!\n");
#endif

  SAYF("For additional help please consult %s/README.md :)\n\n", doc_path);

  exit(1);
#undef PHYTON_SUPPORT

}

#ifndef AFL_LIB

static int stricmp(char const *a, char const *b) {

  if (!a || !b) { FATAL("Null reference"); }

  for (;; ++a, ++b) {

    int d;
    d = tolower((int)*a) - tolower((int)*b);
    if (d != 0 || !*a) { return d; }

  }

}

static void fasan_check_afl_preload(char *afl_preload) {

  char   first_preload[PATH_MAX + 1] = {0};
  char  *separator = strchr(afl_preload, ':');
  size_t first_preload_len = PATH_MAX;
  char  *basename;
  char   clang_runtime_prefix[] = "libclang_rt.asan";

  if (separator != NULL && (separator - afl_preload) < PATH_MAX) {

    first_preload_len = separator - afl_preload;

  }

  strncpy(first_preload, afl_preload, first_preload_len);

  basename = strrchr(first_preload, '/');
  if (basename == NULL) {

    basename = first_preload;

  } else {

    basename = basename + 1;

  }

  if (strncmp(basename, clang_runtime_prefix,
              sizeof(clang_runtime_prefix) - 1) != 0) {

    FATAL("Address Sanitizer DSO must be the first DSO in AFL_PRELOAD");

  }

  if (access(first_preload, R_OK) != 0) {

    FATAL("Address Sanitizer DSO not found");

  }

  OKF("Found ASAN DSO: %s", first_preload);

}

/* Main entry point */

int main(int argc, char **argv_orig, char **envp) {

  s32 opt, auto_sync = 0 /*, user_set_cache = 0*/;
  u64 prev_queued = 0;
  u32 sync_interval_cnt = 0, seek_to = 0, show_help = 0, default_output = 1,
      map_size = get_map_size();
  u8 *extras_dir[4];
  u8  mem_limit_given = 0, exit_1 = 0, debug = 0,
     extras_dir_cnt = 0 /*, have_p = 0*/;
  char  *afl_preload;
  char  *frida_afl_preload = NULL;
  char **use_argv;

  struct timeval  tv;
  struct timezone tz;

  doc_path = access(DOC_PATH, F_OK) != 0 ? (u8 *)"docs" : (u8 *)DOC_PATH;

  if (argc > 1 && strcmp(argv_orig[1], "--version") == 0) {

    printf("afl-fuzz" VERSION "\n");
    exit(0);

  }

  if (argc > 1 && strcmp(argv_orig[1], "--help") == 0) {

    usage(argv_orig[0], 1);
    exit(0);

  }

  #if defined USE_COLOR && defined ALWAYS_COLORED
  if (getenv("AFL_NO_COLOR") || getenv("AFL_NO_COLOUR")) {

    WARNF(
        "Setting AFL_NO_COLOR has no effect (colors are configured on at "
        "compile time)");

  }

  #endif

  char **argv = argv_cpy_dup(argc, argv_orig);

  afl_state_t *afl = calloc(1, sizeof(afl_state_t));
  if (!afl) { FATAL("Could not create afl state"); }

  if (get_afl_env("AFL_DEBUG")) { debug = afl->debug = 1; }

  afl_state_init(afl, map_size);
  afl->debug = debug;
  afl_fsrv_init(&afl->fsrv);
  if (debug) { afl->fsrv.debug = true; }
  read_afl_environment(afl, envp);
  if (afl->shm.map_size) { afl->fsrv.map_size = afl->shm.map_size; }
  exit_1 = !!afl->afl_env.afl_bench_just_one;

  SAYF(cCYA "afl-fuzz" VERSION cRST
            " based on afl by Michal Zalewski and a large online community\n");

  gettimeofday(&tv, &tz);
  rand_set_seed(afl, tv.tv_sec ^ tv.tv_usec ^ getpid());

  afl->shmem_testcase_mode = 1;  // we always try to perform shmem fuzzing

  // still available: HjJkKqruvwz
  while ((opt = getopt(argc, argv,
                       "+a:Ab:B:c:CdDe:E:f:F:g:G:hi:I:l:L:m:M:nNo:Op:P:QRs:S:t:"
                       "T:UV:WXx:YzZ")) > 0) {

    switch (opt) {

      case 'a':

        if (!stricmp(optarg, "text") || !stricmp(optarg, "ascii") ||
            !stricmp(optarg, "txt") || !stricmp(optarg, "asc")) {

          afl->input_mode = 1;

        } else if (!stricmp(optarg, "bin") || !stricmp(optarg, "binary")) {

          afl->input_mode = 2;

        } else if (!stricmp(optarg, "def") || !stricmp(optarg, "default")) {

          afl->input_mode = 0;

        } else {

          FATAL("-a input mode needs to be \"text\" or \"binary\".");

        }

        break;

      case 'P':
        if (!stricmp(optarg, "explore") || !stricmp(optarg, "exploration")) {

          afl->fuzz_mode = 0;
          afl->switch_fuzz_mode = 0;

        } else if (!stricmp(optarg, "exploit") ||

                   !stricmp(optarg, "exploitation")) {

          afl->fuzz_mode = 1;
          afl->switch_fuzz_mode = 0;

        } else {

          if ((afl->switch_fuzz_mode = (u32)atoi(optarg)) > INT_MAX) {

            FATAL(
                "Parameter for option -P must be \"explore\", \"exploit\" or a "
                "number!");

          } else {

            afl->switch_fuzz_mode *= 1000;

          }

        }

        break;

      case 'g':
        afl->min_length = atoi(optarg);
        break;

      case 'G':
        afl->max_length = atoi(optarg);
        break;

      case 'Z':
        afl->old_seed_selection = 1;
        break;

      case 'I':
        afl->infoexec = optarg;
        break;

      case 'b': {                                          /* bind CPU core */

        if (afl->cpu_to_bind != -1) FATAL("Multiple -b options not supported");

        if (sscanf(optarg, "%d", &afl->cpu_to_bind) < 0) {

          FATAL("Bad syntax used for -b");

        }

        break;

      }

      case 'c': {

        if (strcmp(optarg, "-") == 0) {

          if (afl->shm.cmplog_mode) {

            ACTF("Disabling cmplog again because of '-c -'.");
            afl->shm.cmplog_mode = 0;
            afl->cmplog_binary = NULL;

          }

        } else {

          afl->shm.cmplog_mode = 1;
          afl->cmplog_binary = ck_strdup(optarg);

        }

        break;

      }

      case 's': {

        if (optarg == NULL) { FATAL("No valid seed provided. Got NULL."); }
        rand_set_seed(afl, strtoul(optarg, 0L, 10));
        afl->fixed_seed = 1;
        break;

      }

      case 'p':                                           /* Power schedule */

        if (!stricmp(optarg, "fast")) {

          afl->schedule = FAST;

        } else if (!stricmp(optarg, "coe")) {

          afl->schedule = COE;

        } else if (!stricmp(optarg, "exploit")) {

          afl->schedule = EXPLOIT;

        } else if (!stricmp(optarg, "lin")) {

          afl->schedule = LIN;

        } else if (!stricmp(optarg, "quad")) {

          afl->schedule = QUAD;

        } else if (!stricmp(optarg, "mopt") || !stricmp(optarg, "mmopt")) {

          afl->schedule = MMOPT;

        } else if (!stricmp(optarg, "rare")) {

          afl->schedule = RARE;

        } else if (!stricmp(optarg, "explore") || !stricmp(optarg, "afl") ||

                   !stricmp(optarg, "default") ||

                   !stricmp(optarg, "normal")) {

          afl->schedule = EXPLORE;

        } else if (!stricmp(optarg, "seek")) {

          afl->schedule = SEEK;

        } else {

          FATAL("Unknown -p power schedule");

        }

        // have_p = 1;

        break;

      case 'e':

        if (afl->file_extension) { FATAL("Multiple -e options not supported"); }

        afl->file_extension = optarg;

        break;

      case 'i':                                                /* input dir */

        if (afl->in_dir) { FATAL("Multiple -i options not supported"); }
        if (optarg == NULL) { FATAL("Invalid -i option (got NULL)."); }
        afl->in_dir = optarg;

        if (!strcmp(afl->in_dir, "-")) { afl->in_place_resume = 1; }

        break;

      case 'o':                                               /* output dir */

        if (afl->out_dir) { FATAL("Multiple -o options not supported"); }
        afl->out_dir = optarg;
        break;

      case 'M': {                                           /* main sync ID */

        u8 *c;

        if (afl->non_instrumented_mode) {

          FATAL("-M is not supported in non-instrumented mode");

        }

        if (afl->fsrv.cs_mode) {

          FATAL("-M is not supported in ARM CoreSight mode");

        }

        if (afl->sync_id) { FATAL("Multiple -S or -M options not supported"); }

        /* sanity check for argument: should not begin with '-' (possible
         * option) */
        if (optarg && *optarg == '-') {

          FATAL(
              "argument for -M started with a dash '-', which is used for "
              "options");

        }

        afl->sync_id = ck_strdup(optarg);
        afl->old_seed_selection = 1;  // force old queue walking seed selection
        afl->disable_trim = 1;        // disable trimming

        if ((c = strchr(afl->sync_id, ':'))) {

          *c = 0;

          if (sscanf(c + 1, "%u/%u", &afl->main_node_id, &afl->main_node_max) !=
                  2 ||
              !afl->main_node_id || !afl->main_node_max ||
              afl->main_node_id > afl->main_node_max ||
              afl->main_node_max > 1000000) {

            FATAL("Bogus main node ID passed to -M");

          }

        }

        afl->is_main_node = 1;

      }

      break;

      case 'S':                                        /* secondary sync id */

        if (afl->non_instrumented_mode) {

          FATAL("-S is not supported in non-instrumented mode");

        }

        if (afl->fsrv.cs_mode) {

          FATAL("-S is not supported in ARM CoreSight mode");

        }

        if (afl->sync_id) { FATAL("Multiple -S or -M options not supported"); }

        /* sanity check for argument: should not begin with '-' (possible
         * option) */
        if (optarg && *optarg == '-') {

          FATAL(
              "argument for -M started with a dash '-', which is used for "
              "options");

        }

        afl->sync_id = ck_strdup(optarg);
        afl->is_secondary_node = 1;
        break;

      case 'F':                                         /* foreign sync dir */

        if (!optarg) { FATAL("Missing path for -F"); }
        if (!afl->is_main_node) {

          FATAL(
              "Option -F can only be specified after the -M option for the "
              "main fuzzer of a fuzzing campaign");

        }

        if (afl->foreign_sync_cnt >= FOREIGN_SYNCS_MAX) {

          FATAL("Maximum %u entried of -F option can be specified",
                FOREIGN_SYNCS_MAX);

        }

        afl->foreign_syncs[afl->foreign_sync_cnt].dir = optarg;
        while (afl->foreign_syncs[afl->foreign_sync_cnt]
                   .dir[strlen(afl->foreign_syncs[afl->foreign_sync_cnt].dir) -
                        1] == '/') {

          afl->foreign_syncs[afl->foreign_sync_cnt]
              .dir[strlen(afl->foreign_syncs[afl->foreign_sync_cnt].dir) - 1] =
              0;

        }

        afl->foreign_sync_cnt++;
        break;

      case 'f':                                              /* target file */

        if (afl->fsrv.out_file) { FATAL("Multiple -f options not supported"); }

        afl->fsrv.out_file = ck_strdup(optarg);
        afl->fsrv.use_stdin = 0;
        default_output = 0;
        break;

      case 'x':                                               /* dictionary */

        if (extras_dir_cnt >= 4) {

          FATAL("More than four -x options are not supported");

        }

        extras_dir[extras_dir_cnt++] = optarg;
        break;

      case 't': {                                                /* timeout */

        u8 suffix = 0;

        if (afl->timeout_given) { FATAL("Multiple -t options not supported"); }

        if (!optarg ||
            sscanf(optarg, "%u%c", &afl->fsrv.exec_tmout, &suffix) < 1 ||
            optarg[0] == '-') {

          FATAL("Bad syntax used for -t");

        }

        if (afl->fsrv.exec_tmout < 5) { FATAL("Dangerously low value of -t"); }

        if (suffix == '+') {

          afl->timeout_given = 2;

        } else {

          afl->timeout_given = 1;

        }

        break;

      }

      case 'm': {                                              /* mem limit */

        u8 suffix = 'M';

        if (mem_limit_given) {

          WARNF("Overriding previous -m option.");

        } else {

          mem_limit_given = 1;

        }

        if (!optarg) { FATAL("Wrong usage of -m"); }

        if (!strcmp(optarg, "none")) {

          afl->fsrv.mem_limit = 0;
          break;

        }

        if (sscanf(optarg, "%llu%c", &afl->fsrv.mem_limit, &suffix) < 1 ||
            optarg[0] == '-') {

          FATAL("Bad syntax used for -m");

        }

        switch (suffix) {

          case 'T':
            afl->fsrv.mem_limit *= 1024 * 1024;
            break;
          case 'G':
            afl->fsrv.mem_limit *= 1024;
            break;
          case 'k':
            afl->fsrv.mem_limit /= 1024;
            break;
          case 'M':
            break;

          default:
            FATAL("Unsupported suffix or bad syntax for -m");

        }

        if (afl->fsrv.mem_limit && afl->fsrv.mem_limit < 5) {

          FATAL("Dangerously low value of -m");

        }

        if (sizeof(rlim_t) == 4 && afl->fsrv.mem_limit > 2000) {

          FATAL("Value of -m out of range on 32-bit systems");

        }

      }

      break;

      case 'd':
      case 'D':                                        /* old deterministic */

        WARNF(
            "Parameters -d and -D are deprecated, a new enhanced deterministic "
            "fuzzing is active by default, to disable it use -z");
        break;

      case 'z':                                         /* no deterministic */

        afl->skip_deterministic = 1;
        break;

      case 'B':                                              /* load bitmap */

        /* This is a secret undocumented option! It is useful if you find
           an interesting test case during a normal fuzzing process, and want
           to mutate it without rediscovering any of the test cases already
           found during an earlier run.

           To use this mode, you need to point -B to the fuzz_bitmap produced
           by an earlier run for the exact same binary... and that's it.

           I only used this once or twice to get variants of a particular
           file, so I'm not making this an official setting. */

        if (afl->in_bitmap) { FATAL("Multiple -B options not supported"); }

        afl->in_bitmap = optarg;
        break;

      case 'C':                                               /* crash mode */

        if (afl->crash_mode) { FATAL("Multiple -C options not supported"); }
        afl->crash_mode = FSRV_RUN_CRASH;
        break;

      case 'n':                                                /* dumb mode */

        if (afl->is_main_node || afl->is_secondary_node) {

          FATAL("Non instrumented mode is not supported with -M / -S");

        }

        if (afl->non_instrumented_mode) {

          FATAL("Multiple -n options not supported");

        }

        if (afl->afl_env.afl_dumb_forksrv) {

          afl->non_instrumented_mode = 2;

        } else {

          afl->non_instrumented_mode = 1;

        }

        break;

      case 'T':                                                   /* banner */

        if (afl->use_banner) { FATAL("Multiple -T options not supported"); }
        afl->use_banner = optarg;
        break;

  #ifdef __linux__
      case 'X':                                                 /* NYX mode */

        if (afl->fsrv.nyx_mode) { FATAL("Multiple -X options not supported"); }

        afl->fsrv.nyx_parent = true;
        afl->fsrv.nyx_standalone = true;
        afl->fsrv.nyx_mode = 1;
        afl->fsrv.nyx_id = 0;

        break;

      case 'Y':                                     /* NYX distributed mode */
        if (afl->fsrv.nyx_mode) { FATAL("Multiple -Y options not supported"); }

        afl->fsrv.nyx_mode = 1;

        break;
  #else
      case 'X':
      case 'Y':
        FATAL("Nyx mode is only availabe on linux...");
        break;
  #endif
      case 'A':                                           /* CoreSight mode */

  #if !defined(__aarch64__) || !defined(__linux__)
        FATAL("-A option is not supported on this platform");
  #endif

        if (afl->is_main_node || afl->is_secondary_node) {

          FATAL("ARM CoreSight mode is not supported with -M / -S");

        }

        if (afl->fsrv.cs_mode) { FATAL("Multiple -A options not supported"); }

        afl->fsrv.cs_mode = 1;

        break;

      case 'O':                                               /* FRIDA mode */

        if (afl->fsrv.frida_mode) {

          FATAL("Multiple -O options not supported");

        }

        afl->fsrv.frida_mode = 1;
        if (get_afl_env("AFL_USE_FASAN")) { afl->fsrv.frida_asan = 1; }

        break;

      case 'Q':                                                /* QEMU mode */

        if (afl->fsrv.qemu_mode) { FATAL("Multiple -Q options not supported"); }

        afl->fsrv.qemu_mode = 1;

        if (!mem_limit_given) { afl->fsrv.mem_limit = MEM_LIMIT_QEMU; }

        break;

      case 'N':                                             /* Unicorn mode */

        if (afl->no_unlink) { FATAL("Multiple -N options not supported"); }
        afl->fsrv.no_unlink = (afl->no_unlink = true);

        break;

      case 'U':                                             /* Unicorn mode */

        if (afl->unicorn_mode) { FATAL("Multiple -U options not supported"); }
        afl->unicorn_mode = 1;

        if (!mem_limit_given) { afl->fsrv.mem_limit = MEM_LIMIT_UNICORN; }

        break;

      case 'W':                                           /* Wine+QEMU mode */

        if (afl->use_wine) { FATAL("Multiple -W options not supported"); }
        afl->fsrv.qemu_mode = 1;
        afl->use_wine = 1;

        if (!mem_limit_given) { afl->fsrv.mem_limit = 0; }

        break;

      case 'V': {

        afl->most_time_key = 1;
        if (!optarg || sscanf(optarg, "%llu", &afl->most_time) < 1 ||
            optarg[0] == '-') {

          FATAL("Bad syntax used for -V");

        }

      } break;

      case 'E': {

        afl->most_execs_key = 1;
        if (!optarg || sscanf(optarg, "%llu", &afl->most_execs) < 1 ||
            optarg[0] == '-') {

          FATAL("Bad syntax used for -E");

        }

      } break;

      case 'l': {

        if (!optarg) { FATAL("missing parameter for 'l'"); }
        char *c = optarg;
        while (*c) {

          switch (*c) {

            case '0':
            case '1':
              afl->cmplog_lvl = 1;
              break;
            case '2':
              afl->cmplog_lvl = 2;
              break;
            case '3':
              afl->cmplog_lvl = 3;

              if (!afl->disable_trim) {

                ACTF("Deactivating trimming due CMPLOG level 3");
                afl->disable_trim = 1;

              }

              break;
            case 'a':
            case 'A':
              afl->cmplog_enable_arith = 1;
              break;
            case 's':
            case 'S':
              afl->cmplog_enable_scale = 1;
              break;
            case 't':
            case 'T':
              afl->cmplog_enable_transform = 1;
              break;
            case 'x':
            case 'X':
              afl->cmplog_enable_xtreme_transform = 1;
              break;
            case 'r':
            case 'R':
              afl->cmplog_random_colorization = 1;
              break;
            default:
              FATAL("Unknown option value '%c' in -l %s", *c, optarg);

          }

          ++c;

        }

        if (afl->cmplog_lvl == CMPLOG_LVL_MAX) {

          afl->cmplog_max_filesize = MAX_FILE;

        }

      } break;

      case 'L': {                                              /* MOpt mode */

        if (afl->limit_time_sig) { FATAL("Multiple -L options not supported"); }

        afl->havoc_max_mult = HAVOC_MAX_MULT_MOPT;

        if (sscanf(optarg, "%d", &afl->limit_time_puppet) < 1) {

          FATAL("Bad syntax used for -L");

        }

        if (afl->limit_time_puppet == -1) {

          afl->limit_time_sig = -1;
          afl->limit_time_puppet = 0;

        } else if (afl->limit_time_puppet < 0) {

          FATAL("-L value must be between 0 and 2000000 or -1");

        } else {

          afl->limit_time_sig = 1;

        }

        afl->old_seed_selection = 1;
        u64 limit_time_puppet2 = afl->limit_time_puppet * 60 * 1000;

        if ((s32)limit_time_puppet2 < afl->limit_time_puppet) {

          FATAL("limit_time overflow");

        }

        afl->limit_time_puppet = limit_time_puppet2;
        afl->swarm_now = 0;
        if (afl->limit_time_puppet == 0) { afl->key_puppet = 1; }

        int j;
        int tmp_swarm = 0;

        if (afl->g_now > afl->g_max) { afl->g_now = 0; }
        afl->w_now = (afl->w_init - afl->w_end) * (afl->g_max - afl->g_now) /
                         (afl->g_max) +
                     afl->w_end;

        for (tmp_swarm = 0; tmp_swarm < swarm_num; ++tmp_swarm) {

          double total_puppet_temp = 0.0;
          afl->swarm_fitness[tmp_swarm] = 0.0;

          for (j = 0; j < operator_num; ++j) {

            afl->stage_finds_puppet[tmp_swarm][j] = 0;
            afl->probability_now[tmp_swarm][j] = 0.0;
            afl->x_now[tmp_swarm][j] =
                ((double)(random() % 7000) * 0.0001 + 0.1);
            total_puppet_temp += afl->x_now[tmp_swarm][j];
            afl->v_now[tmp_swarm][j] = 0.1;
            afl->L_best[tmp_swarm][j] = 0.5;
            afl->G_best[j] = 0.5;
            afl->eff_best[tmp_swarm][j] = 0.0;

          }

          for (j = 0; j < operator_num; ++j) {

            afl->stage_cycles_puppet_v2[tmp_swarm][j] =
                afl->stage_cycles_puppet[tmp_swarm][j];
            afl->stage_finds_puppet_v2[tmp_swarm][j] =
                afl->stage_finds_puppet[tmp_swarm][j];
            afl->x_now[tmp_swarm][j] =
                afl->x_now[tmp_swarm][j] / total_puppet_temp;

          }

          double x_temp = 0.0;

          for (j = 0; j < operator_num; ++j) {

            afl->probability_now[tmp_swarm][j] = 0.0;
            afl->v_now[tmp_swarm][j] =
                afl->w_now * afl->v_now[tmp_swarm][j] +
                RAND_C *
                    (afl->L_best[tmp_swarm][j] - afl->x_now[tmp_swarm][j]) +
                RAND_C * (afl->G_best[j] - afl->x_now[tmp_swarm][j]);

            afl->x_now[tmp_swarm][j] += afl->v_now[tmp_swarm][j];

            if (afl->x_now[tmp_swarm][j] > v_max) {

              afl->x_now[tmp_swarm][j] = v_max;

            } else if (afl->x_now[tmp_swarm][j] < v_min) {

              afl->x_now[tmp_swarm][j] = v_min;

            }

            x_temp += afl->x_now[tmp_swarm][j];

          }

          for (j = 0; j < operator_num; ++j) {

            afl->x_now[tmp_swarm][j] = afl->x_now[tmp_swarm][j] / x_temp;
            if (likely(j != 0)) {

              afl->probability_now[tmp_swarm][j] =
                  afl->probability_now[tmp_swarm][j - 1] +
                  afl->x_now[tmp_swarm][j];

            } else {

              afl->probability_now[tmp_swarm][j] = afl->x_now[tmp_swarm][j];

            }

          }

          if (afl->probability_now[tmp_swarm][operator_num - 1] < 0.99 ||
              afl->probability_now[tmp_swarm][operator_num - 1] > 1.01) {

            FATAL("ERROR probability");

          }

        }

        for (j = 0; j < operator_num; ++j) {

          afl->core_operator_finds_puppet[j] = 0;
          afl->core_operator_finds_puppet_v2[j] = 0;
          afl->core_operator_cycles_puppet[j] = 0;
          afl->core_operator_cycles_puppet_v2[j] = 0;
          afl->core_operator_cycles_puppet_v3[j] = 0;

        }

        WARNF(
            "Note that the MOpt mode is not maintained and is not as effective "
            "as normal havoc mode.");

      } break;

      case 'h':
        show_help++;
        break;  // not needed

      case 'R':

        FATAL(
            "Radamsa is now a custom mutator, please use that "
            "(custom_mutators/radamsa/).");

        break;

      default:
        if (!show_help) { show_help = 1; }

    }

  }

  if (afl->sync_id && strcmp(afl->sync_id, "addseeds") == 0) {

    FATAL("-M/-S name 'addseeds' is a reserved name, choose something else");

  }

  if (afl->is_main_node == 1 && afl->schedule != FAST &&
      afl->schedule != EXPLORE) {

    FATAL("-M is compatible only with fast and explore -p power schedules");

  }

  if (optind == argc || !afl->in_dir || !afl->out_dir || show_help) {

    usage(argv[0], show_help);

  }

  if (unlikely(afl->afl_env.afl_persistent_record)) {

  #ifdef AFL_PERSISTENT_RECORD

    afl->fsrv.persistent_record = atoi(afl->afl_env.afl_persistent_record);

    if (afl->fsrv.persistent_record < 2) {

      FATAL(
          "AFL_PERSISTENT_RECORD value must be be at least 2, recommended is "
          "100 or 1000.");

    }

  #else

    FATAL(
        "afl-fuzz was not compiled with AFL_PERSISTENT_RECORD enabled in "
        "config.h!");

  #endif

  }

  if (afl->fsrv.mem_limit && afl->shm.cmplog_mode) afl->fsrv.mem_limit += 260;

  OKF("AFL++ is maintained by Marc \"van Hauser\" Heuse, Dominik Maier, Andrea "
      "Fioraldi and Heiko \"hexcoder\" Eißfeldt");
  OKF("AFL++ is open source, get it at "
      "https://github.com/AFLplusplus/AFLplusplus");
  OKF("NOTE: AFL++ >= v3 has changed defaults and behaviours - see README.md");

  #ifdef __linux__
  if (afl->fsrv.nyx_mode) {

    OKF("AFL++ Nyx mode is enabled (developed and maintained by Sergej "
        "Schumilo)");
    OKF("Nyx is open source, get it at https://github.com/Nyx-Fuzz");

  }

  #endif

  // silently disable deterministic mutation if custom mutators are used
  if (!afl->skip_deterministic && afl->afl_env.afl_custom_mutator_only) {

    afl->skip_deterministic = 1;

  }

  if (afl->fixed_seed) {

    OKF("Running with fixed seed: %u", (u32)afl->init_seed);

  }

  #if defined(__SANITIZE_ADDRESS__)
  if (afl->fsrv.mem_limit) {

    WARNF("in the ASAN build we disable all memory limits");
    afl->fsrv.mem_limit = 0;

  }

  #endif

  configure_afl_kill_signals(
      &afl->fsrv, afl->afl_env.afl_child_kill_signal,
      afl->afl_env.afl_fsrv_kill_signal,
      (afl->fsrv.qemu_mode || afl->unicorn_mode || afl->fsrv.use_fauxsrv
  #ifdef __linux__
       || afl->fsrv.nyx_mode
  #endif
       )
          ? SIGKILL
          : SIGTERM);

  setup_signal_handlers();
  check_asan_opts(afl);

  afl->power_name = power_names[afl->schedule];

  if (!afl->non_instrumented_mode && !afl->sync_id) {

    auto_sync = 1;
    afl->sync_id = ck_strdup("default");
    afl->is_secondary_node = 1;
    OKF("No -M/-S set, autoconfiguring for \"-S %s\"", afl->sync_id);

  }

  #ifdef __linux__
  if (afl->fsrv.nyx_mode) {

    if (afl->fsrv.nyx_standalone && strcmp(afl->sync_id, "default") != 0) {

      FATAL(
          "distributed fuzzing is not supported in this Nyx mode (use -Y "
          "instead)");

    }

    if (!afl->fsrv.nyx_standalone) {

      if (afl->is_main_node) {

        if (strcmp("0", afl->sync_id) != 0) {

          FATAL(
              "for Nyx -Y mode, the Main (-M) parameter has to be set to 0 (-M "
              "0)");

        }

        afl->fsrv.nyx_parent = true;
        afl->fsrv.nyx_id = 0;

      }

      if (afl->is_secondary_node) {

        long nyx_id = strtol(afl->sync_id, NULL, 10);

        if (nyx_id == 0 || nyx_id == LONG_MAX) {

          FATAL(
              "for Nyx -Y mode, the Secondary (-S) parameter has to be a "
              "numeric value and >= 1 (e.g. -S 1)");

        }

        afl->fsrv.nyx_id = nyx_id;

      }

    }

  }

  #endif

  if (afl->sync_id) { fix_up_sync(afl); }

  if (!strcmp(afl->in_dir, afl->out_dir)) {

    FATAL("Input and output directories can't be the same");

  }

  if (afl->non_instrumented_mode) {

    if (afl->crash_mode) { FATAL("-C and -n are mutually exclusive"); }
    if (afl->fsrv.frida_mode) { FATAL("-O and -n are mutually exclusive"); }
    if (afl->fsrv.qemu_mode) { FATAL("-Q and -n are mutually exclusive"); }
    if (afl->fsrv.cs_mode) { FATAL("-A and -n are mutually exclusive"); }
    if (afl->unicorn_mode) { FATAL("-U and -n are mutually exclusive"); }

  }

  setenv("__AFL_OUT_DIR", afl->out_dir, 1);

  if (get_afl_env("AFL_DISABLE_TRIM") || get_afl_env("AFL_NO_TRIM")) {

    afl->disable_trim = 1;

  }

  if (getenv("AFL_NO_UI") && getenv("AFL_FORCE_UI")) {

    FATAL("AFL_NO_UI and AFL_FORCE_UI are mutually exclusive");

  }

  if (unlikely(afl->afl_env.afl_statsd)) { statsd_setup_format(afl); }

  if (!afl->use_banner) { afl->use_banner = argv[optind]; }

  if (afl->shm.cmplog_mode && strcmp("0", afl->cmplog_binary) == 0) {

    afl->cmplog_binary = strdup(argv[optind]);

  }

  if (strchr(argv[optind], '/') == NULL && !afl->unicorn_mode) {

    WARNF(cLRD
          "Target binary called without a prefixed path, make sure you are "
          "fuzzing the right binary: " cRST "%s",
          argv[optind]);

  }

  ACTF("Getting to work...");

  switch (afl->schedule) {

    case FAST:
      OKF("Using exponential power schedule (FAST)");
      break;
    case COE:
      OKF("Using cut-off exponential power schedule (COE)");
      break;
    case EXPLOIT:
      OKF("Using exploitation-based constant power schedule (EXPLOIT)");
      break;
    case LIN:
      OKF("Using linear power schedule (LIN)");
      break;
    case QUAD:
      OKF("Using quadratic power schedule (QUAD)");
      break;
    case MMOPT:
      OKF("Using modified MOpt power schedule (MMOPT)");
      break;
    case RARE:
      OKF("Using rare edge focus power schedule (RARE)");
      break;
    case SEEK:
      OKF("Using seek power schedule (SEEK)");
      break;
    case EXPLORE:
      OKF("Using exploration-based constant power schedule (EXPLORE)");
      break;
    default:
      FATAL("Unknown power schedule");
      break;

  }

  if (afl->shm.cmplog_mode) { OKF("CmpLog level: %u", afl->cmplog_lvl); }

  /* Dynamically allocate memory for AFLFast schedules */
  if (afl->schedule >= FAST && afl->schedule <= RARE) {

    afl->n_fuzz = ck_alloc(N_FUZZ_SIZE * sizeof(u32));

  }

  if (get_afl_env("AFL_NO_FORKSRV")) { afl->no_forkserver = 1; }
  if (get_afl_env("AFL_NO_CPU_RED")) { afl->no_cpu_meter_red = 1; }
  if (get_afl_env("AFL_NO_ARITH")) { afl->no_arith = 1; }
  if (get_afl_env("AFL_SHUFFLE_QUEUE")) { afl->shuffle_queue = 1; }
  if (get_afl_env("AFL_EXPAND_HAVOC_NOW")) { afl->expand_havoc = 1; }

  if (afl->afl_env.afl_autoresume) {

    afl->autoresume = 1;
    if (afl->in_place_resume) {

      SAYF("AFL_AUTORESUME has no effect for '-i -'");

    }

  }

  if (afl->afl_env.afl_hang_tmout) {

    s32 hang_tmout = atoi(afl->afl_env.afl_hang_tmout);
    if (hang_tmout < 1) { FATAL("Invalid value for AFL_HANG_TMOUT"); }
    afl->hang_tmout = (u32)hang_tmout;

  }

  if (afl->afl_env.afl_exit_on_time) {

    u64 exit_on_time = atoi(afl->afl_env.afl_exit_on_time);
    afl->exit_on_time = (u64)exit_on_time * 1000;

  }

  if (afl->afl_env.afl_max_det_extras) {

    s32 max_det_extras = atoi(afl->afl_env.afl_max_det_extras);
    if (max_det_extras < 1) { FATAL("Invalid value for AFL_MAX_DET_EXTRAS"); }
    afl->max_det_extras = (u32)max_det_extras;

  } else {

    afl->max_det_extras = MAX_DET_EXTRAS;

  }

  if (afl->afl_env.afl_testcache_size) {

    afl->q_testcase_max_cache_size =
        (u64)atoi(afl->afl_env.afl_testcache_size) * 1048576;

  }

  if (afl->afl_env.afl_testcache_entries) {

    afl->q_testcase_max_cache_entries =
        (u32)atoi(afl->afl_env.afl_testcache_entries);

    // user_set_cache = 1;

  }

  if (!afl->afl_env.afl_testcache_size || !afl->afl_env.afl_testcache_entries) {

    afl->afl_env.afl_testcache_entries = 0;
    afl->afl_env.afl_testcache_size = 0;

  }

  if (!afl->q_testcase_max_cache_size) {

    ACTF(
        "No testcache was configured. it is recommended to use a testcache, it "
        "improves performance: set AFL_TESTCACHE_SIZE=(value in MB)");

  } else if (afl->q_testcase_max_cache_size < 2 * MAX_FILE) {

    FATAL("AFL_TESTCACHE_SIZE must be set to %ld or more, or 0 to disable",
          (2 * MAX_FILE) % 1048576 == 0 ? (2 * MAX_FILE) / 1048576
                                        : 1 + ((2 * MAX_FILE) / 1048576));

  } else {

    OKF("Enabled testcache with %llu MB",
        afl->q_testcase_max_cache_size / 1048576);

  }

  if (afl->afl_env.afl_forksrv_init_tmout) {

    afl->fsrv.init_tmout = atoi(afl->afl_env.afl_forksrv_init_tmout);
    if (!afl->fsrv.init_tmout) {

      FATAL("Invalid value of AFL_FORKSRV_INIT_TMOUT");

    }

  } else {

    afl->fsrv.init_tmout = afl->fsrv.exec_tmout * FORK_WAIT_MULT;

  }

  if (afl->afl_env.afl_crash_exitcode) {

    long exitcode = strtol(afl->afl_env.afl_crash_exitcode, NULL, 10);
    if ((!exitcode && (errno == EINVAL || errno == ERANGE)) ||
        exitcode < -127 || exitcode > 128) {

      FATAL("Invalid crash exitcode, expected -127 to 128, but got %s",
            afl->afl_env.afl_crash_exitcode);

    }

    afl->fsrv.uses_crash_exitcode = true;
    // WEXITSTATUS is 8 bit unsigned
    afl->fsrv.crash_exitcode = (u8)exitcode;

  }

  if (afl->non_instrumented_mode == 2 && afl->no_forkserver) {

    FATAL("AFL_DUMB_FORKSRV and AFL_NO_FORKSRV are mutually exclusive");

  }

  // Marker: ADD_TO_INJECTIONS
  if (getenv("AFL_LLVM_INJECTIONS_ALL") || getenv("AFL_LLVM_INJECTIONS_SQL") ||
      getenv("AFL_LLVM_INJECTIONS_LDAP") || getenv("AFL_LLVM_INJECTIONS_XSS")) {

    OKF("Adding injection tokens to dictionary.");
    if (getenv("AFL_LLVM_INJECTIONS_ALL") ||
        getenv("AFL_LLVM_INJECTIONS_SQL")) {

      add_extra(afl, "'\"\"'", 4);

    }

    if (getenv("AFL_LLVM_INJECTIONS_ALL") ||
        getenv("AFL_LLVM_INJECTIONS_LDAP")) {

      add_extra(afl, "*)(1=*))(|", 10);

    }

    if (getenv("AFL_LLVM_INJECTIONS_ALL") ||
        getenv("AFL_LLVM_INJECTIONS_XSS")) {

      add_extra(afl, "1\"><\"", 5);

    }

  }

  OKF("Generating fuzz data with a length of min=%u max=%u", afl->min_length,
      afl->max_length);
  u32 min_alloc = MAX(64U, afl->min_length);
  afl_realloc(AFL_BUF_PARAM(in_scratch), min_alloc);
  afl_realloc(AFL_BUF_PARAM(in), min_alloc);
  afl_realloc(AFL_BUF_PARAM(out_scratch), min_alloc);
  afl_realloc(AFL_BUF_PARAM(out), min_alloc);
  afl_realloc(AFL_BUF_PARAM(eff), min_alloc);
  afl_realloc(AFL_BUF_PARAM(ex), min_alloc);

  afl->fsrv.use_fauxsrv = afl->non_instrumented_mode == 1 || afl->no_forkserver;
  afl->fsrv.max_length = afl->max_length;

  #ifdef __linux__
  if (!afl->fsrv.nyx_mode) {

    check_crash_handling();
    check_cpu_governor(afl);

  } else {

    u8 *libnyx_binary = find_afl_binary(argv[0], "libnyx.so");
    afl->fsrv.nyx_handlers = afl_load_libnyx_plugin(libnyx_binary);
    if (afl->fsrv.nyx_handlers == NULL) {

      FATAL("failed to initialize libnyx.so...");

    }

  }

  #else
  check_crash_handling();
  check_cpu_governor(afl);
  #endif

  #ifdef __APPLE__
  setenv("DYLD_NO_PIE", "1", 0);
  #endif

  if (getenv("LD_PRELOAD")) {

    WARNF(
        "LD_PRELOAD is set, are you sure that is what you want to do "
        "instead of using AFL_PRELOAD?");

  }

  if (afl->afl_env.afl_preload) {

    if (afl->fsrv.qemu_mode) {

      /* afl-qemu-trace takes care of converting AFL_PRELOAD. */

    } else if (afl->fsrv.frida_mode) {

      afl_preload = getenv("AFL_PRELOAD");
      u8 *frida_binary = find_afl_binary(argv[0], "afl-frida-trace.so");
      OKF("Injecting %s ...", frida_binary);
      if (afl_preload) {

        if (afl->fsrv.frida_asan) {

          OKF("Using Frida Address Sanitizer Mode");

          if (afl->fsrv.mem_limit) {

            WARNF(
                "in the Frida Address Sanitizer Mode we disable all memory "
                "limits");
            afl->fsrv.mem_limit = 0;

          }

          fasan_check_afl_preload(afl_preload);

          setenv("ASAN_OPTIONS", "detect_leaks=false", 1);

        }

        u8 *frida_binary = find_afl_binary(argv[0], "afl-frida-trace.so");
        OKF("Injecting %s ...", frida_binary);
        frida_afl_preload = alloc_printf("%s:%s", afl_preload, frida_binary);

        ck_free(frida_binary);

        setenv("LD_PRELOAD", frida_afl_preload, 1);
        setenv("DYLD_INSERT_LIBRARIES", frida_afl_preload, 1);

      }

    } else {

      /* CoreSight mode uses the default behavior. */

      setenv("LD_PRELOAD", getenv("AFL_PRELOAD"), 1);
      setenv("DYLD_INSERT_LIBRARIES", getenv("AFL_PRELOAD"), 1);

    }

  } else if (afl->fsrv.frida_mode) {

    if (afl->fsrv.frida_asan) {

      OKF("Using Frida Address Sanitizer Mode");
      FATAL(
          "Address Sanitizer DSO must be loaded using AFL_PRELOAD in Frida "
          "Address Sanitizer Mode");

    } else {

      u8 *frida_binary = find_afl_binary(argv[0], "afl-frida-trace.so");
      OKF("Injecting %s ...", frida_binary);
      setenv("LD_PRELOAD", frida_binary, 1);
      setenv("DYLD_INSERT_LIBRARIES", frida_binary, 1);
      ck_free(frida_binary);

    }

  }

  if (getenv("AFL_LD_PRELOAD")) {

    FATAL("Use AFL_PRELOAD instead of AFL_LD_PRELOAD");

  }

  if (afl->afl_env.afl_target_env &&
      !extract_and_set_env(afl->afl_env.afl_target_env)) {

    FATAL("Bad value of AFL_TARGET_ENV");

  }

  save_cmdline(afl, argc, argv);
  check_if_tty(afl);
  if (afl->afl_env.afl_force_ui) { afl->not_on_tty = 0; }

  get_core_count(afl);

  atexit(at_exit);

  setup_dirs_fds(afl);

  #ifdef HAVE_AFFINITY
  bind_to_free_cpu(afl);
  #endif                                                   /* HAVE_AFFINITY */

  #ifdef __linux__
  if (afl->fsrv.nyx_mode && afl->fsrv.nyx_bind_cpu_id == 0xFFFFFFFF) {

    afl->fsrv.nyx_bind_cpu_id = 0;

  }

  #endif

  #ifdef __HAIKU__
  /* Prioritizes performance over power saving */
  set_scheduler_mode(SCHEDULER_MODE_LOW_LATENCY);
  #endif

  #ifdef __APPLE__
  if (pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0) != 0) {

    WARNF("general thread priority settings failed");

  }

  #endif

  init_count_class16();

  if (afl->is_main_node && check_main_node_exists(afl) == 1) {

    WARNF("it is wasteful to run more than one main node!");
    sleep(1);

  } else if (!auto_sync && afl->is_secondary_node &&

             check_main_node_exists(afl) == 0) {

    WARNF(
        "no -M main node found. It is recommended to run exactly one main "
        "instance.");
    sleep(1);

  }

  #ifdef RAND_TEST_VALUES
  u32 counter;
  for (counter = 0; counter < 100000; counter++)
    printf("DEBUG: rand %06d is %u\n", counter, rand_below(afl, 65536));
  #endif

  if (!getenv("AFL_CUSTOM_INFO_PROGRAM")) {

    setenv("AFL_CUSTOM_INFO_PROGRAM", argv[optind], 1);

  }

  if (!getenv("AFL_CUSTOM_INFO_PROGRAM_INPUT") && afl->fsrv.out_file) {

    setenv("AFL_CUSTOM_INFO_PROGRAM_INPUT", afl->fsrv.out_file, 1);

  }

  if (!getenv("AFL_CUSTOM_INFO_PROGRAM_ARGV")) {

    u8 envbuf[8096] = "", tmpbuf[8096] = "";
    for (s32 i = optind + 1; i < argc; ++i) {

      strcpy(tmpbuf, envbuf);
      if (strchr(argv[i], ' ') && !strchr(argv[i], '"') &&
          !strchr(argv[i], '\'')) {

        if (!strchr(argv[i], '\'')) {

          snprintf(envbuf, sizeof(tmpbuf), "%s '%s'", tmpbuf, argv[i]);

        } else {

          snprintf(envbuf, sizeof(tmpbuf), "%s \"%s\"", tmpbuf, argv[i]);

        }

      } else {

        snprintf(envbuf, sizeof(tmpbuf), "%s %s", tmpbuf, argv[i]);

      }

    }

    setenv("AFL_CUSTOM_INFO_PROGRAM_ARGV", envbuf + 1, 1);

  }

  if (!getenv("AFL_CUSTOM_INFO_OUT")) {

    setenv("AFL_CUSTOM_INFO_OUT", afl->out_dir, 1);  // same as __AFL_OUT_DIR

  }

  setup_custom_mutators(afl);

  if (afl->afl_env.afl_custom_mutator_only) {

    if (!afl->custom_mutators_count) {

      if (afl->shm.cmplog_mode) {

        WARNF(
            "No custom mutator loaded, using AFL_CUSTOM_MUTATOR_ONLY is "
            "pointless and only allowed now to allow experiments with CMPLOG.");

      } else {

        FATAL(
            "No custom mutator loaded but AFL_CUSTOM_MUTATOR_ONLY specified.");

      }

    }

    /* This ensures we don't proceed to havoc/splice */
    afl->custom_only = 1;

    /* Ensure we also skip all deterministic steps */
    afl->skip_deterministic = 1;

  }

  if (afl->custom_mutators_count && afl->afl_env.afl_custom_mutator_late_send) {

    u32 count_send = 0;
    LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

      if (el->afl_custom_fuzz_send) {

        if (count_send) {

          FATAL(
              "You can only have one custom send() function if you are using "
              "AFL_CUSTOM_MUTATOR_LATE_SEND!");

        }

        afl->fsrv.late_send = el->afl_custom_fuzz_send;
        afl->fsrv.custom_data_ptr = el->data;
        count_send = 1;

      }

    });

  }

  if (afl->limit_time_sig > 0 && afl->custom_mutators_count) {

    if (afl->custom_only) {

      FATAL("Custom mutators are incompatible with MOpt (-L)");

    }

    u32 custom_fuzz = 0;
    LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

      if (el->afl_custom_fuzz) { custom_fuzz = 1; }

    });

    if (custom_fuzz) {

      WARNF("afl_custom_fuzz is incompatible with MOpt (-L)");

    }

  }

  /* Simply code if AFL_TMPDIR is used or not */
  if (!afl->afl_env.afl_tmpdir) {

    afl->tmp_dir = afl->out_dir;

  } else {

    afl->tmp_dir = afl->afl_env.afl_tmpdir;

  }

  setup_cmdline_file(afl, argv + optind);
  check_binary(afl, argv[optind]);

  u64 prev_target_hash = 0;
  s32 fast_resume = 0;
  #ifdef HAVE_ZLIB
  gzFile fr_fd = NULL;
  #else
  s32 fr_fd = -1;
  #endif

  if (afl->in_place_resume && !afl->afl_env.afl_no_fastresume) {

    u8 fn[PATH_MAX], buf[32];
    snprintf(fn, PATH_MAX, "%s/target_hash", afl->out_dir);
    s32 fd = open(fn, O_RDONLY);
    if (fd >= 0) {

      if (read(fd, buf, 32) >= 16) {

        sscanf(buf, "%p", (void **)&prev_target_hash);

      }

      close(fd);

    }

  }

  write_setup_file(afl, argc, argv);

  if (afl->in_place_resume && !afl->afl_env.afl_no_fastresume) {

  #ifdef __linux__
    u64 target_hash = 0;
    if (afl->fsrv.nyx_mode) {

      nyx_load_target_hash(&afl->fsrv);
      target_hash = afl->fsrv.nyx_target_hash64;

    } else {

      target_hash = get_binary_hash(afl->fsrv.target_path);

    }

  #else
    u64 target_hash = get_binary_hash(afl->fsrv.target_path);
  #endif

    if ((!target_hash || prev_target_hash != target_hash)
  #ifdef __linux__
        || (afl->fsrv.nyx_mode && target_hash == 0)
  #endif
    ) {

      ACTF("Target binary is different, cannot perform FAST RESUME!");

    } else {

      u8 fn[PATH_MAX];
      snprintf(fn, PATH_MAX, "%s/fastresume.bin", afl->out_dir);
  #ifdef HAVE_ZLIB
      if ((fr_fd = ZLIBOPEN(fn, "rb")) != NULL) {

  #else
      if ((fr_fd = open(fn, O_RDONLY)) >= 0) {

  #endif

        u8   ver_string[8];
        u64 *ver = (u64 *)ver_string;
        u64  expect_ver =
            afl->shm.cmplog_mode + (sizeof(struct queue_entry) << 1);

        if (NZLIBREAD(fr_fd, ver_string, sizeof(ver_string)) !=
            sizeof(ver_string))
          WARNF("Emtpy fastresume.bin, ignoring, cannot perform FAST RESUME");
        else if (expect_ver != *ver)
          WARNF(
              "Different AFL++ version or feature usage, cannot perform FAST "
              "RESUME");
        else {

          OKF("Will perform FAST RESUME");
          fast_resume = 1;

        }

      } else {

        ACTF("fastresume.bin not found, cannot perform FAST RESUME!");

      }

      // If the fast resume file is not valid we will be unable to start, so
      // we remove the file but keep the file descriptor open.
      unlink(fn);

    }

  }

  read_testcases(afl, NULL);

  pivot_inputs(afl);

  if (!afl->timeout_given) { find_timeout(afl); }  // only for resumes!

  if (afl->afl_env.afl_tmpdir && !afl->in_place_resume) {

    char tmpfile[PATH_MAX];

    if (afl->file_extension) {

      snprintf(tmpfile, PATH_MAX, "%s/.cur_input.%s", afl->tmp_dir,
               afl->file_extension);

    } else {

      snprintf(tmpfile, PATH_MAX, "%s/.cur_input", afl->tmp_dir);

    }

    /* there is still a race condition here, but well ... */
    if (access(tmpfile, F_OK) != -1) {

      FATAL(
          "AFL_TMPDIR already has an existing temporary input file: %s - if "
          "this is not from another instance, then just remove the file.",
          tmpfile);

    }

  }

  // read_foreign_testcases(afl, 1); for the moment dont do this
  OKF("Loaded a total of %u seeds.", afl->queued_items);

  /* If we don't have a file name chosen yet, use a safe default. */

  if (!afl->fsrv.out_file) {

    u32 j = optind + 1;
    while (argv[j]) {

      u8 *aa_loc = strstr(argv[j], "@@");

      if (aa_loc && !afl->fsrv.out_file) {

        afl->fsrv.use_stdin = 0;
        default_output = 0;

        if (afl->file_extension) {

          afl->fsrv.out_file = alloc_printf("%s/.cur_input.%s", afl->tmp_dir,
                                            afl->file_extension);

        } else {

          afl->fsrv.out_file = alloc_printf("%s/.cur_input", afl->tmp_dir);

        }

        detect_file_args(argv + optind + 1, afl->fsrv.out_file,
                         &afl->fsrv.use_stdin);
        break;

      }

      ++j;

    }

  }

  if (!afl->fsrv.out_file) { setup_stdio_file(afl); }

  if (afl->cmplog_binary) {

    if (afl->unicorn_mode) {

      FATAL("CmpLog and Unicorn mode are not compatible at the moment, sorry");

    }

    if (!afl->fsrv.qemu_mode && !afl->fsrv.frida_mode && !afl->fsrv.cs_mode &&
        !afl->non_instrumented_mode) {

      check_binary(afl, afl->cmplog_binary);

    }

  }

  #ifdef AFL_PERSISTENT_RECORD
  if (unlikely(afl->fsrv.persistent_record)) {

    if (!getenv(PERSIST_ENV_VAR) && !getenv("AFL_FRIDA_PERSISTENT_ADDR") &&
        !getenv("AFL_QEMU_PERSISTENT_ADDR")) {

      FATAL(
          "Target binary is not compiled/run in persistent mode, "
          "AFL_PERSISTENT_RECORD makes no sense.");

    }

    afl->fsrv.persistent_record_dir = alloc_printf("%s", afl->out_dir);

  }

  #endif

  if (afl->shmem_testcase_mode) { setup_testcase_shmem(afl); }

  afl->start_time = get_cur_time();

  if (afl->fsrv.qemu_mode) {

    if (afl->use_wine) {

      use_argv = get_wine_argv(argv[0], &afl->fsrv.target_path, argc - optind,
                               argv + optind);

    } else {

      use_argv = get_qemu_argv(argv[0], &afl->fsrv.target_path, argc - optind,
                               argv + optind);

    }

  } else if (afl->fsrv.cs_mode) {

    use_argv = get_cs_argv(argv[0], &afl->fsrv.target_path, argc - optind,
                           argv + optind);

  } else {

    use_argv = argv + optind;

  }

  if (afl->non_instrumented_mode || afl->fsrv.qemu_mode ||
      afl->fsrv.frida_mode || afl->fsrv.cs_mode || afl->unicorn_mode) {

    u32 old_map_size = map_size;
    map_size = afl->fsrv.real_map_size = afl->fsrv.map_size = MAP_SIZE;
    afl->virgin_bits = ck_realloc(afl->virgin_bits, map_size);
    afl->virgin_tmout = ck_realloc(afl->virgin_tmout, map_size);
    afl->virgin_crash = ck_realloc(afl->virgin_crash, map_size);
    afl->var_bytes = ck_realloc(afl->var_bytes, map_size);
    afl->top_rated = ck_realloc(afl->top_rated, map_size * sizeof(void *));
    afl->clean_trace = ck_realloc(afl->clean_trace, map_size);
    afl->clean_trace_custom = ck_realloc(afl->clean_trace_custom, map_size);
    afl->first_trace = ck_realloc(afl->first_trace, map_size);
    afl->map_tmp_buf = ck_realloc(afl->map_tmp_buf, map_size);

    if (old_map_size < map_size) {

      memset(afl->var_bytes + old_map_size, 0, map_size - old_map_size);
      memset(afl->top_rated + old_map_size, 0, map_size - old_map_size);
      memset(afl->clean_trace + old_map_size, 0, map_size - old_map_size);
      memset(afl->clean_trace_custom + old_map_size, 0,
             map_size - old_map_size);
      memset(afl->first_trace + old_map_size, 0, map_size - old_map_size);
      memset(afl->map_tmp_buf + old_map_size, 0, map_size - old_map_size);

    }

  }

  afl->argv = use_argv;
  afl->fsrv.trace_bits =
      afl_shm_init(&afl->shm, afl->fsrv.map_size, afl->non_instrumented_mode);

  if (!afl->non_instrumented_mode && !afl->fsrv.qemu_mode &&
      !afl->unicorn_mode && !afl->fsrv.frida_mode && !afl->fsrv.cs_mode &&
      !afl->afl_env.afl_skip_bin_check) {

    if (map_size <= DEFAULT_SHMEM_SIZE) {

      afl->fsrv.map_size = DEFAULT_SHMEM_SIZE;  // dummy temporary value
      char vbuf[16];
      snprintf(vbuf, sizeof(vbuf), "%u", DEFAULT_SHMEM_SIZE);
      setenv("AFL_MAP_SIZE", vbuf, 1);

    }

    u32 new_map_size = afl_fsrv_get_mapsize(
        &afl->fsrv, afl->argv, &afl->stop_soon, afl->afl_env.afl_debug_child);

    // only reinitialize if the map needs to be larger than what we have.
    if (map_size < new_map_size) {

      OKF("Re-initializing maps to %u bytes", new_map_size);

      u32 old_map_size = map_size;
      afl->virgin_bits = ck_realloc(afl->virgin_bits, new_map_size);
      afl->virgin_tmout = ck_realloc(afl->virgin_tmout, new_map_size);
      afl->virgin_crash = ck_realloc(afl->virgin_crash, new_map_size);
      afl->var_bytes = ck_realloc(afl->var_bytes, new_map_size);
      afl->top_rated =
          ck_realloc(afl->top_rated, new_map_size * sizeof(void *));
      afl->clean_trace = ck_realloc(afl->clean_trace, new_map_size);
      afl->clean_trace_custom =
          ck_realloc(afl->clean_trace_custom, new_map_size);
      afl->first_trace = ck_realloc(afl->first_trace, new_map_size);
      afl->map_tmp_buf = ck_realloc(afl->map_tmp_buf, new_map_size);

      if (old_map_size < new_map_size) {

        memset(afl->var_bytes + old_map_size, 0, new_map_size - old_map_size);
        memset(afl->top_rated + old_map_size, 0, new_map_size - old_map_size);
        memset(afl->clean_trace + old_map_size, 0, new_map_size - old_map_size);
        memset(afl->clean_trace_custom + old_map_size, 0,
               new_map_size - old_map_size);
        memset(afl->first_trace + old_map_size, 0, new_map_size - old_map_size);
        memset(afl->map_tmp_buf + old_map_size, 0, new_map_size - old_map_size);

      }

      afl_fsrv_kill(&afl->fsrv);
      afl_shm_deinit(&afl->shm);
      afl->fsrv.map_size = new_map_size;
      afl->fsrv.trace_bits =
          afl_shm_init(&afl->shm, new_map_size, afl->non_instrumented_mode);
      setenv("AFL_NO_AUTODICT", "1", 1);  // loaded already
      afl_fsrv_start(&afl->fsrv, afl->argv, &afl->stop_soon,
                     afl->afl_env.afl_debug_child);

      map_size = new_map_size;

    }

  }

  if (afl->cmplog_binary) {

    ACTF("Spawning cmplog forkserver");
    afl_fsrv_init_dup(&afl->cmplog_fsrv, &afl->fsrv);
    // TODO: this is semi-nice
    afl->cmplog_fsrv.trace_bits = afl->fsrv.trace_bits;
    afl->cmplog_fsrv.cs_mode = afl->fsrv.cs_mode;
    afl->cmplog_fsrv.qemu_mode = afl->fsrv.qemu_mode;
    afl->cmplog_fsrv.frida_mode = afl->fsrv.frida_mode;
    afl->cmplog_fsrv.cmplog_binary = afl->cmplog_binary;
    afl->cmplog_fsrv.target_path = afl->fsrv.target_path;
    afl->cmplog_fsrv.init_child_func = cmplog_exec_child;

    if ((map_size <= DEFAULT_SHMEM_SIZE ||
         afl->cmplog_fsrv.map_size < map_size) &&
        !afl->non_instrumented_mode && !afl->fsrv.qemu_mode &&
        !afl->fsrv.frida_mode && !afl->unicorn_mode && !afl->fsrv.cs_mode &&
        !afl->afl_env.afl_skip_bin_check) {

      afl->cmplog_fsrv.map_size = MAX(map_size, (u32)DEFAULT_SHMEM_SIZE);
      char vbuf[16];
      snprintf(vbuf, sizeof(vbuf), "%u", afl->cmplog_fsrv.map_size);
      setenv("AFL_MAP_SIZE", vbuf, 1);

    }

    u32 new_map_size =
        afl_fsrv_get_mapsize(&afl->cmplog_fsrv, afl->argv, &afl->stop_soon,
                             afl->afl_env.afl_debug_child);

    // only reinitialize when it needs to be larger
    if (map_size < new_map_size) {

      OKF("Re-initializing maps to %u bytes due cmplog", new_map_size);

      u32 old_map_size = map_size;
      afl->virgin_bits = ck_realloc(afl->virgin_bits, new_map_size);
      afl->virgin_tmout = ck_realloc(afl->virgin_tmout, new_map_size);
      afl->virgin_crash = ck_realloc(afl->virgin_crash, new_map_size);
      afl->var_bytes = ck_realloc(afl->var_bytes, new_map_size);
      afl->top_rated =
          ck_realloc(afl->top_rated, new_map_size * sizeof(void *));
      afl->clean_trace = ck_realloc(afl->clean_trace, new_map_size);
      afl->clean_trace_custom =
          ck_realloc(afl->clean_trace_custom, new_map_size);
      afl->first_trace = ck_realloc(afl->first_trace, new_map_size);
      afl->map_tmp_buf = ck_realloc(afl->map_tmp_buf, new_map_size);

      if (old_map_size < new_map_size) {

        memset(afl->var_bytes + old_map_size, 0, new_map_size - old_map_size);
        memset(afl->top_rated + old_map_size, 0, new_map_size - old_map_size);
        memset(afl->clean_trace + old_map_size, 0, new_map_size - old_map_size);
        memset(afl->clean_trace_custom + old_map_size, 0,
               new_map_size - old_map_size);
        memset(afl->first_trace + old_map_size, 0, new_map_size - old_map_size);
        memset(afl->map_tmp_buf + old_map_size, 0, new_map_size - old_map_size);

      }

      afl_fsrv_kill(&afl->fsrv);
      afl_fsrv_kill(&afl->cmplog_fsrv);
      afl_shm_deinit(&afl->shm);

      afl->cmplog_fsrv.map_size = new_map_size;  // non-cmplog stays the same
      map_size = new_map_size;

      setenv("AFL_NO_AUTODICT", "1", 1);  // loaded already
      afl->fsrv.trace_bits =
          afl_shm_init(&afl->shm, new_map_size, afl->non_instrumented_mode);
      afl->cmplog_fsrv.trace_bits = afl->fsrv.trace_bits;
      afl_fsrv_start(&afl->fsrv, afl->argv, &afl->stop_soon,
                     afl->afl_env.afl_debug_child);
      afl_fsrv_start(&afl->cmplog_fsrv, afl->argv, &afl->stop_soon,
                     afl->afl_env.afl_debug_child);

    }

    OKF("CMPLOG forkserver successfully started");

  }

  load_auto(afl);

  if (extras_dir_cnt) {

    for (u8 i = 0; i < extras_dir_cnt; i++) {

      load_extras(afl, extras_dir[i]);

    }

  }

  if (afl->fsrv.out_file && afl->fsrv.use_shmem_fuzz) {

    unlink(afl->fsrv.out_file);
    afl->fsrv.out_file = NULL;
    afl->fsrv.use_stdin = 0;
    close(afl->fsrv.out_fd);
    afl->fsrv.out_fd = -1;

    if (!afl->unicorn_mode && !afl->fsrv.use_stdin && !default_output) {

      WARNF(
          "You specified -f or @@ on the command line but the target harness "
          "specified fuzz cases via shmem, switching to shmem!");

    }

  }

  deunicode_extras(afl);
  dedup_extras(afl);
  if (afl->extras_cnt) { OKF("Loaded a total of %u extras.", afl->extras_cnt); }

  if (unlikely(fast_resume)) {

    u64 resume_start = get_cur_time_us();
    // if we get here then we should abort on errors
    ZLIBREAD(fr_fd, afl->virgin_bits, afl->fsrv.map_size, "virgin_bits");
    ZLIBREAD(fr_fd, afl->virgin_tmout, afl->fsrv.map_size, "virgin_tmout");
    ZLIBREAD(fr_fd, afl->virgin_crash, afl->fsrv.map_size, "virgin_crash");
    ZLIBREAD(fr_fd, afl->var_bytes, afl->fsrv.map_size, "var_bytes");

    u8                  res[1] = {0};
    u8                 *o_start = (u8 *)&(afl->queue_buf[0]->colorized);
    u8                 *o_end = (u8 *)&(afl->queue_buf[0]->mother);
    u32                 r = 8 + afl->fsrv.map_size * 4;
    u32                 q_len = o_end - o_start;
    u32                 m_len = (afl->fsrv.map_size >> 3);
    struct queue_entry *q;

    for (u32 i = 0; i < afl->queued_items; i++) {

      q = afl->queue_buf[i];
      ZLIBREAD(fr_fd, (u8 *)&(q->colorized), q_len, "queue data");
      ZLIBREAD(fr_fd, res, 1, "check map");
      if (res[0]) {

        q->trace_mini = ck_alloc(m_len);
        ZLIBREAD(fr_fd, q->trace_mini, m_len, "trace_mini");
        r += q_len + m_len + 1;

      } else {

        r += q_len + 1;

      }

      afl->total_bitmap_size += q->bitmap_size;
      ++afl->total_bitmap_entries;
      update_bitmap_score(afl, q);

      if (q->was_fuzzed) { --afl->pending_not_fuzzed; }

      if (q->disabled) {

        if (!q->was_fuzzed) { --afl->pending_not_fuzzed; }
        --afl->active_items;

      }

      if (q->var_behavior) { ++afl->queued_variable; }
      if (q->favored) {

        ++afl->queued_favored;
        if (!q->was_fuzzed) { ++afl->pending_favored; }

      }

    }

    u8 buf[4];
    if (NZLIBREAD(fr_fd, buf, 3) > 0) {

      FATAL("invalid trailing data in fastresume.bin");

    }

    OKF("Successfully loaded fastresume.bin (%u bytes)!", r);
    ZLIBCLOSE(fr_fd);
    afl->reinit_table = 1;
    update_calibration_time(afl, &resume_start);

  } else {

    // after we have the correct bitmap size we can read the bitmap -B option
    // and set the virgin maps
    if (afl->in_bitmap) {

      read_bitmap(afl->in_bitmap, afl->virgin_bits, afl->fsrv.map_size);

    } else {

      memset(afl->virgin_bits, 255, map_size);

    }

    memset(afl->virgin_tmout, 255, map_size);
    memset(afl->virgin_crash, 255, map_size);

    if (likely(!afl->afl_env.afl_no_startup_calibration)) {

      perform_dry_run(afl);

    } else {

      ACTF("Skipping initial seed calibration due option override!");
      usleep(1000);

    }

  }

  if (afl->q_testcase_max_cache_entries) {

    afl->q_testcase_cache =
        ck_alloc(afl->q_testcase_max_cache_entries * sizeof(size_t));
    if (!afl->q_testcase_cache) { PFATAL("malloc failed for cache entries"); }

  }

  cull_queue(afl);

  // ensure we have at least one seed that is not disabled.
  u32 entry, valid_seeds = 0;
  for (entry = 0; entry < afl->queued_items; ++entry)
    if (!afl->queue_buf[entry]->disabled) { ++valid_seeds; }

  if (!afl->pending_not_fuzzed || !valid_seeds) {

    FATAL("We need at least one valid input seed that does not crash!");

  }

  if (afl->timeout_given == 2) {  // -t ...+ option

    if (valid_seeds == 1) {

      WARNF(
          "Only one valid seed is present, auto-calculating the timeout is "
          "disabled!");
      afl->timeout_given = 1;

    } else {

      u64 max_ms = 0;

      for (entry = 0; entry < afl->queued_items; ++entry)
        if (!afl->queue_buf[entry]->disabled)
          if ((afl->queue_buf[entry]->exec_us / 1000) > max_ms)
            max_ms = afl->queue_buf[entry]->exec_us / 1000;

      // Add 20% as a safety margin, capped to exec_tmout given in -t option
      max_ms *= 1.2;
      if (max_ms > afl->fsrv.exec_tmout) max_ms = afl->fsrv.exec_tmout;

      // Ensure that there is a sensible timeout even for very fast binaries
      if (max_ms < 5) max_ms = 5;

      afl->fsrv.exec_tmout = max_ms;
      afl->timeout_given = 1;

    }

  }

  show_init_stats(afl);

  if (unlikely(afl->old_seed_selection)) seek_to = find_start_position(afl);

  afl->start_time = get_cur_time();
  if (afl->in_place_resume || afl->afl_env.afl_autoresume) {

    load_stats_file(afl);

  }

  if (!afl->non_instrumented_mode) { write_stats_file(afl, 0, 0, 0, 0); }
  maybe_update_plot_file(afl, 0, 0, 0);
  save_auto(afl);

  if (afl->stop_soon) { goto stop_fuzzing; }

  /* Woop woop woop */

  if (!afl->not_on_tty) {

    sleep(1);
    if (afl->stop_soon) { goto stop_fuzzing; }

  }

  // (void)nice(-20);  // does not improve the speed

  #ifdef INTROSPECTION
  u32 prev_saved_crashes = 0, prev_saved_tmouts = 0, stat_prev_queued_items = 0;
  #endif
  u32 prev_queued_items = 0, runs_in_current_cycle = (u32)-1;
  u8  skipped_fuzz;

  #ifdef INTROSPECTION
  char ifn[4096];
  snprintf(ifn, sizeof(ifn), "%s/introspection.txt", afl->out_dir);
  if ((afl->introspection_file = fopen(ifn, "w")) == NULL) {

    PFATAL("could not create '%s'", ifn);

  }

  setvbuf(afl->introspection_file, NULL, _IONBF, 0);
  OKF("Writing mutation introspection to '%s'", ifn);
  #endif

  // real start time, we reset, so this works correctly with -V
  afl->start_time = get_cur_time();

  while (likely(!afl->stop_soon)) {

    cull_queue(afl);

    if (unlikely((!afl->old_seed_selection &&
                  runs_in_current_cycle > afl->queued_items) ||
                 (afl->old_seed_selection && !afl->queue_cur))) {

      if (unlikely((afl->last_sync_cycle < afl->queue_cycle ||
                    (!afl->queue_cycle && afl->afl_env.afl_import_first)) &&
                   afl->sync_id)) {

        if (unlikely(!afl->queue_cycle && afl->afl_env.afl_import_first)) {

          OKF("Syncing queues from other fuzzer instances first ...");

        }

        sync_fuzzers(afl);

      }

      ++afl->queue_cycle;
      if (afl->afl_env.afl_no_ui) {

        ACTF("Entering queue cycle %llu\n", afl->queue_cycle);

      }

      runs_in_current_cycle = (u32)-1;
      afl->cur_skipped_items = 0;

      // 1st april fool joke - enable pizza mode
      // to not waste time on checking the date we only do this when the
      // queue is fully cycled.
      time_t     cursec = time(NULL);
      struct tm *curdate = localtime(&cursec);
      if (unlikely(!afl->afl_env.afl_pizza_mode)) {

        if (unlikely(curdate->tm_mon == 3 && curdate->tm_mday == 1)) {

          afl->pizza_is_served = 1;

        } else {

          afl->pizza_is_served = 0;

        }

      }

      if (unlikely(afl->old_seed_selection)) {

        afl->current_entry = 0;
        while (unlikely(afl->current_entry < afl->queued_items &&
                        afl->queue_buf[afl->current_entry]->disabled)) {

          ++afl->current_entry;

        }

        if (afl->current_entry >= afl->queued_items) { afl->current_entry = 0; }

        afl->queue_cur = afl->queue_buf[afl->current_entry];

        if (unlikely(seek_to)) {

          if (unlikely(seek_to >= afl->queued_items)) {

            // This should never happen.
            FATAL("BUG: seek_to location out of bounds!\n");

          }

          afl->current_entry = seek_to;
          afl->queue_cur = afl->queue_buf[seek_to];
          seek_to = 0;

        }

      }

      /* If we had a full queue cycle with no new finds, try
         recombination strategies next. */

      if (unlikely(afl->queued_items == prev_queued
                   /* FIXME TODO BUG: && (get_cur_time() - afl->start_time) >=
                      3600 */
                   )) {

        ++afl->cycles_wo_finds;

        if (afl->use_splicing) {

          if (unlikely(afl->shm.cmplog_mode &&
                       afl->cmplog_max_filesize < MAX_FILE)) {

            afl->cmplog_max_filesize <<= 4;

          }

          switch (afl->expand_havoc) {

            case 0:
              // this adds extra splicing mutation options to havoc mode
              afl->expand_havoc = 1;
              break;
            case 1:
              // add MOpt mutator
              /*
              if (afl->limit_time_sig == 0 && !afl->custom_only &&
                  !afl->python_only) {

                afl->limit_time_sig = -1;
                afl->limit_time_puppet = 0;

              }

              */
              afl->expand_havoc = 2;
              if (afl->cmplog_lvl && afl->cmplog_lvl < 2) afl->cmplog_lvl = 2;
              break;
            case 2:
              // increase havoc mutations per fuzz attempt
              afl->havoc_stack_pow2++;
              afl->expand_havoc = 3;
              break;
            case 3:
              // further increase havoc mutations per fuzz attempt
              afl->havoc_stack_pow2++;
              afl->expand_havoc = 4;
              break;
            case 4:
              afl->expand_havoc = 5;
              // if (afl->cmplog_lvl && afl->cmplog_lvl < 3) afl->cmplog_lvl =
              // 3;
              break;
            case 5:
              // nothing else currently
              break;

          }

        } else {

  #ifndef NO_SPLICING
          afl->use_splicing = 1;
  #else
          afl->use_splicing = 0;
  #endif

        }

      } else {

        afl->cycles_wo_finds = 0;

      }

  #ifdef INTROSPECTION
      {

        u64 cur_time = get_cur_time();
        fprintf(afl->introspection_file,
                "CYCLE cycle=%llu cycle_wo_finds=%llu time_wo_finds=%llu "
                "expand_havoc=%u queue=%u\n",
                afl->queue_cycle, afl->cycles_wo_finds,
                afl->longest_find_time > cur_time - afl->last_find_time
                    ? afl->longest_find_time / 1000
                    : ((afl->start_time == 0 || afl->last_find_time == 0)
                           ? 0
                           : (cur_time - afl->last_find_time) / 1000),
                afl->expand_havoc, afl->queued_items);

      }

  #endif

      if (afl->cycle_schedules) {

        /* we cannot mix non-AFLfast schedules with others */

        switch (afl->schedule) {

          case EXPLORE:
            afl->schedule = EXPLOIT;
            break;
          case EXPLOIT:
            afl->schedule = MMOPT;
            break;
          case MMOPT:
            afl->schedule = SEEK;
            break;
          case SEEK:
            afl->schedule = EXPLORE;
            break;
          case FAST:
            afl->schedule = COE;
            break;
          case COE:
            afl->schedule = LIN;
            break;
          case LIN:
            afl->schedule = QUAD;
            break;
          case QUAD:
            afl->schedule = RARE;
            break;
          case RARE:
            afl->schedule = FAST;
            break;

        }

        // we must recalculate the scores of all queue entries
        for (u32 i = 0; i < afl->queued_items; i++) {

          if (likely(!afl->queue_buf[i]->disabled)) {

            update_bitmap_score(afl, afl->queue_buf[i]);

          }

        }

      }

      prev_queued = afl->queued_items;

    }

    ++runs_in_current_cycle;

    do {

      if (likely(!afl->old_seed_selection)) {

        if (likely(afl->pending_favored && afl->smallest_favored >= 0)) {

          afl->current_entry = afl->smallest_favored;

          /*

                    } else {

                      for (s32 iter = afl->queued_items - 1; iter >= 0; --iter)
             {

                        if (unlikely(afl->queue_buf[iter]->favored &&
                                     !afl->queue_buf[iter]->was_fuzzed)) {

                          afl->current_entry = iter;
                          break;

                        }

                      }

          */

          afl->queue_cur = afl->queue_buf[afl->current_entry];

        } else {

          if (unlikely(prev_queued_items < afl->queued_items ||
                       afl->reinit_table)) {

            // we have new queue entries since the last run, recreate alias
            // table
            prev_queued_items = afl->queued_items;
            create_alias_table(afl);

          }

          do {

            afl->current_entry = select_next_queue_entry(afl);

          } while (unlikely(afl->current_entry >= afl->queued_items));

          afl->queue_cur = afl->queue_buf[afl->current_entry];

        }

      }

      skipped_fuzz = fuzz_one(afl);
  #ifdef INTROSPECTION
      ++afl->queue_cur->stats_selected;

      if (unlikely(skipped_fuzz)) {

        ++afl->queue_cur->stats_skipped;

      } else {

        if (unlikely(afl->queued_items > stat_prev_queued_items)) {

          afl->queue_cur->stats_finds +=
              afl->queued_items - stat_prev_queued_items;
          stat_prev_queued_items = afl->queued_items;

        }

        if (unlikely(afl->saved_crashes > prev_saved_crashes)) {

          afl->queue_cur->stats_crashes +=
              afl->saved_crashes - prev_saved_crashes;
          prev_saved_crashes = afl->saved_crashes;

        }

        if (unlikely(afl->saved_tmouts > prev_saved_tmouts)) {

          afl->queue_cur->stats_tmouts += afl->saved_tmouts - prev_saved_tmouts;
          prev_saved_tmouts = afl->saved_tmouts;

        }

      }

  #endif

      if (unlikely(!afl->stop_soon && exit_1)) { afl->stop_soon = 2; }

      if (unlikely(afl->old_seed_selection)) {

        while (++afl->current_entry < afl->queued_items &&
               afl->queue_buf[afl->current_entry]->disabled) {};
        if (unlikely(afl->current_entry >= afl->queued_items ||
                     afl->queue_buf[afl->current_entry] == NULL ||
                     afl->queue_buf[afl->current_entry]->disabled)) {

          afl->queue_cur = NULL;

        } else {

          afl->queue_cur = afl->queue_buf[afl->current_entry];

        }

      }

    } while (skipped_fuzz && afl->queue_cur && !afl->stop_soon);

    u64 cur_time = get_cur_time();

    if (likely(afl->switch_fuzz_mode && afl->fuzz_mode == 0 &&
               !afl->non_instrumented_mode) &&
        unlikely(cur_time > (likely(afl->last_find_time) ? afl->last_find_time
                                                         : afl->start_time) +
                                afl->switch_fuzz_mode)) {

      if (afl->afl_env.afl_no_ui) {

        ACTF(
            "No new coverage found for %llu seconds, switching to exploitation "
            "strategy.",
            afl->switch_fuzz_mode / 1000);

      }

      afl->fuzz_mode = 1;

    }

    if (likely(!afl->stop_soon && afl->sync_id)) {

      if (unlikely(afl->is_main_node)) {

        if (unlikely(cur_time > (afl->sync_time >> 1) + afl->last_sync_time)) {

          if (!(sync_interval_cnt++ % (SYNC_INTERVAL / 3))) {

            sync_fuzzers(afl);

          }

        }

      } else {

        if (unlikely(cur_time > afl->sync_time + afl->last_sync_time)) {

          if (!(sync_interval_cnt++ % SYNC_INTERVAL)) { sync_fuzzers(afl); }

        }

      }

    }

  }

stop_fuzzing:

  afl->force_ui_update = 1;  // ensure the screen is reprinted
  afl->stop_soon = 1;        // ensure everything is written
  show_stats(afl);           // print the screen one last time
  write_bitmap(afl);
  save_auto(afl);

  #ifdef __AFL_CODE_COVERAGE
  if (afl->fsrv.persistent_trace_bits) {

    char cfn[4096];
    snprintf(cfn, sizeof(cfn), "%s/covmap.dump", afl->out_dir);

    FILE *cov_fd;
    if ((cov_fd = fopen(cfn, "w")) == NULL) {

      PFATAL("could not create '%s'", cfn);

    }

    // Write the real map size, as the map size must exactly match the pointer
    // map in length.
    fwrite(afl->fsrv.persistent_trace_bits, 1, afl->fsrv.real_map_size, cov_fd);
    fclose(cov_fd);

  }

  #endif

  if (afl->pizza_is_served) {

    SAYF(CURSOR_SHOW cLRD "\n\n+++ Baking aborted %s +++\n" cRST,
         afl->stop_soon == 2 ? "programmatically" : "by the chef");

  } else {

    SAYF(CURSOR_SHOW cLRD "\n\n+++ Testing aborted %s +++\n" cRST,
         afl->stop_soon == 2 ? "programmatically" : "by user");

  }

  if (afl->most_time_key == 2) {

    SAYF(cYEL "[!] " cRST "Time limit was reached\n");

  }

  if (afl->most_execs_key == 2) {

    SAYF(cYEL "[!] " cRST "Execution limit was reached\n");

  }

  /* Running for more than 30 minutes but still doing first cycle? */

  if (afl->queue_cycle == 1 &&
      get_cur_time() - afl->start_time > 30 * 60 * 1000) {

    SAYF("\n" cYEL "[!] " cRST
         "Stopped during the first cycle, results may be incomplete.\n"
         "    (For info on resuming, see %s/README.md)\n",
         doc_path);

  }

  if (afl->not_on_tty) {

    u32 t_bytes = count_non_255_bytes(afl, afl->virgin_bits);
    u8  time_tmp[64];
    u_stringify_time_diff(time_tmp, get_cur_time(), afl->start_time);
    ACTF(
        "Statistics: %u new corpus items found, %.02f%% coverage achieved, "
        "%llu crashes saved, %llu timeouts saved, total runtime %s",
        afl->queued_discovered,
        ((double)t_bytes * 100) / afl->fsrv.real_map_size, afl->saved_crashes,
        afl->saved_hangs, time_tmp);

  }

  #ifdef PROFILING
  SAYF(cYEL "[!] " cRST
            "Profiling information: %llu ms total work, %llu ns/run\n",
       time_spent_working / 1000000,
       time_spent_working / afl->fsrv.total_execs);
  #endif

  if (afl->afl_env.afl_final_sync) {

    SAYF(cYEL "[!] " cRST
              "\nPerforming final sync, this make take some time ...\n");
    sync_fuzzers(afl);
    write_bitmap(afl);
    SAYF(cYEL "[!] " cRST "Done!\n\n");

  }

  if (afl->is_main_node) {

    u8 path[PATH_MAX];
    sprintf(path, "%s/is_main_node", afl->out_dir);
    unlink(path);

  }

  if (frida_afl_preload) { ck_free(frida_afl_preload); }

  fclose(afl->fsrv.plot_file);

  #ifdef INTROSPECTION
  fclose(afl->fsrv.det_plot_file);
  #endif

  if (!afl->afl_env.afl_no_fastresume) {

    /* create fastresume.bin */
    u8 fr[PATH_MAX];
    snprintf(fr, PATH_MAX, "%s/fastresume.bin", afl->out_dir);
    ACTF("Writing %s ...", fr);
  #ifdef HAVE_ZLIB
    if ((fr_fd = ZLIBOPEN(fr, "wb9")) != NULL) {

  #else
    if ((fr_fd = open(fr, O_WRONLY | O_TRUNC | O_CREAT, DEFAULT_PERMISSION)) >=
        0) {

  #endif

      u8   ver_string[8];
      u32  w = 0;
      u64 *ver = (u64 *)ver_string;
      *ver = afl->shm.cmplog_mode + (sizeof(struct queue_entry) << 1);

      ZLIBWRITE(fr_fd, ver_string, sizeof(ver_string), "ver_string");
      ZLIBWRITE(fr_fd, afl->virgin_bits, afl->fsrv.map_size, "virgin_bits");
      ZLIBWRITE(fr_fd, afl->virgin_tmout, afl->fsrv.map_size, "virgin_tmout");
      ZLIBWRITE(fr_fd, afl->virgin_crash, afl->fsrv.map_size, "virgin_crash");
      ZLIBWRITE(fr_fd, afl->var_bytes, afl->fsrv.map_size, "var_bytes");
      w += sizeof(ver_string) + afl->fsrv.map_size * 4;

      u8                  on[1] = {1}, off[1] = {0};
      u8                 *o_start = (u8 *)&(afl->queue_buf[0]->colorized);
      u8                 *o_end = (u8 *)&(afl->queue_buf[0]->mother);
      u32                 q_len = o_end - o_start;
      u32                 m_len = (afl->fsrv.map_size >> 3);
      struct queue_entry *q;

      afl->pending_not_fuzzed = afl->queued_items;
      afl->active_items = afl->queued_items;

      for (u32 i = 0; i < afl->queued_items; i++) {

        q = afl->queue_buf[i];
        ZLIBWRITE(fr_fd, (u8 *)&(q->colorized), q_len, "queue data");
        if (!q->trace_mini) {

          ZLIBWRITE(fr_fd, off, 1, "no_mini");
          w += q_len + 1;

        } else {

          ZLIBWRITE(fr_fd, on, 1, "yes_mini");
          ZLIBWRITE(fr_fd, q->trace_mini, m_len, "trace_mini");
          w += q_len + m_len + 1;

        }

      }

      ZLIBCLOSE(fr_fd);
      afl->var_byte_count = count_bytes(afl, afl->var_bytes);
      OKF("Written fastresume.bin with %u bytes!", w);

    } else {

      WARNF("Could not create fastresume.bin");

    }

  }

  destroy_queue(afl);
  destroy_extras(afl);
  destroy_custom_mutators(afl);
  afl_shm_deinit(&afl->shm);

  if (afl->shm_fuzz) {

    afl_shm_deinit(afl->shm_fuzz);
    ck_free(afl->shm_fuzz);

  }

  afl_fsrv_deinit(&afl->fsrv);

  /* remove tmpfile */
  if (!afl->in_place_resume && afl->fsrv.out_file) {

    (void)unlink(afl->fsrv.out_file);

  }

  if (afl->orig_cmdline) { ck_free(afl->orig_cmdline); }
  ck_free(afl->fsrv.target_path);
  ck_free(afl->fsrv.out_file);
  ck_free(afl->sync_id);
  if (afl->q_testcase_cache) { ck_free(afl->q_testcase_cache); }
  afl_state_deinit(afl);
  free(afl);                                                 /* not tracked */

  argv_cpy_free(argv);

  alloc_report();

  OKF("We're done here. Have a nice day!\n");

  exit(0);

}

#endif                                                          /* !AFL_LIB */

