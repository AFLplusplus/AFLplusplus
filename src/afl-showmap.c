/*
   american fuzzy lop++ - map display utility
   ------------------------------------------

   Originally written by Michal Zalewski

   Forkserver design by Jann Horn <jannhorn@googlemail.com>

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eißfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com> and
                        Dominik Maier <mail@dmnk.co>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   A very simple tool that runs the targeted binary and displays
   the contents of the trace bitmap in a human-readable form. Useful in
   scripts to eliminate redundant inputs and perform other checks.

   Exit code is 2 if the target program crashes; 1 if it times out or
   there is a problem executing it; or 0 if execution is successful.

 */

#define AFL_MAIN

#include "config.h"
#include "types.h"
#include "debug.h"
#include "alloc-inl.h"
#include "hash.h"
#include "sharedmem.h"
#include "forkserver.h"
#include "common.h"
#include "hash.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>

#include <sys/wait.h>
#include <sys/time.h>
#ifndef USEMMAP
  #include <sys/shm.h>
#endif
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>

static char *stdin_file;               /* stdin file                        */

static u8 *in_dir = NULL,              /* input folder                      */
    *out_file = NULL, *at_file = NULL;        /* Substitution string for @@ */

static u8 *in_data,                    /* Input data                        */
    *coverage_map;                     /* Coverage map                      */

static u64 total;                      /* tuple content information         */
static u32 tcnt, highest;              /* tuple content information         */

static u32 in_len,                     /* Input data length                 */
    arg_offset;                        /* Total number of execs             */

static u32 map_size = MAP_SIZE;

static u8 quiet_mode,                  /* Hide non-essential messages?      */
    edges_only,                        /* Ignore hit counts?                */
    raw_instr_output,                  /* Do not apply AFL filters          */
    cmin_mode,                         /* Generate output in afl-cmin mode? */
    binary_mode,                       /* Write output as a binary map      */
    keep_cores,                        /* Allow coredumps?                  */
    remove_shm = 1,                    /* remove shmem?                     */
    collect_coverage,                  /* collect coverage                  */
    have_coverage,                     /* have coverage?                    */
    no_classify,                       /* do not classify counts            */
    debug;                             /* debug mode                        */

static volatile u8 stop_soon,          /* Ctrl-C pressed?                   */
    child_crashed;                     /* Child crashed?                    */

static sharedmem_t       shm;
static afl_forkserver_t *fsrv;
static sharedmem_t *     shm_fuzz;

/* Classify tuple counts. Instead of mapping to individual bits, as in
   afl-fuzz.c, we map to more user-friendly numbers between 1 and 8. */

#define TIMES4(x) x, x, x, x
#define TIMES8(x) TIMES4(x), TIMES4(x)
#define TIMES16(x) TIMES8(x), TIMES8(x)
#define TIMES32(x) TIMES16(x), TIMES16(x)
#define TIMES64(x) TIMES32(x), TIMES32(x)
#define TIMES96(x) TIMES64(x), TIMES32(x)
#define TIMES128(x) TIMES64(x), TIMES64(x)
static const u8 count_class_human[256] = {

    [0] = 0,
    [1] = 1,
    [2] = 2,
    [3] = 3,
    [4] = TIMES4(4),
    [8] = TIMES8(5),
    [16] = TIMES16(6),
    [32] = TIMES96(7),
    [128] = TIMES128(8)

};

static const u8 count_class_binary[256] = {

    [0] = 0,
    [1] = 1,
    [2] = 2,
    [3] = 4,
    [4] = TIMES4(8),
    [8] = TIMES8(16),
    [16] = TIMES16(32),
    [32] = TIMES32(64),
    [128] = TIMES64(128)

};

#undef TIMES128
#undef TIMES96
#undef TIMES64
#undef TIMES32
#undef TIMES16
#undef TIMES8
#undef TIMES4

static void classify_counts(afl_forkserver_t *fsrv) {

  u8 *      mem = fsrv->trace_bits;
  const u8 *map = binary_mode ? count_class_binary : count_class_human;

  u32 i = map_size;

  if (edges_only) {

    while (i--) {

      if (*mem) { *mem = 1; }
      mem++;

    }

  } else if (!raw_instr_output) {

    while (i--) {

      *mem = map[*mem];
      mem++;

    }

  }

}

static sharedmem_t *deinit_shmem(afl_forkserver_t *fsrv,
                                 sharedmem_t *     shm_fuzz) {

  afl_shm_deinit(shm_fuzz);
  fsrv->support_shmem_fuzz = 0;
  fsrv->shmem_fuzz_len = NULL;
  fsrv->shmem_fuzz = NULL;
  ck_free(shm_fuzz);
  return NULL;

}

/* Get rid of temp files (atexit handler). */

static void at_exit_handler(void) {

  if (stdin_file) { unlink(stdin_file); }

  if (remove_shm) {

    if (shm.map) afl_shm_deinit(&shm);
    if (fsrv->use_shmem_fuzz) deinit_shmem(fsrv, shm_fuzz);

  }

  afl_fsrv_killall();

}

/* Analyze results. */

static void analyze_results(afl_forkserver_t *fsrv) {

  u32 i;
  for (i = 0; i < map_size; i++) {

    if (fsrv->trace_bits[i]) {

      total += fsrv->trace_bits[i];
      if (fsrv->trace_bits[i] > highest) highest = fsrv->trace_bits[i];
      if (!coverage_map[i]) { coverage_map[i] = 1; }

    }

  }

}

/* Write results. */

static u32 write_results_to_file(afl_forkserver_t *fsrv, u8 *outfile) {

  s32 fd;
  u32 i, ret = 0;

  u8 cco = !!getenv("AFL_CMIN_CRASHES_ONLY"),
     caa = !!getenv("AFL_CMIN_ALLOW_ANY");

  if (!outfile) { FATAL("Output filename not set (Bug in AFL++?)"); }

  if (cmin_mode &&
      (fsrv->last_run_timed_out || (!caa && child_crashed != cco))) {

    return ret;

  }

  if (!strncmp(outfile, "/dev/", 5)) {

    fd = open(outfile, O_WRONLY);

    if (fd < 0) { PFATAL("Unable to open '%s'", out_file); }

  } else if (!strcmp(outfile, "-")) {

    fd = dup(1);
    if (fd < 0) { PFATAL("Unable to open stdout"); }

  } else {

    unlink(outfile);                                       /* Ignore errors */
    fd = open(outfile, O_WRONLY | O_CREAT | O_EXCL, DEFAULT_PERMISSION);
    if (fd < 0) { PFATAL("Unable to create '%s'", outfile); }

  }

  if (binary_mode) {

    for (i = 0; i < map_size; i++) {

      if (fsrv->trace_bits[i]) { ret++; }

    }

    ck_write(fd, fsrv->trace_bits, map_size, outfile);
    close(fd);

  } else {

    FILE *f = fdopen(fd, "w");

    if (!f) { PFATAL("fdopen() failed"); }

    for (i = 0; i < map_size; i++) {

      if (!fsrv->trace_bits[i]) { continue; }
      ret++;

      total += fsrv->trace_bits[i];
      if (highest < fsrv->trace_bits[i]) { highest = fsrv->trace_bits[i]; }

      if (cmin_mode) {

        fprintf(f, "%u%u\n", fsrv->trace_bits[i], i);

      } else {

        fprintf(f, "%06u:%u\n", i, fsrv->trace_bits[i]);

      }

    }

    fclose(f);

  }

  return ret;

}

/* Execute target application. */

static void showmap_run_target_forkserver(afl_forkserver_t *fsrv, u8 *mem,
                                          u32 len) {

  afl_fsrv_write_to_testcase(fsrv, mem, len);

  if (!quiet_mode) { SAYF("-- Program output begins --\n" cRST); }

  if (afl_fsrv_run_target(fsrv, fsrv->exec_tmout, &stop_soon) ==
      FSRV_RUN_ERROR) {

    FATAL("Error running target");

  }

  if (fsrv->trace_bits[0] == 1) {

    fsrv->trace_bits[0] = 0;
    have_coverage = 1;

  } else {

    have_coverage = 0;

  }

  if (!no_classify) { classify_counts(fsrv); }

  if (!quiet_mode) { SAYF(cRST "-- Program output ends --\n"); }

  if (!fsrv->last_run_timed_out && !stop_soon &&
      WIFSIGNALED(fsrv->child_status)) {

    child_crashed = 1;

  } else {

    child_crashed = 0;

  }

  if (!quiet_mode) {

    if (fsrv->last_run_timed_out) {

      SAYF(cLRD "\n+++ Program timed off +++\n" cRST);

    } else if (stop_soon) {

      SAYF(cLRD "\n+++ Program aborted by user +++\n" cRST);

    } else if (child_crashed) {

      SAYF(cLRD "\n+++ Program killed by signal %u +++\n" cRST,
           WTERMSIG(fsrv->child_status));

    }

  }

  if (stop_soon) {

    SAYF(cRST cLRD "\n+++ afl-showmap folder mode aborted by user +++\n" cRST);
    exit(1);

  }

}

/* Read initial file. */

static u32 read_file(u8 *in_file) {

  struct stat st;
  s32         fd = open(in_file, O_RDONLY);

  if (fd < 0) { WARNF("Unable to open '%s'", in_file); }

  if (fstat(fd, &st) || !st.st_size) {

    WARNF("Zero-sized input file '%s'.", in_file);

  }

  in_len = st.st_size;
  in_data = ck_alloc_nozero(in_len);

  ck_read(fd, in_data, in_len, in_file);

  close(fd);

  // OKF("Read %u byte%s from '%s'.", in_len, in_len == 1 ? "" : "s", in_file);

  return in_len;

}

/* Execute target application. */

static void showmap_run_target(afl_forkserver_t *fsrv, char **argv) {

  static struct itimerval it;
  int                     status = 0;

  if (!quiet_mode) { SAYF("-- Program output begins --\n" cRST); }

  MEM_BARRIER();

  fsrv->child_pid = fork();

  if (fsrv->child_pid < 0) { PFATAL("fork() failed"); }

  if (!fsrv->child_pid) {

    struct rlimit r;

    if (quiet_mode) {

      s32 fd = open("/dev/null", O_RDWR);

      if (fd < 0 || dup2(fd, 1) < 0 || dup2(fd, 2) < 0) {

        *(u32 *)fsrv->trace_bits = EXEC_FAIL_SIG;
        PFATAL("Descriptor initialization failed");

      }

      close(fd);

    }

    if (fsrv->mem_limit) {

      r.rlim_max = r.rlim_cur = ((rlim_t)fsrv->mem_limit) << 20;

#ifdef RLIMIT_AS

      setrlimit(RLIMIT_AS, &r);                            /* Ignore errors */

#else

      setrlimit(RLIMIT_DATA, &r);                          /* Ignore errors */

#endif                                                        /* ^RLIMIT_AS */

    }

    if (!keep_cores) {

      r.rlim_max = r.rlim_cur = 0;

    } else {

      r.rlim_max = r.rlim_cur = RLIM_INFINITY;

    }

    setrlimit(RLIMIT_CORE, &r);                            /* Ignore errors */

    if (!getenv("LD_BIND_LAZY")) { setenv("LD_BIND_NOW", "1", 0); }

    setsid();

    execv(fsrv->target_path, argv);

    *(u32 *)fsrv->trace_bits = EXEC_FAIL_SIG;
    exit(0);

  }

  /* Configure timeout, wait for child, cancel timeout. */

  if (fsrv->exec_tmout) {

    fsrv->last_run_timed_out = 0;
    it.it_value.tv_sec = (fsrv->exec_tmout / 1000);
    it.it_value.tv_usec = (fsrv->exec_tmout % 1000) * 1000;

  }

  setitimer(ITIMER_REAL, &it, NULL);

  if (waitpid(fsrv->child_pid, &status, 0) <= 0) { FATAL("waitpid() failed"); }

  fsrv->child_pid = 0;
  it.it_value.tv_sec = 0;
  it.it_value.tv_usec = 0;
  setitimer(ITIMER_REAL, &it, NULL);

  MEM_BARRIER();

  /* Clean up bitmap, analyze exit condition, etc. */

  if (*(u32 *)fsrv->trace_bits == EXEC_FAIL_SIG) {

    FATAL("Unable to execute '%s'", argv[0]);

  }

  if (fsrv->trace_bits[0] == 1) {

    fsrv->trace_bits[0] = 0;
    have_coverage = 1;

  } else {

    have_coverage = 0;

  }

  if (!no_classify) { classify_counts(fsrv); }

  if (!quiet_mode) { SAYF(cRST "-- Program output ends --\n"); }

  if (!fsrv->last_run_timed_out && !stop_soon && WIFSIGNALED(status)) {

    child_crashed = 1;

  }

  if (!quiet_mode) {

    if (fsrv->last_run_timed_out) {

      SAYF(cLRD "\n+++ Program timed off +++\n" cRST);

    } else if (stop_soon) {

      SAYF(cLRD "\n+++ Program aborted by user +++\n" cRST);

    } else if (child_crashed) {

      SAYF(cLRD "\n+++ Program killed by signal %u +++\n" cRST,
           WTERMSIG(status));

    }

  }

}

/* Handle Ctrl-C and the like. */

static void handle_stop_sig(int sig) {

  (void)sig;
  stop_soon = 1;
  afl_fsrv_killall();

}

/* Do basic preparations - persistent fds, filenames, etc. */

static void set_up_environment(afl_forkserver_t *fsrv) {

  setenv("ASAN_OPTIONS",
         "abort_on_error=1:"
         "detect_leaks=0:"
         "allocator_may_return_null=1:"
         "symbolize=0:"
         "detect_odr_violation=0:"
         "handle_segv=0:"
         "handle_sigbus=0:"
         "handle_abort=0:"
         "handle_sigfpe=0:"
         "handle_sigill=0",
         0);

  setenv("UBSAN_OPTIONS",
         "halt_on_error=1:"
         "abort_on_error=1:"
         "malloc_context_size=0:"
         "allocator_may_return_null=1:"
         "symbolize=0:"
         "handle_segv=0:"
         "handle_sigbus=0:"
         "handle_abort=0:"
         "handle_sigfpe=0:"
         "handle_sigill=0",
         0);

  setenv("MSAN_OPTIONS", "exit_code=" STRINGIFY(MSAN_ERROR) ":"
                         "abort_on_error=1:"
                         "msan_track_origins=0"
                         "allocator_may_return_null=1:"
                         "symbolize=0:"
                         "handle_segv=0:"
                         "handle_sigbus=0:"
                         "handle_abort=0:"
                         "handle_sigfpe=0:"
                         "handle_sigill=0", 0);

  if (get_afl_env("AFL_PRELOAD")) {

    if (fsrv->qemu_mode) {

      /* afl-qemu-trace takes care of converting AFL_PRELOAD. */

    } else {

      setenv("LD_PRELOAD", getenv("AFL_PRELOAD"), 1);
      setenv("DYLD_INSERT_LIBRARIES", getenv("AFL_PRELOAD"), 1);

    }

  }

}

/* Setup signal handlers, duh. */

static void setup_signal_handlers(void) {

  struct sigaction sa;

  sa.sa_handler = NULL;
  sa.sa_flags = SA_RESTART;
  sa.sa_sigaction = NULL;

  sigemptyset(&sa.sa_mask);

  /* Various ways of saying "stop". */

  sa.sa_handler = handle_stop_sig;
  sigaction(SIGHUP, &sa, NULL);
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);

}

/* Show banner. */

static void show_banner(void) {

  SAYF(cCYA "afl-showmap" VERSION cRST " by Michal Zalewski\n");

}

/* Display usage hints. */

static void usage(u8 *argv0) {

  show_banner();

  SAYF(
      "\n%s [ options ] -- /path/to/target_app [ ... ]\n\n"

      "Required parameters:\n"
      "  -o file       - file to write the trace data to\n\n"

      "Execution control settings:\n"
      "  -t msec       - timeout for each run (none)\n"
      "  -m megs       - memory limit for child process (%u MB)\n"
      "  -Q            - use binary-only instrumentation (QEMU mode)\n"
      "  -U            - use Unicorn-based instrumentation (Unicorn mode)\n"
      "  -W            - use qemu-based instrumentation with Wine (Wine mode)\n"
      "                  (Not necessary, here for consistency with other afl-* "
      "tools)\n\n"
      "Other settings:\n"
      "  -i dir        - process all files in this directory, must be combined "
      "with -o.\n"
      "                  With -C, -o is a file, without -C it must be a "
      "directory\n"
      "                  and each bitmap will be written there individually.\n"
      "  -C            - collect coverage, writes all edges to -o and gives a "
      "summary\n"
      "                  Must be combined with -i.\n"
      "  -q            - sink program's output and don't show messages\n"
      "  -e            - show edge coverage only, ignore hit counts\n"
      "  -r            - show real tuple values instead of AFL filter values\n"
      "  -s            - do not classify the map\n"
      "  -c            - allow core dumps\n\n"

      "This tool displays raw tuple data captured by AFL instrumentation.\n"
      "For additional help, consult %s/README.md.\n\n"

      "Environment variables used:\n"
      "LD_BIND_LAZY: do not set LD_BIND_NOW env var for target\n"
      "AFL_CMIN_CRASHES_ONLY: (cmin_mode) only write tuples for crashing "
      "inputs\n"
      "AFL_CMIN_ALLOW_ANY: (cmin_mode) write tuples for crashing inputs also\n"
      "AFL_CRASH_EXITCODE: optional child exit code to be interpreted as "
      "crash\n"
      "AFL_DEBUG: enable extra developer output\n"
      "AFL_FORKSRV_INIT_TMOUT: time spent waiting for forkserver during "
      "startup (in milliseconds)\n"
      "AFL_KILL_SIGNAL: Signal ID delivered to child processes on timeout, "
      "etc. (default: SIGKILL)\n"
      "AFL_MAP_SIZE: the shared memory size for that target. must be >= the "
      "size the target was compiled for\n"
      "AFL_PRELOAD: LD_PRELOAD / DYLD_INSERT_LIBRARIES settings for target\n"
      "AFL_QUIET: do not print extra informational output\n",
      argv0, MEM_LIMIT, doc_path);

  exit(1);

}

/* Main entry point */

int main(int argc, char **argv_orig, char **envp) {

  // TODO: u64 mem_limit = MEM_LIMIT;                  /* Memory limit (MB) */

  s32    opt, i;
  u8     mem_limit_given = 0, timeout_given = 0, unicorn_mode = 0, use_wine = 0;
  char **use_argv;

  char **argv = argv_cpy_dup(argc, argv_orig);

  afl_forkserver_t fsrv_var = {0};
  if (getenv("AFL_DEBUG")) { debug = 1; }
  fsrv = &fsrv_var;
  afl_fsrv_init(fsrv);
  map_size = get_map_size();
  fsrv->map_size = map_size;

  doc_path = access(DOC_PATH, F_OK) ? "docs" : DOC_PATH;

  if (getenv("AFL_QUIET") != NULL) { be_quiet = 1; }

  while ((opt = getopt(argc, argv, "+i:o:f:m:t:A:eqCZQUWbcrsh")) > 0) {

    switch (opt) {

      case 's':
        no_classify = 1;
        break;

      case 'C':
        collect_coverage = 1;
        quiet_mode = 1;
        break;

      case 'i':
        if (in_dir) { FATAL("Multiple -i options not supported"); }
        in_dir = optarg;
        break;

      case 'o':

        if (out_file) { FATAL("Multiple -o options not supported"); }
        out_file = optarg;
        break;

      case 'm': {

        u8 suffix = 'M';

        if (mem_limit_given) { FATAL("Multiple -m options not supported"); }
        mem_limit_given = 1;

        if (!optarg) { FATAL("Wrong usage of -m"); }

        if (!strcmp(optarg, "none")) {

          fsrv->mem_limit = 0;
          break;

        }

        if (sscanf(optarg, "%llu%c", &fsrv->mem_limit, &suffix) < 1 ||
            optarg[0] == '-') {

          FATAL("Bad syntax used for -m");

        }

        switch (suffix) {

          case 'T':
            fsrv->mem_limit *= 1024 * 1024;
            break;
          case 'G':
            fsrv->mem_limit *= 1024;
            break;
          case 'k':
            fsrv->mem_limit /= 1024;
            break;
          case 'M':
            break;

          default:
            FATAL("Unsupported suffix or bad syntax for -m");

        }

        if (fsrv->mem_limit < 5) { FATAL("Dangerously low value of -m"); }

        if (sizeof(rlim_t) == 4 && fsrv->mem_limit > 2000) {

          FATAL("Value of -m out of range on 32-bit systems");

        }

      }

      break;

      case 'f':  // only in here to avoid a compiler warning for use_stdin

        FATAL("Option -f is not supported in afl-showmap");
        // currently not reached:
        fsrv->use_stdin = 0;
        fsrv->out_file = strdup(optarg);

        break;

      case 't':

        if (timeout_given) { FATAL("Multiple -t options not supported"); }
        timeout_given = 1;

        if (!optarg) { FATAL("Wrong usage of -t"); }

        if (strcmp(optarg, "none")) {

          fsrv->exec_tmout = atoi(optarg);

          if (fsrv->exec_tmout < 20 || optarg[0] == '-') {

            FATAL("Dangerously low value of -t");

          }

        }

        break;

      case 'e':

        if (edges_only) { FATAL("Multiple -e options not supported"); }
        if (raw_instr_output) { FATAL("-e and -r are mutually exclusive"); }
        edges_only = 1;
        break;

      case 'q':

        quiet_mode = 1;
        break;

      case 'Z':

        /* This is an undocumented option to write data in the syntax expected
           by afl-cmin. Nobody else should have any use for this. */

        cmin_mode = 1;
        quiet_mode = 1;
        break;

      case 'A':
        /* Another afl-cmin specific feature. */
        at_file = optarg;
        break;

      case 'Q':

        if (fsrv->qemu_mode) { FATAL("Multiple -Q options not supported"); }

        fsrv->qemu_mode = 1;
        break;

      case 'U':

        if (unicorn_mode) { FATAL("Multiple -U options not supported"); }

        unicorn_mode = 1;
        break;

      case 'W':                                           /* Wine+QEMU mode */

        if (use_wine) { FATAL("Multiple -W options not supported"); }
        fsrv->qemu_mode = 1;
        use_wine = 1;

        break;

      case 'b':

        /* Secret undocumented mode. Writes output in raw binary format
           similar to that dumped by afl-fuzz in <out_dir/queue/fuzz_bitmap. */

        binary_mode = 1;
        break;

      case 'c':

        if (keep_cores) { FATAL("Multiple -c options not supported"); }
        keep_cores = 1;
        break;

      case 'r':

        if (raw_instr_output) { FATAL("Multiple -r options not supported"); }
        if (edges_only) { FATAL("-e and -r are mutually exclusive"); }
        raw_instr_output = 1;
        break;

      case 'h':
        usage(argv[0]);
        return -1;
        break;

      default:
        usage(argv[0]);

    }

  }

  if (optind == argc || !out_file) { usage(argv[0]); }

  if (in_dir) {

    if (!out_file && !collect_coverage)
      FATAL("for -i you need to specify either -C and/or -o");

  }

  if (fsrv->qemu_mode && !mem_limit_given) { fsrv->mem_limit = MEM_LIMIT_QEMU; }
  if (unicorn_mode && !mem_limit_given) { fsrv->mem_limit = MEM_LIMIT_UNICORN; }

  check_environment_vars(envp);

  if (getenv("AFL_DEBUG")) {

    DEBUGF("");
    for (i = 0; i < argc; i++)
      SAYF(" %s", argv[i]);
    SAYF("\n");

  }

  //  if (afl->shmem_testcase_mode) { setup_testcase_shmem(afl); }

  setenv("AFL_NO_AUTODICT", "1", 1);

  /* initialize cmplog_mode */
  shm.cmplog_mode = 0;
  setup_signal_handlers();

  set_up_environment(fsrv);

  fsrv->target_path = find_binary(argv[optind]);
  fsrv->trace_bits = afl_shm_init(&shm, map_size, 0);

  if (!quiet_mode) {

    show_banner();
    ACTF("Executing '%s'...", fsrv->target_path);

  }

  if (in_dir) {

    detect_file_args(argv + optind, "", &fsrv->use_stdin);

  } else {

    detect_file_args(argv + optind, at_file, &fsrv->use_stdin);

  }

  if (fsrv->qemu_mode) {

    if (use_wine) {

      use_argv = get_wine_argv(argv[0], &fsrv->target_path, argc - optind,
                               argv + optind);

    } else {

      use_argv = get_qemu_argv(argv[0], &fsrv->target_path, argc - optind,
                               argv + optind);

    }

  } else {

    use_argv = argv + optind;

  }

  i = 0;
  while (use_argv[i] != NULL && !arg_offset) {

    if (strcmp(use_argv[i], "@@") == 0) { arg_offset = i; }
    i++;

  }

  shm_fuzz = ck_alloc(sizeof(sharedmem_t));

  /* initialize cmplog_mode */
  shm_fuzz->cmplog_mode = 0;
  u8 *map = afl_shm_init(shm_fuzz, MAX_FILE + sizeof(u32), 1);
  shm_fuzz->shmemfuzz_mode = 1;
  if (!map) { FATAL("BUG: Zero return from afl_shm_init."); }
#ifdef USEMMAP
  setenv(SHM_FUZZ_ENV_VAR, shm_fuzz->g_shm_file_path, 1);
#else
  u8 *shm_str = alloc_printf("%d", shm_fuzz->shm_id);
  setenv(SHM_FUZZ_ENV_VAR, shm_str, 1);
  ck_free(shm_str);
#endif
  fsrv->support_shmem_fuzz = 1;
  fsrv->shmem_fuzz_len = (u32 *)map;
  fsrv->shmem_fuzz = map + sizeof(u32);

  if (!fsrv->qemu_mode && !unicorn_mode) {

    u32 save_be_quiet = be_quiet;
    be_quiet = !debug;
    fsrv->map_size = 4194304;  // dummy temporary value
    u32 new_map_size =
        afl_fsrv_get_mapsize(fsrv, use_argv, &stop_soon,
                             (get_afl_env("AFL_DEBUG_CHILD") ||
                              get_afl_env("AFL_DEBUG_CHILD_OUTPUT"))
                                 ? 1
                                 : 0);
    be_quiet = save_be_quiet;

    if (new_map_size) {

      // only reinitialize when it makes sense
      if (map_size < new_map_size ||
          (new_map_size > map_size && new_map_size - map_size > MAP_SIZE)) {

        if (!be_quiet)
          ACTF("Aquired new map size for target: %u bytes\n", new_map_size);

        afl_shm_deinit(&shm);
        afl_fsrv_kill(fsrv);
        fsrv->map_size = new_map_size;
        fsrv->trace_bits = afl_shm_init(&shm, new_map_size, 0);

      }

      map_size = new_map_size;

    }

    fsrv->map_size = map_size;

  }

  if (in_dir) {

    DIR *          dir_in, *dir_out = NULL;
    struct dirent *dir_ent;
    //    int            done = 0;
    u8 infile[PATH_MAX], outfile[PATH_MAX];
    u8 wait_for_gdb = 0;
#if !defined(DT_REG)
    struct stat statbuf;
#endif

    if (getenv("AFL_DEBUG_GDB")) wait_for_gdb = 1;

    fsrv->dev_null_fd = open("/dev/null", O_RDWR);
    if (fsrv->dev_null_fd < 0) { PFATAL("Unable to open /dev/null"); }

    // if a queue subdirectory exists switch to that
    u8 *dn = alloc_printf("%s/queue", in_dir);
    if ((dir_in = opendir(dn)) != NULL) {

      closedir(dir_in);
      in_dir = dn;

    } else

      ck_free(dn);
    if (!be_quiet) ACTF("Reading from directory '%s'...", in_dir);

    if (!(dir_in = opendir(in_dir))) {

      PFATAL("cannot open directory %s", in_dir);

    }

    if (!collect_coverage) {

      if (!(dir_out = opendir(out_file))) {

        if (mkdir(out_file, 0700)) {

          PFATAL("cannot create output directory %s", out_file);

        }

      }

    } else {

      if ((coverage_map = (u8 *)malloc(map_size)) == NULL)
        FATAL("coult not grab memory");
      edges_only = 0;
      raw_instr_output = 1;

    }

    u8 *use_dir = ".";

    if (access(use_dir, R_OK | W_OK | X_OK)) {

      use_dir = get_afl_env("TMPDIR");
      if (!use_dir) { use_dir = "/tmp"; }

    }

    stdin_file = at_file ? strdup(at_file)
                         : (char *)alloc_printf("%s/.afl-showmap-temp-%u",
                                                use_dir, (u32)getpid());
    unlink(stdin_file);
    atexit(at_exit_handler);
    fsrv->out_file = stdin_file;
    fsrv->out_fd = open(stdin_file, O_RDWR | O_CREAT | O_EXCL, DEFAULT_PERMISSION);
    if (fsrv->out_fd < 0) { PFATAL("Unable to create '%s'", out_file); }

    if (arg_offset && use_argv[arg_offset] != stdin_file) {

      use_argv[arg_offset] = strdup(stdin_file);

    }

    if (get_afl_env("AFL_DEBUG")) {

      int j = optind;
      DEBUGF("%s:", fsrv->target_path);
      while (argv[j] != NULL) {

        SAYF(" \"%s\"", argv[j++]);

      }

      SAYF("\n");

    }

    if (getenv("AFL_FORKSRV_INIT_TMOUT")) {

      s32 forksrv_init_tmout = atoi(getenv("AFL_FORKSRV_INIT_TMOUT"));
      if (forksrv_init_tmout < 1) {

        FATAL("Bad value specified for AFL_FORKSRV_INIT_TMOUT");

      }

      fsrv->init_tmout = (u32)forksrv_init_tmout;

    }

    fsrv->kill_signal =
        parse_afl_kill_signal_env(getenv("AFL_KILL_SIGNAL"), SIGKILL);

    if (getenv("AFL_CRASH_EXITCODE")) {

      long exitcode = strtol(getenv("AFL_CRASH_EXITCODE"), NULL, 10);
      if ((!exitcode && (errno == EINVAL || errno == ERANGE)) ||
          exitcode < -127 || exitcode > 128) {

        FATAL("Invalid crash exitcode, expected -127 to 128, but got %s",
              getenv("AFL_CRASH_EXITCODE"));

      }

      fsrv->uses_crash_exitcode = true;
      // WEXITSTATUS is 8 bit unsigned
      fsrv->crash_exitcode = (u8)exitcode;

    }

    afl_fsrv_start(fsrv, use_argv, &stop_soon,
                   (get_afl_env("AFL_DEBUG_CHILD") ||
                    get_afl_env("AFL_DEBUG_CHILD_OUTPUT"))
                       ? 1
                       : 0);

    map_size = fsrv->map_size;

    if (fsrv->support_shmem_fuzz && !fsrv->use_shmem_fuzz)
      shm_fuzz = deinit_shmem(fsrv, shm_fuzz);

    while ((dir_ent = readdir(dir_in))) {

      if (dir_ent->d_name[0] == '.') {

        continue;  // skip anything that starts with '.'

      }

#if defined(DT_REG)      /* Posix and Solaris do not know d_type and DT_REG */
      if (dir_ent->d_type != DT_REG) {

        continue;  // only regular files

      }

#endif

      snprintf(infile, sizeof(infile), "%s/%s", in_dir, dir_ent->d_name);

#if !defined(DT_REG)                                          /* use stat() */
      if (-1 == stat(infile, &statbuf) || !S_ISREG(statbuf.st_mode)) continue;
#endif

      if (!collect_coverage)
        snprintf(outfile, sizeof(outfile), "%s/%s", out_file, dir_ent->d_name);

      if (read_file(infile)) {

        if (wait_for_gdb) {

          fprintf(stderr, "exec: gdb -p %d\n", fsrv->child_pid);
          fprintf(stderr, "exec: kill -CONT %d\n", getpid());
          kill(0, SIGSTOP);

        }

        showmap_run_target_forkserver(fsrv, in_data, in_len);
        ck_free(in_data);
        if (collect_coverage)
          analyze_results(fsrv);
        else
          tcnt = write_results_to_file(fsrv, outfile);

      }

    }

    if (!quiet_mode) { OKF("Processed %llu input files.", fsrv->total_execs); }

    closedir(dir_in);
    if (dir_out) { closedir(dir_out); }

    if (collect_coverage) {

      memcpy(fsrv->trace_bits, coverage_map, map_size);
      tcnt = write_results_to_file(fsrv, out_file);

    }

  } else {

    if (fsrv->support_shmem_fuzz && !fsrv->use_shmem_fuzz)
      shm_fuzz = deinit_shmem(fsrv, shm_fuzz);

    showmap_run_target(fsrv, use_argv);
    tcnt = write_results_to_file(fsrv, out_file);
    if (!quiet_mode) {

      OKF("Hash of coverage map: %llx",
          hash64(fsrv->trace_bits, fsrv->map_size, HASH_CONST));

    }

  }

  if (!quiet_mode || collect_coverage) {

    if (!tcnt && !have_coverage) { FATAL("No instrumentation detected" cRST); }
    OKF("Captured %u tuples (highest value %u, total values %llu) in "
        "'%s'." cRST,
        tcnt, highest, total, out_file);
    if (collect_coverage)
      OKF("A coverage of %u edges were achieved out of %u existing (%.02f%%) "
          "with %llu input files.",
          tcnt, map_size, ((float)tcnt * 100) / (float)map_size,
          fsrv->total_execs);

  }

  if (stdin_file) {

    unlink(stdin_file);
    ck_free(stdin_file);
    stdin_file = NULL;

  }

  remove_shm = 0;
  afl_shm_deinit(&shm);
  if (fsrv->use_shmem_fuzz) shm_fuzz = deinit_shmem(fsrv, shm_fuzz);

  u32 ret;

  if (cmin_mode && !!getenv("AFL_CMIN_CRASHES_ONLY")) {

    ret = fsrv->last_run_timed_out;

  } else {

    ret = child_crashed * 2 + fsrv->last_run_timed_out;

  }

  if (fsrv->target_path) { ck_free(fsrv->target_path); }

  afl_fsrv_deinit(fsrv);

  if (stdin_file) { ck_free(stdin_file); }
  if (collect_coverage) { free(coverage_map); }

  argv_cpy_free(argv);
  if (fsrv->qemu_mode) { free(use_argv[2]); }

  exit(ret);

}

