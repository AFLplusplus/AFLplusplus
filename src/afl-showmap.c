/*
   american fuzzy lop++ - map display utility
   ------------------------------------------

   Originally written by Michal Zalewski

   Forkserver design by Jann Horn <jannhorn@googlemail.com>

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eissfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com> and
                        Dominik Maier <mail@dmnk.co>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2024 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   A very simple tool that runs the targeted binary and displays
   the contents of the trace bitmap in a human-readable form. Useful in
   scripts to eliminate redundant inputs and perform other checks.

   Exit code is 2 if the target program crashes; 1 if it times out or
   there is a problem executing it; or 0 if execution is successful.

 */

#define AFL_MAIN
#define AFL_SHOWMAP

#include "config.h"
#include "afl-fuzz.h"
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

#include <dirent.h>
#include <sys/wait.h>
#include <sys/time.h>
#ifndef USEMMAP
  #include <sys/shm.h>
#endif
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>

static afl_state_t *afl;

static char *stdin_file;               /* stdin file                        */

static u8 *in_dir = NULL,              /* input folder                      */
    *out_file = NULL,                  /* output file or directory          */
        *at_file = NULL,               /* Substitution string for @@        */
            *in_filelist = NULL;       /* input file list                   */

static u8 outfile[PATH_MAX];

static u8 *in_data,                    /* Input data                        */
    *coverage_map;                     /* Coverage map                      */

static u64 total;                      /* tuple content information         */
static u32 tcnt, highest;              /* tuple content information         */

static u32 in_len;                     /* Input data length                 */

static u32 map_size = MAP_SIZE, timed_out = 0;

static bool quiet_mode,                /* Hide non-essential messages?      */
    edges_only,                        /* Ignore hit counts?                */
    raw_instr_output,                  /* Do not apply AFL filters          */
    cmin_mode,                         /* Generate output in afl-cmin mode? */
    binary_mode,                       /* Write output as a binary map      */
    keep_cores,                        /* Allow coredumps?                  */
    remove_shm = true,                 /* remove shmem?                     */
    collect_coverage,                  /* collect coverage                  */
    have_coverage,                     /* have coverage?                    */
    no_classify,                       /* do not classify counts            */
    debug,                             /* debug mode                        */
    print_filenames,                   /* print the current filename        */
    wait_for_gdb;

static volatile u8 stop_soon,          /* Ctrl-C pressed?                   */
    child_crashed;                     /* Child crashed?                    */

static sharedmem_t       shm;
static afl_forkserver_t *fsrv;
static sharedmem_t      *shm_fuzz;

/* Classify tuple counts. Instead of mapping to individual bits, as in
   afl-fuzz.c, we map to more user-friendly numbers between 1 and 8. */

static const u8 count_class_human[256] = {

    [0] = 0,          [1] = 1,        [2] = 2,         [3] = 3,
    [4 ... 7] = 4,    [8 ... 15] = 5, [16 ... 31] = 6, [32 ... 127] = 7,
    [128 ... 255] = 8

};

static const u8 count_class_binary[256] = {

    [0] = 0,
    [1] = 1,
    [2] = 2,
    [3] = 4,
    [4 ... 7] = 8,
    [8 ... 15] = 16,
    [16 ... 31] = 32,
    [32 ... 127] = 64,
    [128 ... 255] = 128

};

static void kill_child() {

  timed_out = 1;
  if (fsrv->child_pid > 0) {

    kill(fsrv->child_pid, fsrv->child_kill_signal);
    fsrv->child_pid = -1;

  }

}

/* dummy functions */
u32 write_to_testcase(afl_state_t *afl, void **mem, u32 a, u32 b) {

  (void)afl;
  (void)mem;
  return a + b;

}

void show_stats(afl_state_t *afl) {

  (void)afl;

}

void update_bitmap_score(afl_state_t *afl, struct queue_entry *q) {

  (void)afl;
  (void)q;

}

fsrv_run_result_t fuzz_run_target(afl_state_t *afl, afl_forkserver_t *fsrv,
                                  u32 i) {

  (void)afl;
  (void)fsrv;
  (void)i;
  return 0;

}

void classify_counts(afl_forkserver_t *fsrv) {

  u8       *mem = fsrv->trace_bits;
  const u8 *map = (binary_mode || collect_coverage) ? count_class_binary
                                                    : count_class_human;

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
                                 sharedmem_t      *shm_fuzz) {

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

    remove_shm = false;
    if (shm.map) afl_shm_deinit(&shm);
    if ((shm_fuzz && shm_fuzz->shmemfuzz_mode) || fsrv->use_shmem_fuzz) {

      shm_fuzz = deinit_shmem(fsrv, shm_fuzz);

    }

  }

  afl_fsrv_killall();

}

/* Analyze results. */

static void analyze_results(afl_forkserver_t *fsrv) {

  u32 i;
  for (i = 0; i < map_size; i++) {

    if (fsrv->trace_bits[i]) { coverage_map[i] |= fsrv->trace_bits[i]; }

  }

}

/* Write results. */

static u32 write_results_to_file(afl_forkserver_t *fsrv, u8 *outfile) {

  s32 fd;
  u32 i, ret = 0;

  u8 cco = !!getenv("AFL_CMIN_CRASHES_ONLY"),
     caa = !!getenv("AFL_CMIN_ALLOW_ANY");

  if (!outfile || !*outfile) {

    FATAL("Output filename not set (Bug in AFL++?)");

  }

  if (cmin_mode &&
      (fsrv->last_run_timed_out || (!caa && child_crashed != cco))) {

    if (strcmp(outfile, "-")) {

      // create empty file to prevent error messages in afl-cmin
      fd = open(outfile, O_WRONLY | O_CREAT | O_EXCL, DEFAULT_PERMISSION);
      close(fd);

    }

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

        fprintf(f, "%u%03u\n", i, fsrv->trace_bits[i]);

      } else {

        fprintf(f, "%06u:%u\n", i, fsrv->trace_bits[i]);

      }

    }

    fclose(f);

  }

  return ret;

}

void pre_afl_fsrv_write_to_testcase(afl_forkserver_t *fsrv, u8 *mem, u32 len) {

  static u8 buf[MAX_FILE];
  u32       sent = 0;

  if (unlikely(afl->custom_mutators_count)) {

    ssize_t new_size = len;
    u8     *new_mem = mem;
    u8     *new_buf = NULL;

    LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

      if (el->afl_custom_post_process) {

        new_size =
            el->afl_custom_post_process(el->data, new_mem, new_size, &new_buf);

        if (unlikely(!new_buf || new_size <= 0)) {

          return;

        } else {

          new_mem = new_buf;
          len = new_size;

        }

      }

    });

    if (new_mem != mem && new_mem != NULL) {

      mem = buf;
      memcpy(mem, new_mem, new_size);

    }

    if (unlikely(afl->custom_mutators_count)) {

      LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

        if (el->afl_custom_fuzz_send) {

          el->afl_custom_fuzz_send(el->data, mem, len);
          sent = 1;

        }

      });

    }

  }

  if (likely(!sent)) { afl_fsrv_write_to_testcase(fsrv, mem, len); }

}

/* Execute target application. */

static void showmap_run_target_forkserver(afl_forkserver_t *fsrv, u8 *mem,
                                          u32 len) {

  pre_afl_fsrv_write_to_testcase(fsrv, mem, len);

  if (!quiet_mode) { SAYF("-- Program output begins --\n" cRST); }

  if (afl_fsrv_run_target(fsrv, fsrv->exec_tmout, &stop_soon) ==
      FSRV_RUN_ERROR) {

    FATAL("Error running target");

  }

  if (fsrv->trace_bits[0]) {

    fsrv->trace_bits[0] -= 1;
    have_coverage = true;

  } else {

    have_coverage = false;

  }

  if (!no_classify) { classify_counts(fsrv); }

  if (!quiet_mode) { SAYF(cRST "-- Program output ends --\n"); }

  if (!fsrv->last_run_timed_out && !stop_soon &&
      WIFSIGNALED(fsrv->child_status)) {

    child_crashed = true;

  } else {

    child_crashed = false;

  }

  if (!quiet_mode) {

    if (timed_out || fsrv->last_run_timed_out) {

      SAYF(cLRD "\n+++ Program timed off +++\n" cRST);
      timed_out = 0;

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

  if (print_filenames) {

    SAYF("Processing %s\n", in_file);
    fflush(stdout);

  }

  struct stat st;
  s32         fd = open(in_file, O_RDONLY);

  if (fd < 0) { WARNF("Unable to open '%s'", in_file); }

  if (fstat(fd, &st) || !st.st_size) {

    if (!be_quiet && !quiet_mode) {

      WARNF("Zero-sized input file '%s'.", in_file);

    }

  }

  if (st.st_size > MAX_FILE) {

    if (!be_quiet && !quiet_mode) {

      WARNF("Input file '%s' is too large, only reading %ld bytes.", in_file,
            MAX_FILE);

    }

    in_len = MAX_FILE;

  } else {

    in_len = st.st_size;

  }

  in_data = ck_alloc_nozero(in_len);

  ck_read(fd, in_data, in_len, in_file);

  close(fd);

  // OKF("Read %u byte%s from '%s'.", in_len, in_len == 1 ? "" : "s", in_file);

  return in_len;

}

#ifdef __linux__
/* Execute the target application with an empty input (in Nyx mode). */
static void showmap_run_target_nyx_mode(afl_forkserver_t *fsrv) {

  afl_fsrv_write_to_testcase(fsrv, NULL, 0);

  if (afl_fsrv_run_target(fsrv, fsrv->exec_tmout, &stop_soon) ==
      FSRV_RUN_ERROR) {

    FATAL("Error running target in Nyx mode");

  }

}

#endif

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

    signal(SIGALRM, kill_child);

    setitimer(ITIMER_REAL, &it, NULL);

  }

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

  if (fsrv->trace_bits[0]) {

    fsrv->trace_bits[0] -= 1;
    have_coverage = true;

  } else {

    have_coverage = false;

  }

  if (!no_classify) { classify_counts(fsrv); }

  if (!quiet_mode) { SAYF(cRST "-- Program output ends --\n"); }

  if (!fsrv->last_run_timed_out && !stop_soon && WIFSIGNALED(status)) {

    child_crashed = true;

  }

  if (!quiet_mode) {

    if (timed_out || fsrv->last_run_timed_out) {

      SAYF(cLRD "\n+++ Program timed off +++\n" cRST);
      timed_out = 0;

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
  stop_soon = true;
  afl_fsrv_killall();

}

/* Do basic preparations - persistent fds, filenames, etc. */

static void set_up_environment(afl_forkserver_t *fsrv, char **argv) {

  char *afl_preload;
  char *frida_afl_preload = NULL;

  set_sanitizer_defaults();

  if (get_afl_env("AFL_PRELOAD")) {

    if (fsrv->qemu_mode) {

      /* afl-qemu-trace takes care of converting AFL_PRELOAD. */

    } else if (fsrv->frida_mode) {

      afl_preload = getenv("AFL_PRELOAD");
      u8 *frida_binary = find_afl_binary(argv[0], "afl-frida-trace.so");
      if (afl_preload) {

        frida_afl_preload = alloc_printf("%s:%s", afl_preload, frida_binary);

      } else {

        frida_afl_preload = alloc_printf("%s", frida_binary);

      }

      ck_free(frida_binary);

      setenv("LD_PRELOAD", frida_afl_preload, 1);
      setenv("DYLD_INSERT_LIBRARIES", frida_afl_preload, 1);

    } else {

      /* CoreSight mode uses the default behavior. */

      setenv("LD_PRELOAD", getenv("AFL_PRELOAD"), 1);
      setenv("DYLD_INSERT_LIBRARIES", getenv("AFL_PRELOAD"), 1);

    }

  } else if (fsrv->frida_mode) {

    u8 *frida_binary = find_afl_binary(argv[0], "afl-frida-trace.so");
    setenv("LD_PRELOAD", frida_binary, 1);
    setenv("DYLD_INSERT_LIBRARIES", frida_binary, 1);
    ck_free(frida_binary);

  }

  if (frida_afl_preload) { ck_free(frida_afl_preload); }

}

/* Setup signal handlers, duh. */

static void setup_signal_handlers(void) {

  struct sigaction sa;

  sa.sa_handler = NULL;
#ifdef SA_RESTART
  sa.sa_flags = SA_RESTART;
#else
  sa.sa_flags = 0;
#endif
  sa.sa_sigaction = NULL;

  sigemptyset(&sa.sa_mask);

  /* Various ways of saying "stop". */

  sa.sa_handler = handle_stop_sig;
  sigaction(SIGHUP, &sa, NULL);
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);

}

u32 execute_testcases(u8 *dir) {

  struct dirent **nl;
  s32             nl_cnt, subdirs = 1;
  u32             i, done = 0;
  u8              val_buf[2][STRINGIFY_VAL_SIZE_MAX];

  if (!be_quiet) { ACTF("Scanning '%s'...", dir); }

  /* We use scandir() + alphasort() rather than readdir() because otherwise,
     the ordering of test cases would vary somewhat randomly and would be
     difficult to control. */

  nl_cnt = scandir(dir, &nl, NULL, alphasort);

  if (nl_cnt < 0) { return 0; }

  for (i = 0; i < (u32)nl_cnt; ++i) {

    struct stat st;

    u8 *fn2 = alloc_printf("%s/%s", dir, nl[i]->d_name);

    if (lstat(fn2, &st) || access(fn2, R_OK)) {

      PFATAL("Unable to access '%s'", fn2);

    }

    /* obviously we want to skip "descending" into . and .. directories,
       however it is a good idea to skip also directories that start with
       a dot */
    if (subdirs && S_ISDIR(st.st_mode) && nl[i]->d_name[0] != '.') {

      free(nl[i]);                                           /* not tracked */
      done += execute_testcases(fn2);
      ck_free(fn2);
      continue;

    }

    if (!S_ISREG(st.st_mode) || !st.st_size) {

      free(nl[i]);
      ck_free(fn2);
      continue;

    }

    if (st.st_size > MAX_FILE && !be_quiet && !quiet_mode) {

      WARNF("Test case '%s' is too big (%s, limit is %s), partial reading", fn2,
            stringify_mem_size(val_buf[0], sizeof(val_buf[0]), st.st_size),
            stringify_mem_size(val_buf[1], sizeof(val_buf[1]), MAX_FILE));

    }

    if (!collect_coverage)
      snprintf(outfile, sizeof(outfile), "%s/%s", out_file, nl[i]->d_name);

    free(nl[i]);

    if (read_file(fn2)) {

      if (wait_for_gdb) {

        fprintf(stderr, "exec: gdb -p %d\n", fsrv->child_pid);
        fprintf(stderr, "exec: kill -CONT %d\n", getpid());
        kill(0, SIGSTOP);

      }

      showmap_run_target_forkserver(fsrv, in_data, in_len);
      ck_free(in_data);
      ++done;

      if (child_crashed && debug) { WARNF("crashed: %s", fn2); }

      if (collect_coverage)
        analyze_results(fsrv);
      else
        tcnt = write_results_to_file(fsrv, outfile);

    }

  }

  free(nl);                                                  /* not tracked */
  return done;

}

u32 execute_testcases_filelist(u8 *fn) {

  u32   done = 0;
  u8    buf[4096];
  u8    val_buf[2][STRINGIFY_VAL_SIZE_MAX];
  FILE *f;

  if (!be_quiet) { ACTF("Reading from '%s'...", fn); }

  if ((f = fopen(fn, "r")) == NULL) { FATAL("could not open '%s'", fn); }

  while (fgets(buf, sizeof(buf), f) != NULL) {

    struct stat st;
    u8         *fn2 = buf, *fn3;

    while (*fn2 == ' ') {

      ++fn2;

    }

    while (*fn2 &&
           (fn2[strlen(fn2) - 1] == '\r' || fn2[strlen(fn2) - 1] == '\n' ||
            fn2[strlen(fn2) - 1] == ' ')) {

      fn2[strlen(fn2) - 1] = 0;

    }

    if (debug) { printf("Getting coverage for '%s'\n", fn2); }

    if (!*fn2) { continue; }

    if (lstat(fn2, &st) || access(fn2, R_OK)) {

      WARNF("Unable to access '%s'", fn2);
      continue;

    }

    ++done;

    if (!S_ISREG(st.st_mode) || !st.st_size) { continue; }

    if ((fn3 = strrchr(fn2, '/'))) {

      ++fn3;

    } else {

      fn3 = fn2;

    }

    if (st.st_size > MAX_FILE && !be_quiet && !quiet_mode) {

      WARNF("Test case '%s' is too big (%s, limit is %s), partial reading", fn2,
            stringify_mem_size(val_buf[0], sizeof(val_buf[0]), st.st_size),
            stringify_mem_size(val_buf[1], sizeof(val_buf[1]), MAX_FILE));

    }

    if (!collect_coverage) {

      snprintf(outfile, sizeof(outfile), "%s/%s", out_file, fn3);

    }

    if (read_file(fn2)) {

      if (wait_for_gdb) {

        fprintf(stderr, "exec: gdb -p %d\n", fsrv->child_pid);
        fprintf(stderr, "exec: kill -CONT %d\n", getpid());
        kill(0, SIGSTOP);

      }

      showmap_run_target_forkserver(fsrv, in_data, in_len);
      ck_free(in_data);

      if (child_crashed && debug) { WARNF("crashed: %s", fn2); }

      if (collect_coverage)
        analyze_results(fsrv);
      else
        tcnt = write_results_to_file(fsrv, outfile);

    }

  }

  return done;

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
      "  -o file    - file to write the trace data to\n\n"

      "Execution control settings:\n"
      "  -t msec    - timeout for each run (default: 1000ms)\n"
      "  -m megs    - memory limit for child process (default: none)\n"
#if defined(__linux__) && defined(__aarch64__)
      "  -A         - use binary-only instrumentation (ARM CoreSight mode)\n"
#endif
      "  -O         - use binary-only instrumentation (FRIDA mode)\n"
#if defined(__linux__)
      "  -Q         - use binary-only instrumentation (QEMU mode)\n"
      "  -U         - use Unicorn-based instrumentation (Unicorn mode)\n"
      "  -W         - use qemu-based instrumentation with Wine (Wine mode)\n"
      "               (Not necessary, here for consistency with other afl-* "
      "tools)\n"
      "  -X         - use Nyx mode\n"
#endif
      "\n"
      "Other settings:\n"
      "  -i dir     - process all files below this directory, must be combined "
      "with -o.\n"
      "               With -C, -o is a file, without -C it must be a "
      "directory\n"
      "               and each bitmap will be written there individually.\n"
      "  -I filelist - alternatively to -i, -I is a list of files\n"
      "  -C         - collect coverage, writes all edges to -o and gives a "
      "summary\n"
      "               Must be combined with -i.\n"
      "  -q         - sink program's output and don't show messages\n"
      "  -e         - show edge coverage only, ignore hit counts\n"
      "  -r         - show real tuple values instead of AFL filter values\n"
      "  -s         - do not classify the map\n"
      "  -c         - allow core dumps\n\n"

      "This tool displays raw tuple data captured by AFL instrumentation.\n"
      "For additional help, consult %s/README.md.\n\n"

      "If you use -i/-I mode, then custom mutator post_process send send "
      "functionality\n"
      "is supported.\n\n"

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
      "etc.\n"
      "                 (default: SIGKILL)\n"
      "AFL_FORK_SERVER_KILL_SIGNAL: Kill signal for the fork server on "
      "termination\n"
      "                             (default: SIGTERM). If unset and "
      "AFL_KILL_SIGNAL is\n"
      "                             set, that value will be used.\n"
      "AFL_MAP_SIZE: the shared memory size for that target. must be >= the "
      "size the\n"
      "              target was compiled for\n"
      "AFL_PRELOAD: LD_PRELOAD / DYLD_INSERT_LIBRARIES settings for target\n"
      "AFL_PRINT_FILENAMES: Print the queue entry currently processed will to "
      "stdout\n"
      "AFL_QUIET: do not print extra informational output\n"
      "AFL_NO_FORKSRV: run target via execve instead of using the forkserver\n",
      argv0, doc_path);

  exit(1);

}

/* Main entry point */

int main(int argc, char **argv_orig, char **envp) {

  // TODO: u64 mem_limit = MEM_LIMIT;                  /* Memory limit (MB) */

  s32  opt, i;
  bool mem_limit_given = false, timeout_given = false, unicorn_mode = false,
       use_wine = false;
  char **use_argv;

  char **argv = argv_cpy_dup(argc, argv_orig);

  afl_forkserver_t fsrv_var = {0};
  if (getenv("AFL_DEBUG")) { debug = true; }
  if (get_afl_env("AFL_PRINT_FILENAMES")) { print_filenames = true; }

  fsrv = &fsrv_var;
  afl_fsrv_init(fsrv);
  map_size = get_map_size();
  fsrv->map_size = map_size;

  doc_path = access(DOC_PATH, F_OK) ? "docs" : DOC_PATH;

  if (getenv("AFL_QUIET") != NULL) { be_quiet = true; }

  while ((opt = getopt(argc, argv, "+i:I:o:f:m:t:AeqCZOH:QUWbcrshXY")) > 0) {

    switch (opt) {

      case 's':
        no_classify = true;
        break;

      case 'C':
        collect_coverage = true;
        quiet_mode = true;
        break;

      case 'i':
        if (in_dir) { FATAL("Multiple -i options not supported"); }
        in_dir = optarg;
        break;

      case 'I':
        if (in_filelist) { FATAL("Multiple -I options not supported"); }
        in_filelist = optarg;
        break;

      case 'o':

        if (out_file) { FATAL("Multiple -o options not supported"); }
        out_file = optarg;
        break;

      case 'm': {

        u8 suffix = 'M';

        if (mem_limit_given) { FATAL("Multiple -m options not supported"); }
        mem_limit_given = true;

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
        timeout_given = true;

        if (!optarg) { FATAL("Wrong usage of -t"); }

        if (strcmp(optarg, "none")) {

          fsrv->exec_tmout = atoi(optarg);

          if (fsrv->exec_tmout < 20 || optarg[0] == '-') {

            FATAL("Dangerously low value of -t");

          }

        } else {

          // The forkserver code does not have a way to completely
          // disable the timeout, so we'll use a very, very long
          // timeout instead.
          WARNF(
              "Setting an execution timeout of 120 seconds ('none' is not "
              "allowed).");
          fsrv->exec_tmout = 120 * 1000;

        }

        break;

      case 'e':

        if (edges_only) { FATAL("Multiple -e options not supported"); }
        if (raw_instr_output) { FATAL("-e and -r are mutually exclusive"); }
        edges_only = true;
        break;

      case 'q':

        quiet_mode = true;
        break;

      case 'Z':

        /* This is an undocumented option to write data in the syntax expected
           by afl-cmin. Nobody else should have any use for this. */

        cmin_mode = true;
        quiet_mode = true;
        break;

      case 'H':
        /* Another afl-cmin specific feature. */
        at_file = optarg;
        break;

      case 'O':                                               /* FRIDA mode */

        if (fsrv->frida_mode) { FATAL("Multiple -O options not supported"); }

        fsrv->frida_mode = true;
        setenv("AFL_FRIDA_INST_SEED", "1", 1);

        break;

      /* FIXME: We want to use -P for consistency, but it is already unsed for
       * undocumenetd feature "Another afl-cmin specific feature." */
      case 'A':                                           /* CoreSight mode */

#if !defined(__aarch64__) || !defined(__linux__)
        FATAL("-A option is not supported on this platform");
#endif

        if (fsrv->cs_mode) { FATAL("Multiple -A options not supported"); }

        fsrv->cs_mode = true;
        break;

      case 'Q':

        if (fsrv->qemu_mode) { FATAL("Multiple -Q options not supported"); }

        fsrv->qemu_mode = true;
        break;

      case 'U':

        if (unicorn_mode) { FATAL("Multiple -U options not supported"); }

        unicorn_mode = true;
        break;

      case 'W':                                           /* Wine+QEMU mode */

        if (use_wine) { FATAL("Multiple -W options not supported"); }
        fsrv->qemu_mode = true;
        use_wine = true;

        break;

      case 'Y':  // fallthrough
#ifdef __linux__
      case 'X':                                                 /* NYX mode */

        if (fsrv->nyx_mode) { FATAL("Multiple -X options not supported"); }

        fsrv->nyx_mode = 1;
        fsrv->nyx_parent = true;
        fsrv->nyx_standalone = true;

        break;
#else
      case 'X':
        FATAL("Nyx mode is only availabe on linux...");
        break;
#endif

      case 'b':

        /* Secret undocumented mode. Writes output in raw binary format
           similar to that dumped by afl-fuzz in <out_dir/queue/fuzz_bitmap. */

        binary_mode = true;
        break;

      case 'c':

        if (keep_cores) { FATAL("Multiple -c options not supported"); }
        keep_cores = true;
        break;

      case 'r':

        if (raw_instr_output) { FATAL("Multiple -r options not supported"); }
        if (edges_only) { FATAL("-e and -r are mutually exclusive"); }
        raw_instr_output = true;
        break;

      case 'h':
        usage(argv[0]);
        return -1;
        break;

      default:
        usage(argv[0]);

    }

  }

  if (collect_coverage) { binary_mode = false; }  // ensure this

  if (optind == argc || !out_file) { usage(argv[0]); }

  if (in_dir && in_filelist) { FATAL("you can only specify either -i or -I"); }

  if (in_dir || in_filelist) {

    if (!out_file && !collect_coverage)
      FATAL("for -i/-I you need to specify either -C and/or -o");

  }

  if (fsrv->qemu_mode && !mem_limit_given) { fsrv->mem_limit = MEM_LIMIT_QEMU; }
  if (unicorn_mode && !mem_limit_given) { fsrv->mem_limit = MEM_LIMIT_UNICORN; }

  check_environment_vars(envp);

  if (getenv("AFL_NO_FORKSRV")) {             /* if set, use the fauxserver */
    fsrv->use_fauxsrv = true;

  }

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

  set_up_environment(fsrv, argv);

#ifdef __linux__
  if (!fsrv->nyx_mode) {

    fsrv->target_path = find_binary(argv[optind]);

  } else {

    fsrv->target_path = ck_strdup(argv[optind]);

  }

#else
  fsrv->target_path = find_binary(argv[optind]);
#endif

  fsrv->trace_bits = afl_shm_init(&shm, map_size, 0);

  if (!quiet_mode) {

    show_banner();
    ACTF("Executing '%s'...", fsrv->target_path);

  }

  if (in_dir || in_filelist) {

    /* If we don't have a file name chosen yet, use a safe default. */
    u8 *use_dir = ".";

    if (access(use_dir, R_OK | W_OK | X_OK)) {

      use_dir = get_afl_env("TMPDIR");
      if (!use_dir) { use_dir = "/tmp"; }

    }

    stdin_file = at_file ? strdup(at_file)
                         : (char *)alloc_printf("%s/.afl-showmap-temp-%u",
                                                use_dir, (u32)getpid());
    unlink(stdin_file);

    // If @@ are in the target args, replace them and also set use_stdin=false.
    detect_file_args(argv + optind, stdin_file, &fsrv->use_stdin);

    fsrv->dev_null_fd = open("/dev/null", O_RDWR);
    if (fsrv->dev_null_fd < 0) { PFATAL("Unable to open /dev/null"); }

    fsrv->out_file = stdin_file;
    fsrv->out_fd =
        open(stdin_file, O_RDWR | O_CREAT | O_EXCL, DEFAULT_PERMISSION);
    if (fsrv->out_fd < 0) { PFATAL("Unable to create '%s'", stdin_file); }

  } else {

    // If @@ are in the target args, replace them and also set use_stdin=false.
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

  } else if (fsrv->cs_mode) {

    use_argv =
        get_cs_argv(argv[0], &fsrv->target_path, argc - optind, argv + optind);

#ifdef __linux__

  } else if (fsrv->nyx_mode) {

    use_argv = ck_alloc(sizeof(char *) * (1));
    use_argv[0] = argv[0];

    fsrv->nyx_id = 0;

    u8 *libnyx_binary = find_afl_binary(use_argv[0], "libnyx.so");
    fsrv->nyx_handlers = afl_load_libnyx_plugin(libnyx_binary);
    if (fsrv->nyx_handlers == NULL) {

      FATAL("failed to initialize libnyx.so...");

    }

    fsrv->nyx_use_tmp_workdir = true;
    fsrv->nyx_bind_cpu_id = 0;
#endif

  } else {

    use_argv = argv + optind;

  }

  afl = calloc(1, sizeof(afl_state_t));

  if (getenv("AFL_FORKSRV_INIT_TMOUT")) {

    s32 forksrv_init_tmout = atoi(getenv("AFL_FORKSRV_INIT_TMOUT"));
    if (forksrv_init_tmout < 1) {

      FATAL("Bad value specified for AFL_FORKSRV_INIT_TMOUT");

    }

    fsrv->init_tmout = (u32)forksrv_init_tmout;

  }

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

#ifdef __linux__
  if (!fsrv->nyx_mode && (in_dir || in_filelist)) {

    (void)check_binary_signatures(fsrv->target_path);

  }

#else
  if (in_dir) { (void)check_binary_signatures(fsrv->target_path); }
#endif

  shm_fuzz = ck_alloc(sizeof(sharedmem_t));

  /* initialize cmplog_mode */
  shm_fuzz->cmplog_mode = 0;
  atexit(at_exit_handler);

  u8 *map = afl_shm_init(shm_fuzz, MAX_FILE + sizeof(u32), 1);
  shm_fuzz->shmemfuzz_mode = true;
  if (!map) { FATAL("BUG: Zero return from afl_shm_init."); }
#ifdef USEMMAP
  setenv(SHM_FUZZ_ENV_VAR, shm_fuzz->g_shm_file_path, 1);
#else
  u8 *shm_str = alloc_printf("%d", shm_fuzz->shm_id);
  setenv(SHM_FUZZ_ENV_VAR, shm_str, 1);
  ck_free(shm_str);
#endif
  fsrv->support_shmem_fuzz = true;
  fsrv->shmem_fuzz_len = (u32 *)map;
  fsrv->shmem_fuzz = map + sizeof(u32);

  configure_afl_kill_signals(fsrv, NULL, NULL,
                             (fsrv->qemu_mode || unicorn_mode
#ifdef __linux__
                              || fsrv->nyx_mode
#endif
                              )
                                 ? SIGKILL
                                 : SIGTERM);

  if (!fsrv->cs_mode && !fsrv->qemu_mode && !unicorn_mode) {

    u32 save_be_quiet = be_quiet;
    be_quiet = !debug;
    if (map_size > 4194304) {

      fsrv->map_size = map_size;

    } else {

      fsrv->map_size = 4194304;  // dummy temporary value

    }

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
          ACTF("Acquired new map size for target: %u bytes\n", new_map_size);

        afl_shm_deinit(&shm);
        afl_fsrv_kill(fsrv);
        fsrv->map_size = new_map_size;
        fsrv->trace_bits = afl_shm_init(&shm, new_map_size, 0);

      }

      map_size = new_map_size;

    }

    fsrv->map_size = map_size;

  } else {

    afl_fsrv_start(fsrv, use_argv, &stop_soon,
                   (get_afl_env("AFL_DEBUG_CHILD") ||
                    get_afl_env("AFL_DEBUG_CHILD_OUTPUT"))
                       ? 1
                       : 0);

  }

  if (in_dir || in_filelist) {

    afl->fsrv.dev_urandom_fd = open("/dev/urandom", O_RDONLY);
    if (afl->fsrv.dev_urandom_fd < 0) { PFATAL("Unable to open /dev/urandom"); }
    afl->afl_env.afl_custom_mutator_library =
        getenv("AFL_CUSTOM_MUTATOR_LIBRARY");
    afl->afl_env.afl_python_module = getenv("AFL_PYTHON_MODULE");
    setup_custom_mutators(afl);

  } else {

    if (getenv("AFL_CUSTOM_MUTATOR_LIBRARY") || getenv("AFL_PYTHON_MODULE")) {

      WARNF(
          "Custom mutator environment detected, this is only supported in "
          "-i/-I mode!\n");

    }

  }

  if (in_dir || in_filelist) {

    DIR *dir_in, *dir_out = NULL;
    u8  *dn = NULL;

    if (getenv("AFL_DEBUG_GDB")) wait_for_gdb = true;

    if (in_filelist) {

      if (!be_quiet) ACTF("Reading from file list '%s'...", in_filelist);

    } else {

      // if a queue subdirectory exists switch to that
      dn = alloc_printf("%s/queue", in_dir);

      if ((dir_in = opendir(dn)) != NULL) {

        closedir(dir_in);
        in_dir = dn;

      } else {

        ck_free(dn);

      }

      if (!be_quiet) ACTF("Reading from directory '%s'...", in_dir);

    }

    if (!collect_coverage) {

      if (!(dir_out = opendir(out_file))) {

        if (mkdir(out_file, 0700)) {

          PFATAL("cannot create output directory %s", out_file);

        }

      }

    } else {

      if ((coverage_map = (u8 *)malloc(map_size + 64)) == NULL)
        FATAL("coult not grab memory");
      edges_only = false;

    }

    if (get_afl_env("AFL_DEBUG")) {

      int j = optind;
      DEBUGF("%s:", fsrv->target_path);
      while (argv[j] != NULL) {

        SAYF(" \"%s\"", argv[j++]);

      }

      SAYF("\n");

    }

    map_size = fsrv->map_size;

    if (fsrv->support_shmem_fuzz && !fsrv->use_shmem_fuzz) {

      shm_fuzz = deinit_shmem(fsrv, shm_fuzz);

    }

    if (in_dir) {

      if (execute_testcases(in_dir) == 0) {

        FATAL("could not read input testcases from %s", in_dir);

      }

    } else {

      if (execute_testcases_filelist(in_filelist) == 0) {

        FATAL("could not read input testcases from %s", in_filelist);

      }

    }

    if (!quiet_mode) { OKF("Processed %llu input files.", fsrv->total_execs); }

    if (dir_out) { closedir(dir_out); }

    if (collect_coverage) {

      memcpy(fsrv->trace_bits, coverage_map, map_size);
      tcnt = write_results_to_file(fsrv, out_file);

    }

  } else {

    if (fsrv->support_shmem_fuzz && !fsrv->use_shmem_fuzz) {

      shm_fuzz = deinit_shmem(fsrv, shm_fuzz);

    }

#ifdef __linux__
    if (!fsrv->nyx_mode) {

#endif
      showmap_run_target(fsrv, use_argv);
#ifdef __linux__

    } else {

      showmap_run_target_nyx_mode(fsrv);

    }

#endif
    tcnt = write_results_to_file(fsrv, out_file);
    if (!quiet_mode) {

      OKF("Hash of coverage map: %llx",
          hash64(fsrv->trace_bits, fsrv->map_size, HASH_CONST));

    }

  }

  if (!quiet_mode || collect_coverage) {

    if (!tcnt && !have_coverage) { FATAL("No instrumentation detected" cRST); }
    OKF("Captured %u tuples (map size %u, highest value %u, total values %llu) "
        "in '%s'." cRST,
        tcnt, fsrv->real_map_size, highest, total, out_file);
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

  remove_shm = false;
  afl_shm_deinit(&shm);
  if (fsrv->use_shmem_fuzz) { shm_fuzz = deinit_shmem(fsrv, shm_fuzz); }

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

