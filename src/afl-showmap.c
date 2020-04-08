/*
   american fuzzy lop++ - map display utility
   ------------------------------------------

   Originally written by Michal Zalewski

   Forkserver design by Jann Horn <jannhorn@googlemail.com>

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eißfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com>

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
#include <fcntl.h>

#include <sys/wait.h>
#include <sys/time.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>

char *stdin_file;                      /* stdin file                        */

u8 *in_dir,                            /* input folder                      */
    *at_file = NULL;              /* Substitution string for @@             */

static u8 *in_data;                    /* Input data                        */

static u32 total, highest;             /* tuple content information         */

static u32 in_len,                     /* Input data length                 */
    arg_offset, total_execs;           /* Total number of execs             */

u8 quiet_mode,                         /* Hide non-essential messages?      */
    edges_only,                        /* Ignore hit counts?                */
    raw_instr_output,                  /* Do not apply AFL filters          */
    cmin_mode,                         /* Generate output in afl-cmin mode? */
    binary_mode,                       /* Write output as a binary map      */
    keep_cores;                        /* Allow coredumps?                  */

static volatile u8 stop_soon,          /* Ctrl-C pressed?                   */
    child_crashed;                     /* Child crashed?                    */

static u8 qemu_mode;

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

static void classify_counts(u8 *mem, const u8 *map) {

  u32 i = MAP_SIZE;

  if (edges_only) {

    while (i--) {

      if (*mem) *mem = 1;
      mem++;

    }

  } else if (!raw_instr_output) {

    while (i--) {

      *mem = map[*mem];
      mem++;

    }

  }

}

/* Get rid of temp files (atexit handler). */

static void at_exit_handler(void) {

  if (stdin_file) unlink(stdin_file);

}

/* Write results. */

static u32 write_results_to_file(afl_forkserver_t *fsrv, u8 *outfile) {

  s32 fd;
  u32 i, ret = 0;

  u8 cco = !!getenv("AFL_CMIN_CRASHES_ONLY"),
     caa = !!getenv("AFL_CMIN_ALLOW_ANY");

  if (!strncmp(outfile, "/dev/", 5)) {

    fd = open(outfile, O_WRONLY);

    if (fd < 0) PFATAL("Unable to open '%s'", fsrv->out_file);

  } else if (!strcmp(outfile, "-")) {

    fd = dup(1);
    if (fd < 0) PFATAL("Unable to open stdout");

  } else {

    unlink(outfile);                                       /* Ignore errors */
    fd = open(outfile, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) PFATAL("Unable to create '%s'", outfile);

  }

  if (binary_mode) {

    for (i = 0; i < MAP_SIZE; i++)
      if (fsrv->trace_bits[i]) ret++;

    ck_write(fd, fsrv->trace_bits, MAP_SIZE, outfile);
    close(fd);

  } else {

    FILE *f = fdopen(fd, "w");

    if (!f) PFATAL("fdopen() failed");

    for (i = 0; i < MAP_SIZE; i++) {

      if (!fsrv->trace_bits[i]) continue;
      ret++;

      total += fsrv->trace_bits[i];
      if (highest < fsrv->trace_bits[i]) highest = fsrv->trace_bits[i];

      if (cmin_mode) {

        if (fsrv->child_timed_out) break;
        if (!caa && child_crashed != cco) break;

        fprintf(f, "%u%u\n", fsrv->trace_bits[i], i);

      } else

        fprintf(f, "%06u:%u\n", i, fsrv->trace_bits[i]);

    }

    fclose(f);

  }

  return ret;

}

/* Write results. */

static u32 write_results(afl_forkserver_t *fsrv) {

  return write_results_to_file(fsrv, fsrv->out_file);

}

/* Write modified data to file for testing. If use_stdin is clear, the old file
   is unlinked and a new one is created. Otherwise, out_fd is rewound and
   truncated. */

static void write_to_testcase(afl_forkserver_t *fsrv, void *mem, u32 len) {

  lseek(fsrv->out_fd, 0, SEEK_SET);
  ck_write(fsrv->out_fd, mem, len, fsrv->out_file);
  if (ftruncate(fsrv->out_fd, len)) PFATAL("ftruncate() failed");
  lseek(fsrv->out_fd, 0, SEEK_SET);

}

/* Execute target application. Returns 0 if the changes are a dud, or
   1 if they should be kept. */

static u8 run_target_forkserver(afl_forkserver_t *fsrv, char **argv, u8 *mem,
                                u32 len) {

  struct itimerval it;
  int              status = 0;

  memset(fsrv->trace_bits, 0, MAP_SIZE);
  MEM_BARRIER();

  write_to_testcase(fsrv, mem, len);

  s32 res;

  /* we have the fork server up and running, so simply
     tell it to have at it, and then read back PID. */

  if ((res = write(fsrv->fsrv_ctl_fd, &fsrv->prev_timed_out, 4)) != 4) {

    if (stop_soon) return 0;
    RPFATAL(res, "Unable to request new process from fork server (OOM?)");

  }

  if ((res = read(fsrv->fsrv_st_fd, &fsrv->child_pid, 4)) != 4) {

    if (stop_soon) return 0;
    RPFATAL(res, "Unable to request new process from fork server (OOM?)");

  }

  if (fsrv->child_pid <= 0) FATAL("Fork server is misbehaving (OOM?)");

  /* Configure timeout, wait for child, cancel timeout. */

  if (fsrv->exec_tmout) {

    it.it_value.tv_sec = (fsrv->exec_tmout / 1000);
    it.it_value.tv_usec = (fsrv->exec_tmout % 1000) * 1000;

  }

  setitimer(ITIMER_REAL, &it, NULL);

  if ((res = read(fsrv->fsrv_st_fd, &status, 4)) != 4) {

    if (stop_soon) return 0;
    RPFATAL(res, "Unable to communicate with fork server (OOM?)");

  }

  fsrv->child_pid = 0;
  it.it_value.tv_sec = 0;
  it.it_value.tv_usec = 0;

  setitimer(ITIMER_REAL, &it, NULL);

  MEM_BARRIER();

  /* Clean up bitmap, analyze exit condition, etc. */

  if (*(u32 *)fsrv->trace_bits == EXEC_FAIL_SIG)
    FATAL("Unable to execute '%s'", argv[0]);

  classify_counts(fsrv->trace_bits,
                  binary_mode ? count_class_binary : count_class_human);
  total_execs++;

  if (stop_soon) {

    SAYF(cRST cLRD "\n+++ afl-showmap folder mode aborted by user +++\n" cRST);
    exit(1);

  }

  /* Always discard inputs that time out. */

  if (fsrv->child_timed_out) { return 0; }

  /* Handle crashing inputs depending on current mode. */

  if (WIFSIGNALED(status) ||
      (WIFEXITED(status) && WEXITSTATUS(status) == MSAN_ERROR) ||
      (WIFEXITED(status) && WEXITSTATUS(status))) {

    return 0;

  }

  return 0;

}

/* Read initial file. */

u32 read_file(u8 *in_file) {

  struct stat st;
  s32         fd = open(in_file, O_RDONLY);

  if (fd < 0) WARNF("Unable to open '%s'", in_file);

  if (fstat(fd, &st) || !st.st_size)
    WARNF("Zero-sized input file '%s'.", in_file);

  in_len = st.st_size;
  in_data = ck_alloc_nozero(in_len);

  ck_read(fd, in_data, in_len, in_file);

  close(fd);

  // OKF("Read %u byte%s from '%s'.", in_len, in_len == 1 ? "" : "s", in_file);

  return in_len;

}

/* Execute target application. */

static void run_target(afl_forkserver_t *fsrv, char **argv) {

  static struct itimerval it;
  int                     status = 0;

  if (!quiet_mode) SAYF("-- Program output begins --\n" cRST);

  MEM_BARRIER();

  fsrv->child_pid = fork();

  if (fsrv->child_pid < 0) PFATAL("fork() failed");

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

    if (!keep_cores)
      r.rlim_max = r.rlim_cur = 0;
    else
      r.rlim_max = r.rlim_cur = RLIM_INFINITY;

    setrlimit(RLIMIT_CORE, &r);                            /* Ignore errors */

    if (!getenv("LD_BIND_LAZY")) setenv("LD_BIND_NOW", "1", 0);

    setsid();

    execv(fsrv->target_path, argv);

    *(u32 *)fsrv->trace_bits = EXEC_FAIL_SIG;
    exit(0);

  }

  /* Configure timeout, wait for child, cancel timeout. */

  if (fsrv->exec_tmout) {

    fsrv->child_timed_out = 0;
    it.it_value.tv_sec = (fsrv->exec_tmout / 1000);
    it.it_value.tv_usec = (fsrv->exec_tmout % 1000) * 1000;

  }

  setitimer(ITIMER_REAL, &it, NULL);

  if (waitpid(fsrv->child_pid, &status, 0) <= 0) FATAL("waitpid() failed");

  fsrv->child_pid = 0;
  it.it_value.tv_sec = 0;
  it.it_value.tv_usec = 0;
  setitimer(ITIMER_REAL, &it, NULL);

  MEM_BARRIER();

  /* Clean up bitmap, analyze exit condition, etc. */

  if (*(u32 *)fsrv->trace_bits == EXEC_FAIL_SIG)
    FATAL("Unable to execute '%s'", argv[0]);

  classify_counts(fsrv->trace_bits,
                  binary_mode ? count_class_binary : count_class_human);

  if (!quiet_mode) SAYF(cRST "-- Program output ends --\n");

  if (!fsrv->child_timed_out && !stop_soon && WIFSIGNALED(status))
    child_crashed = 1;

  if (!quiet_mode) {

    if (fsrv->child_timed_out)
      SAYF(cLRD "\n+++ Program timed off +++\n" cRST);
    else if (stop_soon)
      SAYF(cLRD "\n+++ Program aborted by user +++\n" cRST);
    else if (child_crashed)
      SAYF(cLRD "\n+++ Program killed by signal %u +++\n" cRST,
           WTERMSIG(status));

  }

}

/* Handle Ctrl-C and the like. */

static void handle_stop_sig(int sig) {

  stop_soon = 1;
  afl_fsrv_killall();

}

/* Do basic preparations - persistent fds, filenames, etc. */

static void set_up_environment(void) {

  setenv("ASAN_OPTIONS",
         "abort_on_error=1:"
         "detect_leaks=0:"
         "symbolize=0:"
         "allocator_may_return_null=1",
         0);

  setenv("MSAN_OPTIONS", "exit_code=" STRINGIFY(MSAN_ERROR) ":"
                         "symbolize=0:"
                         "abort_on_error=1:"
                         "allocator_may_return_null=1:"
                         "msan_track_origins=0", 0);

  if (get_afl_env("AFL_PRELOAD")) {

    if (qemu_mode) {

      u8 *qemu_preload = getenv("QEMU_SET_ENV");
      u8 *afl_preload = getenv("AFL_PRELOAD");
      u8 *buf;

      s32 i, afl_preload_size = strlen(afl_preload);
      for (i = 0; i < afl_preload_size; ++i) {

        if (afl_preload[i] == ',')
          PFATAL(
              "Comma (',') is not allowed in AFL_PRELOAD when -Q is "
              "specified!");

      }

      if (qemu_preload)
        buf = alloc_printf("%s,LD_PRELOAD=%s,DYLD_INSERT_LIBRARIES=%s",
                           qemu_preload, afl_preload, afl_preload);
      else
        buf = alloc_printf("LD_PRELOAD=%s,DYLD_INSERT_LIBRARIES=%s",
                           afl_preload, afl_preload);

      setenv("QEMU_SET_ENV", buf, 1);

      ck_free(buf);

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
      "  -m megs       - memory limit for child process (%d MB)\n"
      "  -Q            - use binary-only instrumentation (QEMU mode)\n"
      "  -U            - use Unicorn-based instrumentation (Unicorn mode)\n"
      "  -W            - use qemu-based instrumentation with Wine (Wine mode)\n"
      "                  (Not necessary, here for consistency with other afl-* "
      "tools)\n\n"

      "Other settings:\n"

      "  -i dir        - process all files in this directory, -o must be a "
      "directory\n"
      "                  and each bitmap will be written there individually.\n"
      "  -q            - sink program's output and don't show messages\n"
      "  -e            - show edge coverage only, ignore hit counts\n"
      "  -r            - show real tuple values instead of AFL filter values\n"
      "  -c            - allow core dumps\n\n"

      "This tool displays raw tuple data captured by AFL instrumentation.\n"
      "For additional help, consult %s/README.md.\n\n"

      "Environment variables used:\n"
      "AFL_PRELOAD: LD_PRELOAD / DYLD_INSERT_LIBRARIES settings for target\n"
      "AFL_DEBUG: enable extra developer output\n"
      "AFL_QUIET: do not print extra informational output"
      "AFL_CMIN_CRASHES_ONLY: (cmin_mode) only write tuples for crashing "
      "inputs\n"
      "AFL_CMIN_ALLOW_ANY: (cmin_mode) write tuples for crashing inputs also\n"
      "LD_BIND_LAZY: do not set LD_BIND_NOW env var for target\n",
      argv0, MEM_LIMIT, doc_path);

  exit(1);

}

/* Find binary. */

static void find_binary(afl_forkserver_t *fsrv, u8 *fname) {

  u8 *        env_path = 0;
  struct stat st;

  if (strchr(fname, '/') || !(env_path = getenv("PATH"))) {

    fsrv->target_path = ck_strdup(fname);

    if (stat(fsrv->target_path, &st) || !S_ISREG(st.st_mode) ||
        !(st.st_mode & 0111) || st.st_size < 4)
      FATAL("Program '%s' not found or not executable", fname);

  } else {

    while (env_path) {

      u8 *cur_elem, *delim = strchr(env_path, ':');

      if (delim) {

        cur_elem = ck_alloc(delim - env_path + 1);
        memcpy(cur_elem, env_path, delim - env_path);
        delim++;

      } else

        cur_elem = ck_strdup(env_path);

      env_path = delim;

      if (cur_elem[0])
        fsrv->target_path = alloc_printf("%s/%s", cur_elem, fname);
      else
        fsrv->target_path = ck_strdup(fname);

      ck_free(cur_elem);

      if (!stat(fsrv->target_path, &st) && S_ISREG(st.st_mode) &&
          (st.st_mode & 0111) && st.st_size >= 4)
        break;

      ck_free(fsrv->target_path);
      fsrv->target_path = 0;

    }

    if (!fsrv->target_path)
      FATAL("Program '%s' not found or not executable", fname);

  }

}

/* Main entry point */

int main(int argc, char **argv_orig, char **envp) {

  // TODO: u64 mem_limit = MEM_LIMIT;                  /* Memory limit (MB) */

  s32    opt, i;
  u8     mem_limit_given = 0, timeout_given = 0, unicorn_mode = 0, use_wine = 0;
  u32    tcnt = 0;
  char **use_argv;

  char **argv = argv_cpy_dup(argc, argv_orig);

  afl_forkserver_t  fsrv_var = {0};
  afl_forkserver_t *fsrv = &fsrv_var;
  afl_fsrv_init(fsrv);

  doc_path = access(DOC_PATH, F_OK) ? "docs" : DOC_PATH;

  if (getenv("AFL_QUIET") != NULL) be_quiet = 1;

  while ((opt = getopt(argc, argv, "+i:o:f:m:t:A:eqZQUWbcrh")) > 0)

    switch (opt) {

      case 'i':
        if (in_dir) FATAL("Multiple -i options not supported");
        in_dir = optarg;
        break;

      case 'o':

        if (fsrv->out_file) FATAL("Multiple -o options not supported");
        fsrv->out_file = optarg;
        break;

      case 'm': {

        u8 suffix = 'M';

        if (mem_limit_given) FATAL("Multiple -m options not supported");
        mem_limit_given = 1;

        if (!strcmp(optarg, "none")) {

          fsrv->mem_limit = 0;
          break;

        }

        if (sscanf(optarg, "%llu%c", &fsrv->mem_limit, &suffix) < 1 ||
            optarg[0] == '-')
          FATAL("Bad syntax used for -m");

        switch (suffix) {

          case 'T': fsrv->mem_limit *= 1024 * 1024; break;
          case 'G': fsrv->mem_limit *= 1024; break;
          case 'k': fsrv->mem_limit /= 1024; break;
          case 'M': break;

          default: FATAL("Unsupported suffix or bad syntax for -m");

        }

        if (fsrv->mem_limit < 5) FATAL("Dangerously low value of -m");

        if (sizeof(rlim_t) == 4 && fsrv->mem_limit > 2000)
          FATAL("Value of -m out of range on 32-bit systems");

      }

      break;

      case 'f':  // only in here to avoid a compiler warning for use_stdin

        fsrv->use_stdin = 0;
        FATAL("Option -f is not supported in afl-showmap");

        break;

      case 't':

        if (timeout_given) FATAL("Multiple -t options not supported");
        timeout_given = 1;

        if (strcmp(optarg, "none")) {

          fsrv->exec_tmout = atoi(optarg);

          if (fsrv->exec_tmout < 20 || optarg[0] == '-')
            FATAL("Dangerously low value of -t");

        }

        break;

      case 'e':

        if (edges_only) FATAL("Multiple -e options not supported");
        if (raw_instr_output) FATAL("-e and -r are mutually exclusive");
        edges_only = 1;
        break;

      case 'q':

        if (quiet_mode) FATAL("Multiple -q options not supported");
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

        if (qemu_mode) FATAL("Multiple -Q options not supported");
        if (!mem_limit_given) fsrv->mem_limit = MEM_LIMIT_QEMU;

        qemu_mode = 1;
        break;

      case 'U':

        if (unicorn_mode) FATAL("Multiple -U options not supported");
        if (!mem_limit_given) fsrv->mem_limit = MEM_LIMIT_UNICORN;

        unicorn_mode = 1;
        break;

      case 'W':                                           /* Wine+QEMU mode */

        if (use_wine) FATAL("Multiple -W options not supported");
        qemu_mode = 1;
        use_wine = 1;

        if (!mem_limit_given) fsrv->mem_limit = 0;

        break;

      case 'b':

        /* Secret undocumented mode. Writes output in raw binary format
           similar to that dumped by afl-fuzz in <out_dir/queue/fuzz_bitmap. */

        binary_mode = 1;
        break;

      case 'c':

        if (keep_cores) FATAL("Multiple -c options not supported");
        keep_cores = 1;
        break;

      case 'r':

        if (raw_instr_output) FATAL("Multiple -r options not supported");
        if (edges_only) FATAL("-e and -r are mutually exclusive");
        raw_instr_output = 1;
        break;

      case 'h':
        usage(argv[0]);
        return -1;
        break;

      default: usage(argv[0]);

    }

  if (optind == argc || !fsrv->out_file) usage(argv[0]);

  check_environment_vars(envp);

  sharedmem_t shm = {0};
  fsrv->trace_bits = afl_shm_init(&shm, MAP_SIZE, 0);
  setup_signal_handlers();

  set_up_environment();

  find_binary(fsrv, argv[optind]);

  if (!quiet_mode) {

    show_banner();
    ACTF("Executing '%s'...", fsrv->target_path);

  }

  if (in_dir) {

    if (at_file) PFATAL("Options -A and -i are mutually exclusive");
    detect_file_args(argv + optind, "", &fsrv->use_stdin);

  } else {

    detect_file_args(argv + optind, at_file, &fsrv->use_stdin);

  }

  for (i = optind; i < argc; i++)
    if (strcmp(argv[i], "@@") == 0) arg_offset = i;

  if (qemu_mode) {

    if (use_wine)
      use_argv = get_wine_argv(argv[0], &fsrv->target_path, argc - optind,
                               argv + optind);
    else
      use_argv = get_qemu_argv(argv[0], &fsrv->target_path, argc - optind,
                               argv + optind);

  } else

    use_argv = argv + optind;

  if (in_dir) {

    DIR *          dir_in, *dir_out;
    struct dirent *dir_ent;
    int            done = 0;
    u8             infile[4096], outfile[4096];
#if !defined(DT_REG)
    struct stat statbuf;
#endif

    fsrv->dev_null_fd = open("/dev/null", O_RDWR);
    if (fsrv->dev_null_fd < 0) PFATAL("Unable to open /dev/null");

    if (!(dir_in = opendir(in_dir))) PFATAL("cannot open directory %s", in_dir);

    if (!(dir_out = opendir(fsrv->out_file)))
      if (mkdir(fsrv->out_file, 0700))
        PFATAL("cannot create output directory %s", fsrv->out_file);

    u8 *use_dir = ".";

    if (access(use_dir, R_OK | W_OK | X_OK)) {

      use_dir = get_afl_env("TMPDIR");
      if (!use_dir) use_dir = "/tmp";

    }

    stdin_file = alloc_printf("%s/.afl-showmap-temp-%u", use_dir, getpid());
    unlink(stdin_file);
    atexit(at_exit_handler);
    fsrv->out_fd = open(stdin_file, O_RDWR | O_CREAT | O_EXCL, 0600);
    if (fsrv->out_fd < 0) PFATAL("Unable to create '%s'", fsrv->out_file);

    if (arg_offset && argv[arg_offset] != stdin_file) {

      ck_free(argv[arg_offset]);
      argv[arg_offset] = strdup(stdin_file);

    }

    if (get_afl_env("AFL_DEBUG")) {

      int i = optind;
      SAYF(cMGN "[D]" cRST " %s:", fsrv->target_path);
      while (argv[i] != NULL)
        SAYF(" \"%s\"", argv[i++]);
      SAYF("\n");
      SAYF(cMGN "[D]" cRST " %d - %d = %d, %s\n", arg_offset, optind,
           arg_offset - optind, infile);

    }

    afl_fsrv_start(fsrv, use_argv);

    while (done == 0 && (dir_ent = readdir(dir_in))) {

      if (dir_ent->d_name[0] == '.')
        continue;  // skip anything that starts with '.'

#if defined(DT_REG)      /* Posix and Solaris do not know d_type and DT_REG */
      if (dir_ent->d_type != DT_REG) continue;  // only regular files
#endif

      snprintf(infile, sizeof(infile), "%s/%s", in_dir, dir_ent->d_name);

#if !defined(DT_REG)                                          /* use stat() */
      if (-1 == stat(infile, &statbuf) || !S_ISREG(statbuf.st_mode)) continue;
#endif

      snprintf(outfile, sizeof(outfile), "%s/%s", fsrv->out_file,
               dir_ent->d_name);

      if (read_file(infile)) {

        run_target_forkserver(fsrv, use_argv, in_data, in_len);
        ck_free(in_data);
        tcnt = write_results_to_file(fsrv, outfile);

      }

    }

    if (!quiet_mode) OKF("Processed %u input files.", total_execs);

    closedir(dir_in);
    closedir(dir_out);

  } else {

    run_target(fsrv, use_argv);
    tcnt = write_results(fsrv);

  }

  if (!quiet_mode) {

    if (!tcnt) FATAL("No instrumentation detected" cRST);
    OKF("Captured %u tuples (highest value %u, total values %u) in '%s'." cRST,
        tcnt, highest, total, fsrv->out_file);

  }

  if (stdin_file) {

    unlink(stdin_file);
    ck_free(stdin_file);
    stdin_file = NULL;

  }

  afl_shm_deinit(&shm);

  u32 ret = child_crashed * 2 + fsrv->child_timed_out;

  if (fsrv->target_path) ck_free(fsrv->target_path);

  afl_fsrv_deinit(fsrv);
  if (stdin_file) ck_free(stdin_file);

  argv_cpy_free(argv);

  exit(ret);

}

