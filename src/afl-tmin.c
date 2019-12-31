/*
   american fuzzy lop++ - test case minimizer
   ------------------------------------------

   Originally written by Michal Zalewski

   Forkserver design by Jann Horn <jannhorn@googlemail.com>

   Now maintained by by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eißfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   A simple test case minimizer that takes an input file and tries to remove
   as much data as possible while keeping the binary in a crashing state
   *or* producing consistent instrumentation output (the mode is auto-selected
   based on the initially observed behavior).

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
#include "forkserver.h"
#include "sharedmem.h"
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

s32 forksrv_pid,                        /* PID of the fork server           */
    child_pid;                          /* PID of the tested program        */

s32 fsrv_ctl_fd,                        /* Fork server control pipe (write) */
    fsrv_st_fd;                         /* Fork server status pipe (read)   */

u8*        trace_bits;                 /* SHM with instrumentation bitmap   */
static u8* mask_bitmap;                /* Mask for trace bits (-B)          */

u8 *in_file,                           /* Minimizer input test case         */
    *output_file,                      /* Minimizer output file             */
    *out_file,                         /* Targeted program input file       */
    *doc_path;                         /* Path to docs                      */

s32 out_fd;                           /* Persistent fd for out_file         */

static u8* in_data;                    /* Input data for trimming           */

static u32 in_len,                     /* Input data length                 */
    orig_cksum,                        /* Original checksum                 */
    total_execs,                       /* Total number of execs             */
    missed_hangs,                      /* Misses due to hangs               */
    missed_crashes,                    /* Misses due to crashes             */
    missed_paths;                      /* Misses due to exec path diffs     */
u32 exec_tmout = EXEC_TIMEOUT;         /* Exec timeout (ms)                 */

u64 mem_limit = MEM_LIMIT;             /* Memory limit (MB)                 */

s32 dev_null_fd = -1;                  /* FD to /dev/null                   */

u8 crash_mode,                         /* Crash-centric mode?               */
    exit_crash,                        /* Treat non-zero exit as crash?     */
    edges_only,                        /* Ignore hit counts?                */
    exact_mode,                        /* Require path match for crashes?   */
    use_stdin = 1;                     /* Use stdin for program input?      */

static volatile u8 stop_soon;          /* Ctrl-C pressed?                   */

static u8 qemu_mode;

/*
 * forkserver section
 */

/* we only need this to use afl-forkserver */
FILE* plot_file;
u8    uses_asan;
s32   out_fd = -1, out_dir_fd = -1, dev_urandom_fd = -1;

/* we import this as we need this information */
extern u8 child_timed_out;

/* Classify tuple counts. This is a slow & naive version, but good enough here.
 */

static const u8 count_class_lookup[256] = {

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

static void classify_counts(u8* mem) {

  u32 i = MAP_SIZE;

  if (edges_only) {

    while (i--) {

      if (*mem) *mem = 1;
      mem++;

    }

  } else {

    while (i--) {

      *mem = count_class_lookup[*mem];
      mem++;

    }

  }

}

/* Apply mask to classified bitmap (if set). */

static void apply_mask(u32* mem, u32* mask) {

  u32 i = (MAP_SIZE >> 2);

  if (!mask) return;

  while (i--) {

    *mem &= ~*mask;
    mem++;
    mask++;

  }

}

/* See if any bytes are set in the bitmap. */

static inline u8 anything_set(void) {

  u32* ptr = (u32*)trace_bits;
  u32  i = (MAP_SIZE >> 2);

  while (i--)
    if (*(ptr++)) return 1;

  return 0;

}

/* Get rid of temp files (atexit handler). */

static void at_exit_handler(void) {

  if (out_file) unlink(out_file);                          /* Ignore errors */

}

/* Read initial file. */

static void read_initial_file(void) {

  struct stat st;
  s32         fd = open(in_file, O_RDONLY);

  if (fd < 0) PFATAL("Unable to open '%s'", in_file);

  if (fstat(fd, &st) || !st.st_size) FATAL("Zero-sized input file.");

  if (st.st_size >= TMIN_MAX_FILE)
    FATAL("Input file is too large (%u MB max)", TMIN_MAX_FILE / 1024 / 1024);

  in_len = st.st_size;
  in_data = ck_alloc_nozero(in_len);

  ck_read(fd, in_data, in_len, in_file);

  close(fd);

  OKF("Read %u byte%s from '%s'.", in_len, in_len == 1 ? "" : "s", in_file);

}

/* Write output file. */

static s32 write_to_file(u8* path, u8* mem, u32 len) {

  s32 ret;

  unlink(path);                                            /* Ignore errors */

  ret = open(path, O_RDWR | O_CREAT | O_EXCL, 0600);

  if (ret < 0) PFATAL("Unable to create '%s'", path);

  ck_write(ret, mem, len, path);

  lseek(ret, 0, SEEK_SET);

  return ret;

}

/* Write modified data to file for testing. If use_stdin is clear, the old file
   is unlinked and a new one is created. Otherwise, out_fd is rewound and
   truncated. */

static void write_to_testcase(void* mem, u32 len) {

  s32 fd = out_fd;

  if (!use_stdin) {

    unlink(out_file);                                     /* Ignore errors. */

    fd = open(out_file, O_WRONLY | O_CREAT | O_EXCL, 0600);

    if (fd < 0) PFATAL("Unable to create '%s'", out_file);

  } else

    lseek(fd, 0, SEEK_SET);

  ck_write(fd, mem, len, out_file);

  if (use_stdin) {

    if (ftruncate(fd, len)) PFATAL("ftruncate() failed");
    lseek(fd, 0, SEEK_SET);

  } else

    close(fd);

}

/* Handle timeout signal. */
/*
static void handle_timeout(int sig) {

  if (child_pid > 0) {

  child_timed_out = 1;
    kill(child_pid, SIGKILL);

  } else if (child_pid == -1 && forksrv_pid > 0) {

    child_timed_out = 1;
    kill(forksrv_pid, SIGKILL);

  }

}

*/

/* start the app and it's forkserver */
/*
static void init_forkserver(char **argv) {

  static struct itimerval it;
  int st_pipe[2], ctl_pipe[2];
  int status = 0;
  s32 rlen;

  ACTF("Spinning up the fork server...");
  if (pipe(st_pipe) || pipe(ctl_pipe)) PFATAL("pipe() failed");

  forksrv_pid = fork();

  if (forksrv_pid < 0) PFATAL("fork() failed");

  if (!forksrv_pid) {

    struct rlimit r;

    if (dup2(use_stdin ? out_fd : dev_null_fd, 0) < 0 ||
        dup2(dev_null_fd, 1) < 0 ||
        dup2(dev_null_fd, 2) < 0) {

      *(u32*)trace_bits = EXEC_FAIL_SIG;
      PFATAL("dup2() failed");

    }

    close(dev_null_fd);
    close(out_fd);

    setsid();

    if (mem_limit) {

      r.rlim_max = r.rlim_cur = ((rlim_t)mem_limit) << 20;

#ifdef RLIMIT_AS

      setrlimit(RLIMIT_AS, &r); // Ignore errors

#else

      setrlimit(RLIMIT_DATA, &r); // Ignore errors

#endif // ^RLIMIT_AS

    }

    r.rlim_max = r.rlim_cur = 0;
    setrlimit(RLIMIT_CORE, &r); // Ignore errors

    // Set up control and status pipes, close the unneeded original fds.

    if (dup2(ctl_pipe[0], FORKSRV_FD) < 0) PFATAL("dup2() failed");
    if (dup2(st_pipe[1], FORKSRV_FD + 1) < 0) PFATAL("dup2() failed");

    close(ctl_pipe[0]);
    close(ctl_pipe[1]);
    close(st_pipe[0]);
    close(st_pipe[1]);

    execv(target_path, argv);

    *(u32*)trace_bits = EXEC_FAIL_SIG;
    exit(0);

  }

  // Close the unneeded endpoints.

  close(ctl_pipe[0]);
  close(st_pipe[1]);

  fsrv_ctl_fd = ctl_pipe[1];
  fsrv_st_fd  = st_pipe[0];

  // Configure timeout, wait for child, cancel timeout.

  if (exec_tmout) {

    child_timed_out = 0;
    it.it_value.tv_sec = (exec_tmout * FORK_WAIT_MULT / 1000);
    it.it_value.tv_usec = ((exec_tmout * FORK_WAIT_MULT) % 1000) * 1000;

  }

  setitimer(ITIMER_REAL, &it, NULL);

  rlen = read(fsrv_st_fd, &status, 4);

  it.it_value.tv_sec = 0;
  it.it_value.tv_usec = 0;
  setitimer(ITIMER_REAL, &it, NULL);

  // If we have a four-byte "hello" message from the server, we're all set.
  // Otherwise, try to figure out what went wrong.

  if (rlen == 4) {

    ACTF("All right - fork server is up.");
    return;

  }

  if (waitpid(forksrv_pid, &status, 0) <= 0)
    PFATAL("waitpid() failed");

  u8 child_crashed;

  if (WIFSIGNALED(status))
    child_crashed = 1;

  if (child_timed_out)
    SAYF(cLRD "\n+++ Program timed off +++\n" cRST);
  else if (stop_soon)
    SAYF(cLRD "\n+++ Program aborted by user +++\n" cRST);
  else if (child_crashed)
    SAYF(cLRD "\n+++ Program killed by signal %u +++\n" cRST, WTERMSIG(status));

}

*/

/* Execute target application. Returns 0 if the changes are a dud, or
   1 if they should be kept. */

static u8 run_target(char** argv, u8* mem, u32 len, u8 first_run) {

  static struct itimerval it;
  static u32              prev_timed_out = 0;
  int                     status = 0;

  u32 cksum;

  memset(trace_bits, 0, MAP_SIZE);
  MEM_BARRIER();

  write_to_testcase(mem, len);

  s32 res;

  /* we have the fork server up and running, so simply
     tell it to have at it, and then read back PID. */

  if ((res = write(fsrv_ctl_fd, &prev_timed_out, 4)) != 4) {

    if (stop_soon) return 0;
    RPFATAL(res, "Unable to request new process from fork server (OOM?)");

  }

  if ((res = read(fsrv_st_fd, &child_pid, 4)) != 4) {

    if (stop_soon) return 0;
    RPFATAL(res, "Unable to request new process from fork server (OOM?)");

  }

  if (child_pid <= 0) FATAL("Fork server is misbehaving (OOM?)");

  /* Configure timeout, wait for child, cancel timeout. */

  if (exec_tmout) {

    it.it_value.tv_sec = (exec_tmout / 1000);
    it.it_value.tv_usec = (exec_tmout % 1000) * 1000;

  }

  setitimer(ITIMER_REAL, &it, NULL);

  if ((res = read(fsrv_st_fd, &status, 4)) != 4) {

    if (stop_soon) return 0;
    RPFATAL(res, "Unable to communicate with fork server (OOM?)");

  }

  child_pid = 0;
  it.it_value.tv_sec = 0;
  it.it_value.tv_usec = 0;

  setitimer(ITIMER_REAL, &it, NULL);

  MEM_BARRIER();

  /* Clean up bitmap, analyze exit condition, etc. */

  if (*(u32*)trace_bits == EXEC_FAIL_SIG)
    FATAL("Unable to execute '%s'", argv[0]);

  classify_counts(trace_bits);
  apply_mask((u32*)trace_bits, (u32*)mask_bitmap);
  total_execs++;

  if (stop_soon) {

    SAYF(cRST cLRD "\n+++ Minimization aborted by user +++\n" cRST);
    close(write_to_file(output_file, in_data, in_len));
    exit(1);

  }

  /* Always discard inputs that time out. */

  if (child_timed_out) {

    missed_hangs++;
    return 0;

  }

  /* Handle crashing inputs depending on current mode. */

  if (WIFSIGNALED(status) ||
      (WIFEXITED(status) && WEXITSTATUS(status) == MSAN_ERROR) ||
      (WIFEXITED(status) && WEXITSTATUS(status) && exit_crash)) {

    if (first_run) crash_mode = 1;

    if (crash_mode) {

      if (!exact_mode) return 1;

    } else {

      missed_crashes++;
      return 0;

    }

  } else

      /* Handle non-crashing inputs appropriately. */

      if (crash_mode) {

    missed_paths++;
    return 0;

  }

  cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);

  if (first_run) orig_cksum = cksum;

  if (orig_cksum == cksum) return 1;

  missed_paths++;
  return 0;

}

/* Find first power of two greater or equal to val. */

static u32 next_p2(u32 val) {

  u32 ret = 1;
  while (val > ret)
    ret <<= 1;
  return ret;

}

/* Actually minimize! */

static void minimize(char** argv) {

  static u32 alpha_map[256];

  u8* tmp_buf = ck_alloc_nozero(in_len);
  u32 orig_len = in_len, stage_o_len;

  u32 del_len, set_len, del_pos, set_pos, i, alpha_size, cur_pass = 0;
  u32 syms_removed, alpha_del0 = 0, alpha_del1, alpha_del2, alpha_d_total = 0;
  u8  changed_any, prev_del;

  /***********************
   * BLOCK NORMALIZATION *
   ***********************/

  set_len = next_p2(in_len / TMIN_SET_STEPS);
  set_pos = 0;

  if (set_len < TMIN_SET_MIN_SIZE) set_len = TMIN_SET_MIN_SIZE;

  ACTF(cBRI "Stage #0: " cRST "One-time block normalization...");

  while (set_pos < in_len) {

    u32 use_len = MIN(set_len, in_len - set_pos);

    for (i = 0; i < use_len; i++)
      if (in_data[set_pos + i] != '0') break;

    if (i != use_len) {

      memcpy(tmp_buf, in_data, in_len);
      memset(tmp_buf + set_pos, '0', use_len);

      u8 res;
      res = run_target(argv, tmp_buf, in_len, 0);

      if (res) {

        memset(in_data + set_pos, '0', use_len);
        /*        changed_any = 1; value is not used */
        alpha_del0 += use_len;

      }

    }

    set_pos += set_len;

  }

  alpha_d_total += alpha_del0;

  OKF("Block normalization complete, %u byte%s replaced.", alpha_del0,
      alpha_del0 == 1 ? "" : "s");

next_pass:

  ACTF(cYEL "--- " cBRI "Pass #%u " cYEL "---", ++cur_pass);
  changed_any = 0;

  /******************
   * BLOCK DELETION *
   ******************/

  del_len = next_p2(in_len / TRIM_START_STEPS);
  stage_o_len = in_len;

  ACTF(cBRI "Stage #1: " cRST "Removing blocks of data...");

next_del_blksize:

  if (!del_len) del_len = 1;
  del_pos = 0;
  prev_del = 1;

  SAYF(cGRA "    Block length = %u, remaining size = %u\n" cRST, del_len,
       in_len);

  while (del_pos < in_len) {

    u8  res;
    s32 tail_len;

    tail_len = in_len - del_pos - del_len;
    if (tail_len < 0) tail_len = 0;

    /* If we have processed at least one full block (initially, prev_del == 1),
       and we did so without deleting the previous one, and we aren't at the
       very end of the buffer (tail_len > 0), and the current block is the same
       as the previous one... skip this step as a no-op. */

    if (!prev_del && tail_len &&
        !memcmp(in_data + del_pos - del_len, in_data + del_pos, del_len)) {

      del_pos += del_len;
      continue;

    }

    prev_del = 0;

    /* Head */
    memcpy(tmp_buf, in_data, del_pos);

    /* Tail */
    memcpy(tmp_buf + del_pos, in_data + del_pos + del_len, tail_len);

    res = run_target(argv, tmp_buf, del_pos + tail_len, 0);

    if (res) {

      memcpy(in_data, tmp_buf, del_pos + tail_len);
      prev_del = 1;
      in_len = del_pos + tail_len;

      changed_any = 1;

    } else

      del_pos += del_len;

  }

  if (del_len > 1 && in_len >= 1) {

    del_len /= 2;
    goto next_del_blksize;

  }

  OKF("Block removal complete, %u bytes deleted.", stage_o_len - in_len);

  if (!in_len && changed_any)
    WARNF(cLRD
          "Down to zero bytes - check the command line and mem limit!" cRST);

  if (cur_pass > 1 && !changed_any) goto finalize_all;

  /*************************
   * ALPHABET MINIMIZATION *
   *************************/

  alpha_size = 0;
  alpha_del1 = 0;
  syms_removed = 0;

  memset(alpha_map, 0, sizeof(alpha_map));

  for (i = 0; i < in_len; i++) {

    if (!alpha_map[in_data[i]]) alpha_size++;
    alpha_map[in_data[i]]++;

  }

  ACTF(cBRI "Stage #2: " cRST "Minimizing symbols (%u code point%s)...",
       alpha_size, alpha_size == 1 ? "" : "s");

  for (i = 0; i < 256; i++) {

    u32 r;
    u8  res;

    if (i == '0' || !alpha_map[i]) continue;

    memcpy(tmp_buf, in_data, in_len);

    for (r = 0; r < in_len; r++)
      if (tmp_buf[r] == i) tmp_buf[r] = '0';

    res = run_target(argv, tmp_buf, in_len, 0);

    if (res) {

      memcpy(in_data, tmp_buf, in_len);
      syms_removed++;
      alpha_del1 += alpha_map[i];
      changed_any = 1;

    }

  }

  alpha_d_total += alpha_del1;

  OKF("Symbol minimization finished, %u symbol%s (%u byte%s) replaced.",
      syms_removed, syms_removed == 1 ? "" : "s", alpha_del1,
      alpha_del1 == 1 ? "" : "s");

  /**************************
   * CHARACTER MINIMIZATION *
   **************************/

  alpha_del2 = 0;

  ACTF(cBRI "Stage #3: " cRST "Character minimization...");

  memcpy(tmp_buf, in_data, in_len);

  for (i = 0; i < in_len; i++) {

    u8 res, orig = tmp_buf[i];

    if (orig == '0') continue;
    tmp_buf[i] = '0';

    res = run_target(argv, tmp_buf, in_len, 0);

    if (res) {

      in_data[i] = '0';
      alpha_del2++;
      changed_any = 1;

    } else

      tmp_buf[i] = orig;

  }

  alpha_d_total += alpha_del2;

  OKF("Character minimization done, %u byte%s replaced.", alpha_del2,
      alpha_del2 == 1 ? "" : "s");

  if (changed_any) goto next_pass;

finalize_all:

  SAYF("\n" cGRA "     File size reduced by : " cRST
       "%0.02f%% (to %u byte%s)\n" cGRA "    Characters simplified : " cRST
       "%0.02f%%\n" cGRA "     Number of execs done : " cRST "%u\n" cGRA
       "          Fruitless execs : " cRST "path=%u crash=%u hang=%s%u\n\n",
       100 - ((double)in_len) * 100 / orig_len, in_len, in_len == 1 ? "" : "s",
       ((double)(alpha_d_total)) * 100 / (in_len ? in_len : 1), total_execs,
       missed_paths, missed_crashes, missed_hangs ? cLRD : "", missed_hangs);

  if (total_execs > 50 && missed_hangs * 10 > total_execs)
    WARNF(cLRD "Frequent timeouts - results may be skewed." cRST);

}

/* Handle Ctrl-C and the like. */

static void handle_stop_sig(int sig) {

  stop_soon = 1;

  if (child_pid > 0) kill(child_pid, SIGKILL);

}

/* Do basic preparations - persistent fds, filenames, etc. */

static void set_up_environment(void) {

  u8* x;

  dev_null_fd = open("/dev/null", O_RDWR);
  if (dev_null_fd < 0) PFATAL("Unable to open /dev/null");

  if (!out_file) {

    u8* use_dir = ".";

    if (access(use_dir, R_OK | W_OK | X_OK)) {

      use_dir = getenv("TMPDIR");
      if (!use_dir) use_dir = "/tmp";

    }

    out_file = alloc_printf("%s/.afl-tmin-temp-%u", use_dir, getpid());

  }

  unlink(out_file);

  out_fd = open(out_file, O_RDWR | O_CREAT | O_EXCL, 0600);

  if (out_fd < 0) PFATAL("Unable to create '%s'", out_file);

  /* Set sane defaults... */

  x = getenv("ASAN_OPTIONS");

  if (x) {

    if (!strstr(x, "abort_on_error=1"))
      FATAL("Custom ASAN_OPTIONS set without abort_on_error=1 - please fix!");

    if (!strstr(x, "symbolize=0"))
      FATAL("Custom ASAN_OPTIONS set without symbolize=0 - please fix!");

  }

  x = getenv("MSAN_OPTIONS");

  if (x) {

    if (!strstr(x, "exit_code=" STRINGIFY(MSAN_ERROR)))
      FATAL("Custom MSAN_OPTIONS set without exit_code=" STRINGIFY(
          MSAN_ERROR) " - please fix!");

    if (!strstr(x, "symbolize=0"))
      FATAL("Custom MSAN_OPTIONS set without symbolize=0 - please fix!");

  }

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

  if (getenv("AFL_PRELOAD")) {

    if (qemu_mode) {

      u8* qemu_preload = getenv("QEMU_SET_ENV");
      u8* afl_preload = getenv("AFL_PRELOAD");
      u8* buf;

      s32 i, afl_preload_size = strlen(afl_preload);
      for (i = 0; i < afl_preload_size; ++i) {

        if (afl_preload[i] == ',')
          PFATAL(
              "Comma (',') is not allowed in AFL_PRELOAD when -Q is "
              "specified!");

      }

      if (qemu_preload)
        buf = alloc_printf("%s,LD_PRELOAD=%s", qemu_preload, afl_preload);
      else
        buf = alloc_printf("LD_PRELOAD=%s", afl_preload);

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

  /* Exec timeout notifications. */

  sa.sa_handler = handle_timeout;
  sigaction(SIGALRM, &sa, NULL);

}

/* Display usage hints. */

static void usage(u8* argv0) {

  SAYF(
      "\n%s [ options ] -- /path/to/target_app [ ... ]\n\n"

      "Required parameters:\n\n"

      "  -i file       - input test case to be shrunk by the tool\n"
      "  -o file       - final output location for the minimized data\n\n"

      "Execution control settings:\n\n"

      "  -f file       - input file read by the tested program (stdin)\n"
      "  -t msec       - timeout for each run (%d ms)\n"
      "  -m megs       - memory limit for child process (%d MB)\n"
      "  -Q            - use binary-only instrumentation (QEMU mode)\n"
      "  -U            - use unicorn-based instrumentation (Unicorn mode)\n"
      "  -W            - use qemu-based instrumentation with Wine (Wine "
      "mode)\n\n"
      "                  (Not necessary, here for consistency with other afl-* "
      "tools)\n\n"

      "Minimization settings:\n\n"

      "  -e            - solve for edge coverage only, ignore hit counts\n"
      "  -x            - treat non-zero exit codes as crashes\n\n"

      "For additional tips, please consult %s/README.\n\n",

      argv0, EXEC_TIMEOUT, MEM_LIMIT, doc_path);

  exit(1);

}

/* Find binary. */

static void find_binary(u8* fname) {

  u8*         env_path = 0;
  struct stat st;

  if (strchr(fname, '/') || !(env_path = getenv("PATH"))) {

    target_path = ck_strdup(fname);

    if (stat(target_path, &st) || !S_ISREG(st.st_mode) ||
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
        target_path = alloc_printf("%s/%s", cur_elem, fname);
      else
        target_path = ck_strdup(fname);

      ck_free(cur_elem);

      if (!stat(target_path, &st) && S_ISREG(st.st_mode) &&
          (st.st_mode & 0111) && st.st_size >= 4)
        break;

      ck_free(target_path);
      target_path = 0;

    }

    if (!target_path) FATAL("Program '%s' not found or not executable", fname);

  }

}

/* Read mask bitmap from file. This is for the -B option. */

static void read_bitmap(u8* fname) {

  s32 fd = open(fname, O_RDONLY);

  if (fd < 0) PFATAL("Unable to open '%s'", fname);

  ck_read(fd, mask_bitmap, MAP_SIZE, fname);

  close(fd);

}

/* Main entry point */

int main(int argc, char** argv) {

  s32    opt;
  u8     mem_limit_given = 0, timeout_given = 0, unicorn_mode = 0, use_wine = 0;
  char** use_argv;

  doc_path = access(DOC_PATH, F_OK) ? "docs" : DOC_PATH;

  SAYF(cCYA "afl-tmin" VERSION cRST " by Michal Zalewski\n");

  while ((opt = getopt(argc, argv, "+i:o:f:m:t:B:xeQUWh")) > 0)

    switch (opt) {

      case 'i':

        if (in_file) FATAL("Multiple -i options not supported");
        in_file = optarg;
        break;

      case 'o':

        if (output_file) FATAL("Multiple -o options not supported");
        output_file = optarg;
        break;

      case 'f':

        if (out_file) FATAL("Multiple -f options not supported");
        use_stdin = 0;
        out_file = optarg;
        break;

      case 'e':

        if (edges_only) FATAL("Multiple -e options not supported");
        edges_only = 1;
        break;

      case 'x':

        if (exit_crash) FATAL("Multiple -x options not supported");
        exit_crash = 1;
        break;

      case 'm': {

        u8 suffix = 'M';

        if (mem_limit_given) FATAL("Multiple -m options not supported");
        mem_limit_given = 1;

        if (!strcmp(optarg, "none")) {

          mem_limit = 0;
          break;

        }

        if (sscanf(optarg, "%llu%c", &mem_limit, &suffix) < 1 ||
            optarg[0] == '-')
          FATAL("Bad syntax used for -m");

        switch (suffix) {

          case 'T': mem_limit *= 1024 * 1024; break;
          case 'G': mem_limit *= 1024; break;
          case 'k': mem_limit /= 1024; break;
          case 'M': break;

          default: FATAL("Unsupported suffix or bad syntax for -m");

        }

        if (mem_limit < 5) FATAL("Dangerously low value of -m");

        if (sizeof(rlim_t) == 4 && mem_limit > 2000)
          FATAL("Value of -m out of range on 32-bit systems");

      }

      break;

      case 't':

        if (timeout_given) FATAL("Multiple -t options not supported");
        timeout_given = 1;

        exec_tmout = atoi(optarg);

        if (exec_tmout < 10 || optarg[0] == '-')
          FATAL("Dangerously low value of -t");

        break;

      case 'Q':

        if (qemu_mode) FATAL("Multiple -Q options not supported");
        if (!mem_limit_given) mem_limit = MEM_LIMIT_QEMU;

        qemu_mode = 1;
        break;

      case 'U':

        if (unicorn_mode) FATAL("Multiple -Q options not supported");
        if (!mem_limit_given) mem_limit = MEM_LIMIT_UNICORN;

        unicorn_mode = 1;
        break;

      case 'W':                                           /* Wine+QEMU mode */

        if (use_wine) FATAL("Multiple -W options not supported");
        qemu_mode = 1;
        use_wine = 1;

        if (!mem_limit_given) mem_limit = 0;

        break;

      case 'B':                                              /* load bitmap */

        /* This is a secret undocumented option! It is speculated to be useful
           if you have a baseline "boring" input file and another "interesting"
           file you want to minimize.

           You can dump a binary bitmap for the boring file using
           afl-showmap -b, and then load it into afl-tmin via -B. The minimizer
           will then minimize to preserve only the edges that are unique to
           the interesting input file, but ignoring everything from the
           original map.

           The option may be extended and made more official if it proves
           to be useful. */

        if (mask_bitmap) FATAL("Multiple -B options not supported");
        mask_bitmap = ck_alloc(MAP_SIZE);
        read_bitmap(optarg);
        break;

      case 'h':
        usage(argv[0]);
        return -1;
        break;

      default: usage(argv[0]);

    }

  if (optind == argc || !in_file || !output_file) usage(argv[0]);

  setup_shm(0);
  atexit(at_exit_handler);
  setup_signal_handlers();

  set_up_environment();

  find_binary(argv[optind]);
  detect_file_args(argv + optind, out_file);

  if (qemu_mode) {

    if (use_wine)
      use_argv = get_wine_argv(argv[0], argv + optind, argc - optind);
    else
      use_argv = get_qemu_argv(argv[0], argv + optind, argc - optind);

  } else

    use_argv = argv + optind;

  exact_mode = !!getenv("AFL_TMIN_EXACT");

  SAYF("\n");

  read_initial_file();

  init_forkserver(use_argv);

  ACTF("Performing dry run (mem limit = %llu MB, timeout = %u ms%s)...",
       mem_limit, exec_tmout, edges_only ? ", edges only" : "");

  run_target(use_argv, in_data, in_len, 1);

  if (child_timed_out)
    FATAL("Target binary times out (adjusting -t may help).");

  if (!crash_mode) {

    OKF("Program terminates normally, minimizing in " cCYA "instrumented" cRST
        " mode.");

    if (!anything_set()) FATAL("No instrumentation detected.");

  } else {

    OKF("Program exits with a signal, minimizing in " cMGN "%scrash" cRST
        " mode.",
        exact_mode ? "EXACT " : "");

  }

  minimize(use_argv);

  ACTF("Writing output to '%s'...", output_file);

  unlink(out_file);
  out_file = NULL;

  close(write_to_file(output_file, in_data, in_len));

  OKF("We're done here. Have a nice day!\n");

  exit(0);

}

