/*
   american fuzzy lop++ - file format analyzer
   -------------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eißfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2022 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   A nifty utility that grabs an input file and takes a stab at explaining
   its structure by observing how changes to it affect the execution path.

   If the output scrolls past the edge of the screen, pipe it to 'less -r'.

 */

#define AFL_MAIN

#include "config.h"
#include "types.h"
#include "debug.h"
#include "alloc-inl.h"
#include "hash.h"
#include "sharedmem.h"
#include "common.h"
#include "forkserver.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h>
#include <fcntl.h>
#include <ctype.h>

#include <sys/wait.h>
#include <sys/time.h>
#ifndef USEMMAP
  #include <sys/shm.h>
#endif
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>

static u8 *in_file;                    /* Analyzer input test case          */

static u8 *in_data;                    /* Input data for analysis           */

static u32 in_len,                     /* Input data length                 */
    total_execs,                       /* Total number of execs             */
    exec_hangs,                        /* Total number of hangs             */
    exec_tmout = EXEC_TIMEOUT;         /* Exec timeout (ms)                 */

static u64 orig_cksum;                 /* Original checksum                 */

static u64 mem_limit = MEM_LIMIT;      /* Memory limit (MB)                 */

static bool edges_only,                  /* Ignore hit counts?              */
    use_hex_offsets,                   /* Show hex offsets?                 */
    use_stdin = true;                     /* Use stdin for program input?   */

static volatile u8 stop_soon;          /* Ctrl-C pressed?                   */

static u8 *target_path;
static u8  frida_mode;
static u8  qemu_mode;
static u8  cs_mode;
static u32 map_size = MAP_SIZE;

static afl_forkserver_t fsrv = {0};   /* The forkserver                     */

/* Constants used for describing byte behavior. */

#define RESP_NONE 0x00                 /* Changing byte is a no-op.         */
#define RESP_MINOR 0x01                /* Some changes have no effect.      */
#define RESP_VARIABLE 0x02             /* Changes produce variable paths.   */
#define RESP_FIXED 0x03                /* Changes produce fixed patterns.   */

#define RESP_LEN 0x04                  /* Potential length field            */
#define RESP_CKSUM 0x05                /* Potential checksum                */
#define RESP_SUSPECT 0x06              /* Potential "suspect" blob          */

/* Classify tuple counts. This is a slow & naive version, but good enough here.
 */

static u8 count_class_lookup[256] = {

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

  if (fsrv.child_pid > 0) {

    kill(fsrv.child_pid, fsrv.kill_signal);
    fsrv.child_pid = -1;

  }

}

static void classify_counts(u8 *mem) {

  u32 i = map_size;

  if (edges_only) {

    while (i--) {

      if (*mem) { *mem = 1; }
      mem++;

    }

  } else {

    while (i--) {

      *mem = count_class_lookup[*mem];
      mem++;

    }

  }

}

/* See if any bytes are set in the bitmap. */

static inline u8 anything_set(void) {

  u32 *ptr = (u32 *)fsrv.trace_bits;
  u32  i = (map_size >> 2);

  while (i--) {

    if (*(ptr++)) { return 1; }

  }

  return 0;

}

/* Get rid of temp files (atexit handler). */

static void at_exit_handler(void) {

  unlink(fsrv.out_file);                                   /* Ignore errors */

}

/* Read initial file. */

static void read_initial_file(void) {

  struct stat st;
  s32         fd = open(in_file, O_RDONLY);

  if (fd < 0) { PFATAL("Unable to open '%s'", in_file); }

  if (fstat(fd, &st) || !st.st_size) { FATAL("Zero-sized input file."); }

  if (st.st_size >= TMIN_MAX_FILE) {

    FATAL("Input file is too large (%ld MB max)", TMIN_MAX_FILE / 1024 / 1024);

  }

  in_len = st.st_size;
  in_data = ck_alloc_nozero(in_len);

  ck_read(fd, in_data, in_len, in_file);

  close(fd);

  OKF("Read %u byte%s from '%s'.", in_len, in_len == 1 ? "" : "s", in_file);

}

/* Execute target application. Returns exec checksum, or 0 if program
   times out. */

static u32 analyze_run_target(u8 *mem, u32 len, u8 first_run) {

  afl_fsrv_write_to_testcase(&fsrv, mem, len);
  fsrv_run_result_t ret = afl_fsrv_run_target(&fsrv, exec_tmout, &stop_soon);

  if (ret == FSRV_RUN_ERROR) {

    FATAL("Error in forkserver");

  } else if (ret == FSRV_RUN_NOINST) {

    FATAL("Target not instrumented");

  } else if (ret == FSRV_RUN_NOBITS) {

    FATAL("Failed to run target");

  }

  classify_counts(fsrv.trace_bits);
  total_execs++;

  if (stop_soon) {

    SAYF(cRST cLRD "\n+++ Analysis aborted by user +++\n" cRST);
    exit(1);

  }

  /* Always discard inputs that time out. */

  if (fsrv.last_run_timed_out) {

    exec_hangs++;
    return 0;

  }

  u64 cksum = hash64(fsrv.trace_bits, fsrv.map_size, HASH_CONST);

  if (ret == FSRV_RUN_CRASH) {

    /* We don't actually care if the target is crashing or not,
       except that when it does, the checksum should be different. */

    cksum ^= 0xffffffff;

  }

  if (first_run) { orig_cksum = cksum; }

  return cksum;

}

#ifdef USE_COLOR

/* Helper function to display a human-readable character. */

static void show_char(u8 val) {

  switch (val) {

    case 0 ... 32:
    case 127 ... 255:
      SAYF("#%02x", val);
      break;

    default:
      SAYF(" %c ", val);

  }

}

/* Show the legend */

static void show_legend(void) {

  SAYF("    " cLGR bgGRA " 01 " cRST " - no-op block              " cBLK bgLGN
       " 01 " cRST
       " - suspected length field\n"
       "    " cBRI bgGRA " 01 " cRST " - superficial content      " cBLK bgYEL
       " 01 " cRST
       " - suspected cksum or magic int\n"
       "    " cBLK bgCYA " 01 " cRST " - critical stream          " cBLK bgLRD
       " 01 " cRST
       " - suspected checksummed block\n"
       "    " cBLK bgMGN " 01 " cRST " - \"magic value\" section\n\n");

}

#endif                                                         /* USE_COLOR */

/* Interpret and report a pattern in the input file. */

static void dump_hex(u32 len, u8 *b_data) {

  u32 i;

  for (i = 0; i < len; i++) {

#ifdef USE_COLOR
    u32 rlen = 1, off;
#else
    u32 rlen = 1;
#endif                                                        /* ^USE_COLOR */

    u8 rtype = b_data[i] & 0x0f;

    /* Look ahead to determine the length of run. */

    while (i + rlen < len && (b_data[i] >> 7) == (b_data[i + rlen] >> 7)) {

      if (rtype < (b_data[i + rlen] & 0x0f)) {

        rtype = b_data[i + rlen] & 0x0f;

      }

      rlen++;

    }

    /* Try to do some further classification based on length & value. */

    if (rtype == RESP_FIXED) {

      switch (rlen) {

        case 2: {

          u16 val = *(u16 *)(in_data + i);

          /* Small integers may be length fields. */

          if (val && (val <= in_len || SWAP16(val) <= in_len)) {

            rtype = RESP_LEN;
            break;

          }

          /* Uniform integers may be checksums. */

          if (val && abs(in_data[i] - in_data[i + 1]) > 32) {

            rtype = RESP_CKSUM;
            break;

          }

          break;

        }

        case 4: {

          u32 val = *(u32 *)(in_data + i);

          /* Small integers may be length fields. */

          if (val && (val <= in_len || SWAP32(val) <= in_len)) {

            rtype = RESP_LEN;
            break;

          }

          /* Uniform integers may be checksums. */

          if (val && (in_data[i] >> 7 != in_data[i + 1] >> 7 ||
                      in_data[i] >> 7 != in_data[i + 2] >> 7 ||
                      in_data[i] >> 7 != in_data[i + 3] >> 7)) {

            rtype = RESP_CKSUM;
            break;

          }

          break;

        }

        case 1:
        case 3:
        case 5 ... MAX_AUTO_EXTRA - 1:
          break;

        default:
          rtype = RESP_SUSPECT;

      }

    }

    /* Print out the entire run. */

#ifdef USE_COLOR

    for (off = 0; off < rlen; off++) {

      /* Every 16 digits, display offset. */

      if (!((i + off) % 16)) {

        if (off) { SAYF(cRST cLCY ">"); }

        if (use_hex_offsets) {

          SAYF(cRST cGRA "%s[%06x] " cRST, (i + off) ? "\n" : "", i + off);

        } else {

          SAYF(cRST cGRA "%s[%06u] " cRST, (i + off) ? "\n" : "", i + off);

        }

      }

      switch (rtype) {

        case RESP_NONE:
          SAYF(cLGR bgGRA);
          break;
        case RESP_MINOR:
          SAYF(cBRI bgGRA);
          break;
        case RESP_VARIABLE:
          SAYF(cBLK bgCYA);
          break;
        case RESP_FIXED:
          SAYF(cBLK bgMGN);
          break;
        case RESP_LEN:
          SAYF(cBLK bgLGN);
          break;
        case RESP_CKSUM:
          SAYF(cBLK bgYEL);
          break;
        case RESP_SUSPECT:
          SAYF(cBLK bgLRD);
          break;

      }

      show_char(in_data[i + off]);

      if (off != rlen - 1 && (i + off + 1) % 16) {

        SAYF(" ");

      } else {

        SAYF(cRST " ");

      }

    }

#else

    if (use_hex_offsets)
      SAYF("    Offset %x, length %u: ", i, rlen);
    else
      SAYF("    Offset %u, length %u: ", i, rlen);

    switch (rtype) {

      case RESP_NONE:
        SAYF("no-op block\n");
        break;
      case RESP_MINOR:
        SAYF("superficial content\n");
        break;
      case RESP_VARIABLE:
        SAYF("critical stream\n");
        break;
      case RESP_FIXED:
        SAYF("\"magic value\" section\n");
        break;
      case RESP_LEN:
        SAYF("suspected length field\n");
        break;
      case RESP_CKSUM:
        SAYF("suspected cksum or magic int\n");
        break;
      case RESP_SUSPECT:
        SAYF("suspected checksummed block\n");
        break;

    }

#endif                                                        /* ^USE_COLOR */

    i += rlen - 1;

  }

#ifdef USE_COLOR
  SAYF(cRST "\n");
#endif                                                         /* USE_COLOR */

}

/* Actually analyze! */

static void analyze() {

  u32 i;
  u32 boring_len = 0, prev_xff = 0, prev_x01 = 0, prev_s10 = 0, prev_a10 = 0;

  u8 *b_data = ck_alloc(in_len + 1);
  u8  seq_byte = 0;

  b_data[in_len] = 0xff;                         /* Intentional terminator. */

  ACTF("Analyzing input file (this may take a while)...\n");

#ifdef USE_COLOR
  show_legend();
#endif                                                         /* USE_COLOR */

  for (i = 0; i < in_len; i++) {

    u32 xor_ff, xor_01, sub_10, add_10;
    u8  xff_orig, x01_orig, s10_orig, a10_orig;

    /* Perform walking byte adjustments across the file. We perform four
       operations designed to elicit some response from the underlying
       code. */

    in_data[i] ^= 0xff;
    xor_ff = analyze_run_target(in_data, in_len, 0);

    in_data[i] ^= 0xfe;
    xor_01 = analyze_run_target(in_data, in_len, 0);

    in_data[i] = (in_data[i] ^ 0x01) - 0x10;
    sub_10 = analyze_run_target(in_data, in_len, 0);

    in_data[i] += 0x20;
    add_10 = analyze_run_target(in_data, in_len, 0);
    in_data[i] -= 0x10;

    /* Classify current behavior. */

    xff_orig = (xor_ff == orig_cksum);
    x01_orig = (xor_01 == orig_cksum);
    s10_orig = (sub_10 == orig_cksum);
    a10_orig = (add_10 == orig_cksum);

    if (xff_orig && x01_orig && s10_orig && a10_orig) {

      b_data[i] = RESP_NONE;
      boring_len++;

    } else if (xff_orig || x01_orig || s10_orig || a10_orig) {

      b_data[i] = RESP_MINOR;
      boring_len++;

    } else if (xor_ff == xor_01 && xor_ff == sub_10 && xor_ff == add_10) {

      b_data[i] = RESP_FIXED;

    } else {

      b_data[i] = RESP_VARIABLE;

    }

    /* When all checksums change, flip most significant bit of b_data. */

    if (prev_xff != xor_ff && prev_x01 != xor_01 && prev_s10 != sub_10 &&
        prev_a10 != add_10) {

      seq_byte ^= 0x80;

    }

    b_data[i] |= seq_byte;

    prev_xff = xor_ff;
    prev_x01 = xor_01;
    prev_s10 = sub_10;
    prev_a10 = add_10;

  }

  dump_hex(in_len, b_data);

  SAYF("\n");

  OKF("Analysis complete. Interesting bits: %0.02f%% of the input file.",
      100.0 - ((double)boring_len * 100) / in_len);

  if (exec_hangs) {

    WARNF(cLRD "Encountered %u timeouts - results may be skewed." cRST,
          exec_hangs);

  }

  ck_free(b_data);

}

/* Handle Ctrl-C and the like. */

static void handle_stop_sig(int sig) {

  (void)sig;
  stop_soon = 1;

  afl_fsrv_killall();

}

/* Do basic preparations - persistent fds, filenames, etc. */

static void set_up_environment(char **argv) {

  u8 *  x;
  char *afl_preload;
  char *frida_afl_preload = NULL;

  fsrv.dev_null_fd = open("/dev/null", O_RDWR);
  if (fsrv.dev_null_fd < 0) { PFATAL("Unable to open /dev/null"); }

  if (!fsrv.out_file) {

    u8 *use_dir = ".";

    if (access(use_dir, R_OK | W_OK | X_OK)) {

      use_dir = get_afl_env("TMPDIR");
      if (!use_dir) { use_dir = "/tmp"; }

    }

    fsrv.out_file =
        alloc_printf("%s/.afl-analyze-temp-%u", use_dir, (u32)getpid());

  }

  unlink(fsrv.out_file);
  fsrv.out_fd =
      open(fsrv.out_file, O_RDWR | O_CREAT | O_EXCL, DEFAULT_PERMISSION);

  if (fsrv.out_fd < 0) { PFATAL("Unable to create '%s'", fsrv.out_file); }

  /* Set sane defaults... */

  x = get_afl_env("ASAN_OPTIONS");

  if (x) {

    if (!strstr(x, "abort_on_error=1")) {

      FATAL("Custom ASAN_OPTIONS set without abort_on_error=1 - please fix!");

    }

#ifndef ASAN_BUILD
    if (!getenv("AFL_DEBUG") && !strstr(x, "symbolize=0")) {

      FATAL("Custom ASAN_OPTIONS set without symbolize=0 - please fix!");

    }

#endif

  }

  x = get_afl_env("MSAN_OPTIONS");

  if (x) {

    if (!strstr(x, "exit_code=" STRINGIFY(MSAN_ERROR))) {

      FATAL("Custom MSAN_OPTIONS set without exit_code=" STRINGIFY(
          MSAN_ERROR) " - please fix!");

    }

    if (!strstr(x, "symbolize=0")) {

      FATAL("Custom MSAN_OPTIONS set without symbolize=0 - please fix!");

    }

  }

  x = get_afl_env("LSAN_OPTIONS");

  if (x) {

    if (!strstr(x, "symbolize=0")) {

      FATAL("Custom LSAN_OPTIONS set without symbolize=0 - please fix!");

    }

  }

  setenv("ASAN_OPTIONS",
         "abort_on_error=1:"
         "detect_leaks=0:"
         "allocator_may_return_null=1:"
         "detect_odr_violation=0:"
         "symbolize=0:"
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

  setenv("LSAN_OPTIONS",
         "exitcode=" STRINGIFY(LSAN_ERROR) ":"
         "fast_unwind_on_malloc=0:"
         "symbolize=0:"
         "print_suppressions=0",
         0);

  if (get_afl_env("AFL_PRELOAD")) {

    if (qemu_mode) {

      /* afl-qemu-trace takes care of converting AFL_PRELOAD. */

    } else if (frida_mode) {

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

  } else if (frida_mode) {

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
  sa.sa_flags = SA_RESTART;
  sa.sa_sigaction = NULL;

  sigemptyset(&sa.sa_mask);

  /* Various ways of saying "stop". */

  sa.sa_handler = handle_stop_sig;
  sigaction(SIGHUP, &sa, NULL);
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);

}

/* Display usage hints. */

static void usage(u8 *argv0) {

  SAYF(
      "\n%s [ options ] -- /path/to/target_app [ ... ]\n\n"

      "Required parameters:\n"

      "  -i file       - input test case to be analyzed by the tool\n\n"

      "Execution control settings:\n"

      "  -f file       - input file read by the tested program (stdin)\n"
      "  -t msec       - timeout for each run (%u ms)\n"
      "  -m megs       - memory limit for child process (%u MB)\n"
#if defined(__linux__) && defined(__aarch64__)
      "  -A            - use binary-only instrumentation (ARM CoreSight mode)\n"
#endif
      "  -O            - use binary-only instrumentation (FRIDA mode)\n"
#if defined(__linux__)
      "  -Q            - use binary-only instrumentation (QEMU mode)\n"
      "  -U            - use unicorn-based instrumentation (Unicorn mode)\n"
      "  -W            - use qemu-based instrumentation with Wine (Wine "
      "mode)\n"
#endif
      "\n"

      "Analysis settings:\n"

      "  -e            - look for edge coverage only, ignore hit counts\n\n"

      "For additional tips, please consult %s/README.md.\n\n"

      "Environment variables used:\n"
      "TMPDIR: directory to use for temporary input files\n"
      "ASAN_OPTIONS: custom settings for ASAN\n"
      "              (must contain abort_on_error=1 and symbolize=0)\n"
      "MSAN_OPTIONS: custom settings for MSAN\n"
      "              (must contain exitcode="STRINGIFY(MSAN_ERROR)" and symbolize=0)\n"
      "AFL_ANALYZE_HEX: print file offsets in hexadecimal instead of decimal\n"
      "AFL_MAP_SIZE: the shared memory size for that target. must be >= the size\n"
      "              the target was compiled for\n"
      "AFL_PRELOAD: LD_PRELOAD / DYLD_INSERT_LIBRARIES settings for target\n"
      "AFL_SKIP_BIN_CHECK: skip checking the location of and the target\n"

      , argv0, EXEC_TIMEOUT, MEM_LIMIT, doc_path);

  exit(1);

}

/* Main entry point */

int main(int argc, char **argv_orig, char **envp) {

  s32    opt;
  u8     mem_limit_given = 0, timeout_given = 0, unicorn_mode = 0, use_wine = 0;
  char **use_argv;
  char **argv = argv_cpy_dup(argc, argv_orig);

  doc_path = access(DOC_PATH, F_OK) ? "docs" : DOC_PATH;

  SAYF(cCYA "afl-analyze" VERSION cRST " by Michal Zalewski\n");

  afl_fsrv_init(&fsrv);

  while ((opt = getopt(argc, argv, "+i:f:m:t:eAOQUWh")) > 0) {

    switch (opt) {

      case 'i':

        if (in_file) { FATAL("Multiple -i options not supported"); }
        in_file = optarg;
        break;

      case 'f':

        if (fsrv.out_file) { FATAL("Multiple -f options not supported"); }
        fsrv.use_stdin = 0;
        fsrv.out_file = ck_strdup(optarg);
        break;

      case 'e':

        if (edges_only) { FATAL("Multiple -e options not supported"); }
        edges_only = 1;
        break;

      case 'm': {

        u8 suffix = 'M';

        if (mem_limit_given) { FATAL("Multiple -m options not supported"); }
        mem_limit_given = 1;

        if (!optarg) { FATAL("Wrong usage of -m"); }

        if (!strcmp(optarg, "none")) {

          mem_limit = 0;
          fsrv.mem_limit = 0;
          break;

        }

        if (sscanf(optarg, "%llu%c", &mem_limit, &suffix) < 1 ||
            optarg[0] == '-') {

          FATAL("Bad syntax used for -m");

        }

        switch (suffix) {

          case 'T':
            mem_limit *= 1024 * 1024;
            break;
          case 'G':
            mem_limit *= 1024;
            break;
          case 'k':
            mem_limit /= 1024;
            break;
          case 'M':
            break;

          default:
            FATAL("Unsupported suffix or bad syntax for -m");

        }

        if (mem_limit < 5) { FATAL("Dangerously low value of -m"); }

        if (sizeof(rlim_t) == 4 && mem_limit > 2000) {

          FATAL("Value of -m out of range on 32-bit systems");

        }

        fsrv.mem_limit = mem_limit;

      }

      break;

      case 't':

        if (timeout_given) { FATAL("Multiple -t options not supported"); }
        timeout_given = 1;

        if (!optarg) { FATAL("Wrong usage of -t"); }

        exec_tmout = atoi(optarg);

        if (exec_tmout < 10 || optarg[0] == '-') {

          FATAL("Dangerously low value of -t");

        }

        fsrv.exec_tmout = exec_tmout;

        break;

      case 'A':                                           /* CoreSight mode */

#if !defined(__aarch64__) || !defined(__linux__)
        FATAL("-A option is not supported on this platform");
#endif

        if (cs_mode) { FATAL("Multiple -A options not supported"); }

        cs_mode = 1;
        fsrv.cs_mode = cs_mode;
        break;

      case 'O':                                               /* FRIDA mode */

        if (frida_mode) { FATAL("Multiple -O options not supported"); }

        frida_mode = 1;
        fsrv.frida_mode = frida_mode;
        setenv("AFL_FRIDA_INST_SEED", "1", 1);

        break;

      case 'Q':

        if (qemu_mode) { FATAL("Multiple -Q options not supported"); }
        if (!mem_limit_given) { mem_limit = MEM_LIMIT_QEMU; }

        qemu_mode = 1;
        fsrv.mem_limit = mem_limit;
        fsrv.qemu_mode = qemu_mode;
        break;

      case 'U':

        if (unicorn_mode) { FATAL("Multiple -U options not supported"); }
        if (!mem_limit_given) { mem_limit = MEM_LIMIT_UNICORN; }

        unicorn_mode = 1;
        fsrv.mem_limit = mem_limit;
        break;

      case 'W':                                           /* Wine+QEMU mode */

        if (use_wine) { FATAL("Multiple -W options not supported"); }
        qemu_mode = 1;
        use_wine = 1;

        if (!mem_limit_given) { mem_limit = 0; }
        fsrv.qemu_mode = qemu_mode;
        fsrv.mem_limit = mem_limit;

        break;

      case 'h':
        usage(argv[0]);
        return -1;
        break;

      default:
        usage(argv[0]);

    }

  }

  if (optind == argc || !in_file) { usage(argv[0]); }

  map_size = get_map_size();
  fsrv.map_size = map_size;

  use_hex_offsets = !!get_afl_env("AFL_ANALYZE_HEX");

  check_environment_vars(envp);

  sharedmem_t shm = {0};

  /* initialize cmplog_mode */
  shm.cmplog_mode = 0;

  atexit(at_exit_handler);
  setup_signal_handlers();

  set_up_environment(argv);

  fsrv.target_path = find_binary(argv[optind]);
  fsrv.trace_bits = afl_shm_init(&shm, map_size, 0);
  detect_file_args(argv + optind, fsrv.out_file, &use_stdin);
  signal(SIGALRM, kill_child);

  if (qemu_mode) {

    if (use_wine) {

      use_argv =
          get_wine_argv(argv[0], &target_path, argc - optind, argv + optind);

    } else {

      use_argv =
          get_qemu_argv(argv[0], &target_path, argc - optind, argv + optind);

    }

  } else if (cs_mode) {

    use_argv = get_cs_argv(argv[0], &target_path, argc - optind, argv + optind);

  } else {

    use_argv = argv + optind;

  }

  SAYF("\n");

  if (getenv("AFL_FORKSRV_INIT_TMOUT")) {

    s32 forksrv_init_tmout = atoi(getenv("AFL_FORKSRV_INIT_TMOUT"));
    if (forksrv_init_tmout < 1) {

      FATAL("Bad value specified for AFL_FORKSRV_INIT_TMOUT");

    }

    fsrv.init_tmout = (u32)forksrv_init_tmout;

  }

  fsrv.kill_signal =
      parse_afl_kill_signal_env(getenv("AFL_KILL_SIGNAL"), SIGKILL);

  read_initial_file();
  (void)check_binary_signatures(fsrv.target_path);

  ACTF("Performing dry run (mem limit = %llu MB, timeout = %u ms%s)...",
       mem_limit, exec_tmout, edges_only ? ", edges only" : "");

  afl_fsrv_start(&fsrv, use_argv, &stop_soon, false);
  analyze_run_target(in_data, in_len, 1);

  if (fsrv.last_run_timed_out) {

    FATAL("Target binary times out (adjusting -t may help).");

  }

  if (get_afl_env("AFL_SKIP_BIN_CHECK") == NULL && !anything_set()) {

    FATAL("No instrumentation detected.");

  }

  analyze();

  OKF("We're done here. Have a nice day!\n");

  afl_shm_deinit(&shm);
  afl_fsrv_deinit(&fsrv);
  if (fsrv.target_path) { ck_free(fsrv.target_path); }
  if (in_data) { ck_free(in_data); }

  exit(0);

}

