/*
   american fuzzy lop++ - network proxy server
   -------------------------------------------

   Originally written by Michal Zalewski

   Forkserver design by Jann Horn <jannhorn@googlemail.com>

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eißfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com> and
                        Dominik Maier <mail@dmnk.co>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2024 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

 */

#define AFL_MAIN

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
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#ifndef USEMMAP
  #include <sys/shm.h>
#endif
#include <sys/socket.h>
#include <netdb.h>

#ifdef USE_DEFLATE
  #include <libdeflate.h>
struct libdeflate_compressor   *compressor;
struct libdeflate_decompressor *decompressor;
#endif

static u8 *in_file,                    /* Minimizer input test case         */
    *out_file;

static u8 *in_data;                    /* Input data for trimming           */
static u8 *buf2;

static s32 in_len;
static s32 buf2_len;
static u32 map_size = MAP_SIZE;

static volatile u8 stop_soon;          /* Ctrl-C pressed?                   */

/* See if any bytes are set in the bitmap. */

static inline u8 anything_set(afl_forkserver_t *fsrv) {

  u32 *ptr = (u32 *)fsrv->trace_bits;
  u32  i = (map_size >> 2);

  while (i--) {

    if (*(ptr++)) { return 1; }

  }

  return 0;

}

static void at_exit_handler(void) {

  afl_fsrv_killall();

}

/* Write output file. */

static s32 write_to_file(u8 *path, u8 *mem, u32 len) {

  s32 ret;

  unlink(path);                                            /* Ignore errors */

  ret = open(path, O_RDWR | O_CREAT | O_EXCL, 0600);

  if (ret < 0) { PFATAL("Unable to create '%s'", path); }

  ck_write(ret, mem, len, path);

  lseek(ret, 0, SEEK_SET);

  return ret;

}

/* Execute target application. Returns 0 if the changes are a dud, or
   1 if they should be kept. */

static u8 run_target(afl_forkserver_t *fsrv, char **argv, u8 *mem, u32 len,
                     u8 first_run) {

  afl_fsrv_write_to_testcase(fsrv, mem, len);

  fsrv_run_result_t ret =
      afl_fsrv_run_target(fsrv, fsrv->exec_tmout, &stop_soon);

  if (ret == FSRV_RUN_ERROR) { FATAL("Couldn't run child"); }

  if (stop_soon) {

    SAYF(cRST cLRD "\n+++ aborted by user +++\n" cRST);
    exit(1);

  }

  return ret;

}

/* Handle Ctrl-C and the like. */

static void handle_stop_sig(int sig) {

  stop_soon = 1;
  afl_fsrv_killall();

}

/* Do basic preparations - persistent fds, filenames, etc. */

static void set_up_environment(afl_forkserver_t *fsrv) {

  u8 *x;

  fsrv->dev_null_fd = open("/dev/null", O_RDWR);
  if (fsrv->dev_null_fd < 0) { PFATAL("Unable to open /dev/null"); }

  if (!out_file) {

    u8 *use_dir = ".";

    if (access(use_dir, R_OK | W_OK | X_OK)) {

      use_dir = get_afl_env("TMPDIR");
      if (!use_dir) { use_dir = "/tmp"; }

    }

    out_file = alloc_printf("%s/.afl-input-temp-%u", use_dir, getpid());
    fsrv->out_file = out_file;

  }

  unlink(out_file);

  fsrv->out_fd = open(out_file, O_RDWR | O_CREAT | O_EXCL, 0600);

  if (fsrv->out_fd < 0) { PFATAL("Unable to create '%s'", out_file); }

  /* Set sane defaults... */

  x = get_afl_env("ASAN_OPTIONS");

  if (x) {

    if (!strstr(x, "abort_on_error=1")) {

      FATAL("Custom ASAN_OPTIONS set without abort_on_error=1 - please fix!");

    }

    if (!getenv("AFL_DEBUG") && !strstr(x, "symbolize=0")) {

      FATAL("Custom ASAN_OPTIONS set without symbolize=0 - please fix!");

    }

  }

  x = get_afl_env("MSAN_OPTIONS");

  if (x) {

    if (!strstr(x, "exit_code=" STRINGIFY(MSAN_ERROR))) {

      FATAL("Custom MSAN_OPTIONS set without exit_code=" STRINGIFY(
          MSAN_ERROR) " - please fix!");

    }

    if (!getenv("AFL_DEBUG") && !strstr(x, "symbolize=0")) {

      FATAL("Custom MSAN_OPTIONS set without symbolize=0 - please fix!");

    }

  }

  set_sanitizer_defaults();

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

/* Display usage hints. */

static void usage(u8 *argv0) {

  SAYF(
      "\n%s [ options ] -- /path/to/target_app [ ... ]\n\n"

      "Required parameters:\n"

      "  -i port       - the port to listen for the client to connect to\n\n"

      "Execution control settings:\n"

      "  -f file       - input file read by the tested program (stdin)\n"
      "  -t msec       - timeout for each run (%d ms)\n"
      "  -m megs       - memory limit for child process (%d MB)\n"
      "  -Q            - use binary-only instrumentation (QEMU mode)\n"
      "  -U            - use unicorn-based instrumentation (Unicorn mode)\n"
      "  -W            - use qemu-based instrumentation with Wine (Wine "
      "mode)\n\n"

      "Environment variables used:\n"
      "TMPDIR: directory to use for temporary input files\n"
      "ASAN_OPTIONS: custom settings for ASAN\n"
      "              (must contain abort_on_error=1 and symbolize=0)\n"
      "MSAN_OPTIONS: custom settings for MSAN\n"
      "              (must contain exitcode="STRINGIFY(MSAN_ERROR)" and symbolize=0)\n"
      "AFL_MAP_SIZE: the shared memory size for that target. must be >= the size\n"
      "              the target was compiled for\n"
      "AFL_PRELOAD:  LD_PRELOAD / DYLD_INSERT_LIBRARIES settings for target\n"

      , argv0, EXEC_TIMEOUT, MEM_LIMIT);

  exit(1);

}

int recv_testcase(int s, void **buf) {

  u32    size;
  s32    ret;
  size_t received;

  received = 0;
  while (received < 4 && (ret = recv(s, &size + received, 4 - received, 0)) > 0)
    received += ret;
  if (received != 4) FATAL("did not receive size information");
  if (size == 0) FATAL("did not receive valid size information");
  // fprintf(stderr, "received size information of %d\n", size);

  if ((size & 0xff000000) != 0xff000000) {

    *buf = afl_realloc(buf, size);
    if (unlikely(!*buf)) { PFATAL("Alloc"); }
    received = 0;
    // fprintf(stderr, "unCOMPRESS (%u)\n", size);
    while (received < size &&
           (ret = recv(s, ((char *)*buf) + received, size - received, 0)) > 0)
      received += ret;

  } else {

#ifdef USE_DEFLATE
    u32 clen;
    size -= 0xff000000;
    *buf = afl_realloc(buf, size);
    if (unlikely(!*buf)) { PFATAL("Alloc"); }
    received = 0;
    while (received < 4 &&
           (ret = recv(s, &clen + received, 4 - received, 0)) > 0)
      received += ret;
    if (received != 4) FATAL("did not receive clen1 information");
    // fprintf(stderr, "received clen information of %d\n", clen);
    if (clen < 1)
      FATAL("did not receive valid compressed len information: %u", clen);
    buf2 = afl_realloc((void **)&buf2, clen);
    buf2_len = clen;
    if (unlikely(!buf2)) { PFATAL("Alloc"); }
    received = 0;
    while (received < clen &&
           (ret = recv(s, buf2 + received, clen - received, 0)) > 0)
      received += ret;
    if (received != clen) FATAL("did not receive compressed information");
    if (libdeflate_deflate_decompress(decompressor, buf2, clen, (char *)*buf,
                                      size, &received) != LIBDEFLATE_SUCCESS)
      FATAL("decompression failed");
      // fprintf(stderr, "DECOMPRESS (%u->%u):\n", clen, received);
      // for (u32 i = 0; i < clen; i++) fprintf(stderr, "%02x", buf2[i]);
      // fprintf(stderr, "\n");
      // for (u32 i = 0; i < received; i++) fprintf(stderr, "%02x",
      // ((u8*)(*buf))[i]); fprintf(stderr, "\n");
#else
    FATAL("Received compressed data but not compiled with compression support");
#endif

  }

  // fprintf(stderr, "receiving testcase %p %p max %u\n", buf, *buf, *max_len);
  if (received != size)
    FATAL("did not receive testcase data %lu != %u, %d", received, size, ret);
  // fprintf(stderr, "received testcase\n");
  return size;

}

/* Main entry point */

int main(int argc, char **argv_orig, char **envp) {

  s32    opt, s, sock, on = 1, port = -1;
  u8     mem_limit_given = 0, timeout_given = 0, unicorn_mode = 0, use_wine = 0;
  char **use_argv;
  struct sockaddr_in6 serveraddr, clientaddr;
  int                 addrlen = sizeof(clientaddr);
  char                str[INET6_ADDRSTRLEN];
  char              **argv = argv_cpy_dup(argc, argv_orig);
  u8                 *send_buf;
#ifdef USE_DEFLATE
  u32 *lenptr;
#endif

  afl_forkserver_t  fsrv_var = {0};
  afl_forkserver_t *fsrv = &fsrv_var;
  afl_fsrv_init(fsrv);
  map_size = get_map_size();
  fsrv->map_size = map_size;

  if ((send_buf = malloc(map_size + 4)) == NULL) PFATAL("malloc");

  while ((opt = getopt(argc, argv, "+i:f:m:t:QUWh")) > 0) {

    switch (opt) {

      case 'i':

        if (port > 0) { FATAL("Multiple -i options not supported"); }
        port = atoi(optarg);
        if (port < 1 || port > 65535)
          FATAL("invalid port definition, must be between 1-65535: %s", optarg);
        break;

      case 'f':

        if (out_file) { FATAL("Multiple -f options not supported"); }
        fsrv->use_stdin = 0;
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

      case 't':

        if (timeout_given) { FATAL("Multiple -t options not supported"); }
        timeout_given = 1;

        if (!optarg) { FATAL("Wrong usage of -t"); }

        fsrv->exec_tmout = atoi(optarg);

        if (fsrv->exec_tmout < 10 || optarg[0] == '-') {

          FATAL("Dangerously low value of -t");

        }

        break;

      case 'Q':

        if (fsrv->qemu_mode) { FATAL("Multiple -Q options not supported"); }
        if (!mem_limit_given) { fsrv->mem_limit = MEM_LIMIT_QEMU; }

        fsrv->qemu_mode = 1;
        break;

      case 'U':

        if (unicorn_mode) { FATAL("Multiple -Q options not supported"); }
        if (!mem_limit_given) { fsrv->mem_limit = MEM_LIMIT_UNICORN; }

        unicorn_mode = 1;
        break;

      case 'W':                                           /* Wine+QEMU mode */

        if (use_wine) { FATAL("Multiple -W options not supported"); }
        fsrv->qemu_mode = 1;
        use_wine = 1;

        if (!mem_limit_given) { fsrv->mem_limit = 0; }

        break;

      case 'h':
        usage(argv[0]);
        return -1;
        break;

      default:
        usage(argv[0]);

    }

  }

  if (optind == argc || port < 1) { usage(argv[0]); }

  check_environment_vars(envp);

  sharedmem_t shm = {0};
  fsrv->trace_bits = afl_shm_init(&shm, map_size, 0);

  in_data = afl_realloc((void **)&in_data, 65536);
  if (unlikely(!in_data)) { PFATAL("Alloc"); }

  atexit(at_exit_handler);
  setup_signal_handlers();

  set_up_environment(fsrv);

  fsrv->target_path = find_binary(argv[optind]);
  detect_file_args(argv + optind, out_file, &fsrv->use_stdin);

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

  if ((sock = socket(AF_INET6, SOCK_STREAM, 0)) < 0) PFATAL("socket() failed");

#ifdef SO_REUSEADDR
  if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on)) < 0) {

    WARNF("setsockopt(SO_REUSEADDR) failed");

  }

#endif

#ifdef SO_PRIORITY
  int priority = 7;
  if (setsockopt(sock, SOL_SOCKET, SO_PRIORITY, &priority, sizeof(priority)) <
      0) {

    priority = 6;
    if (setsockopt(sock, SOL_SOCKET, SO_PRIORITY, &priority, sizeof(priority)) <
        0)
      WARNF("could not set priority on socket");

  }

#endif

  memset(&serveraddr, 0, sizeof(serveraddr));
  serveraddr.sin6_family = AF_INET6;
  serveraddr.sin6_port = htons(port);
  serveraddr.sin6_addr = in6addr_any;

  if (bind(sock, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0)
    PFATAL("bind() failed");

  if (listen(sock, 1) < 0) { PFATAL("listen() failed"); }

  afl_fsrv_start(
      fsrv, use_argv, &stop_soon,
      (get_afl_env("AFL_DEBUG_CHILD") || get_afl_env("AFL_DEBUG_CHILD_OUTPUT"))
          ? 1
          : 0);

#ifdef USE_DEFLATE
  compressor = libdeflate_alloc_compressor(1);
  decompressor = libdeflate_alloc_decompressor();
  buf2 = afl_realloc((void **)&buf2, map_size + 16);
  buf2_len = map_size + 16;
  if (unlikely(!buf2)) { PFATAL("alloc"); }
  lenptr = (u32 *)(buf2 + 4);
  fprintf(stderr, "Compiled with compression support\n");
#endif

  fprintf(stderr,
          "Waiting for incoming connection from afl-network-client on port %d "
          "...\n",
          port);

  if ((s = accept(sock, NULL, NULL)) < 0) { PFATAL("accept() failed"); }
  fprintf(stderr, "Received connection, starting ...\n");

#ifdef SO_PRIORITY
  priority = 7;
  if (setsockopt(s, SOL_SOCKET, SO_PRIORITY, &priority, sizeof(priority)) < 0) {

    priority = 6;
    if (setsockopt(s, SOL_SOCKET, SO_PRIORITY, &priority, sizeof(priority)) < 0)
      WARNF("could not set priority on socket");

  }

#endif

  while ((in_len = recv_testcase(s, (void **)&in_data)) > 0) {

    // fprintf(stderr, "received %u\n", in_len);
    (void)run_target(fsrv, use_argv, in_data, in_len, 1);

    memcpy(send_buf + 4, fsrv->trace_bits, fsrv->map_size);

#ifdef USE_DEFLATE
    memcpy(buf2, &fsrv->child_status, 4);
    *lenptr = (u32)libdeflate_deflate_compress(
        compressor, send_buf + 4, fsrv->map_size, buf2 + 8, buf2_len - 8);
    // fprintf(stderr, "COMPRESS (%u->%u): ", fsrv->map_size, *lenptr);
    // for (u32 i = 0; i < fsrv->map_size; i++) fprintf(stderr, "%02x",
    // fsrv->trace_bits[i]); fprintf(stderr, "\n");
    if (send(s, buf2, *lenptr + 8, 0) != 8 + *lenptr)
      FATAL("could not send data");
#else
    memcpy(send_buf, &fsrv->child_status, 4);
    if (send(s, send_buf, fsrv->map_size + 4, 0) != 4 + fsrv->map_size)
      FATAL("could not send data");
#endif

    // fprintf(stderr, "sent result\n");

  }

  unlink(out_file);
  if (out_file) { ck_free(out_file); }
  out_file = NULL;

  afl_shm_deinit(&shm);
  afl_fsrv_deinit(fsrv);
  if (fsrv->target_path) { ck_free(fsrv->target_path); }
  afl_free(in_data);
#if USE_DEFLATE
  afl_free(buf2);
  libdeflate_free_compressor(compressor);
  libdeflate_free_decompressor(decompressor);
#endif

  argv_cpy_free(argv);

  exit(0);

}

