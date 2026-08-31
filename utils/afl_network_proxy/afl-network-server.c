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
   Copyright 2019-2026 AFLplusplus Project. All rights reserved.

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
#include "afl-network-proxy.h"

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
static u8                      *in_comp;
static u8                      *out_comp;
static size_t                   out_comp_len;
#endif

static u8 *out_file;                   /* File to fuzz, if any              */
static u8  out_file_allocated;         /* Did we allocate out_file?         */

static u8 *in_data;                    /* Test case received from the client*/
static u8 *send_buf;                   /* status + coverage answer buffer   */

static u32 map_size = MAP_SIZE;
static u32 max_testcase_len = AFL_NETWORK_MAX_TESTCASE;
static u32 net_flags;                  /* negotiated protocol flags         */

static volatile u8 stop_soon;          /* Ctrl-C pressed?                   */

static void at_exit_handler(void) {

  afl_fsrv_killall();

}

/* Execute target application. */

static fsrv_run_result_t run_target(afl_forkserver_t *fsrv, u8 *mem, u32 len) {

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

  (void)sig;
  stop_soon = 1;
  afl_fsrv_killall();

}

/* Do basic preparations - persistent fds, filenames, etc. */

static void set_up_environment(afl_forkserver_t *fsrv, char *argv0) {

  fsrv->dev_null_fd = open("/dev/null", O_RDWR);
  if (fsrv->dev_null_fd < 0) { PFATAL("Unable to open /dev/null"); }

  if (!out_file) {

    u8 *use_dir = ".";

    if (access(use_dir, R_OK | W_OK | X_OK)) {

      use_dir = get_afl_env("TMPDIR");
      if (!use_dir) { use_dir = "/tmp"; }

    }

    out_file = alloc_printf("%s/.afl-input-temp-%u", use_dir, getpid());
    out_file_allocated = 1;

  }

  fsrv->out_file = out_file;

  unlink(out_file);

  fsrv->out_fd = open(out_file, O_RDWR | O_CREAT | O_EXCL, fsrv->perm);

  if (fsrv->out_fd < 0) { PFATAL("Unable to create '%s'", out_file); }

  if (fsrv->chown_needed) {

    if (fchown(fsrv->out_fd, -1, fsrv->gid) == -1) {

      PFATAL("fchown() failed");

    }

  }

  set_sanitizer_defaults();
  afl_fsrv_setup_preload(fsrv, argv0);

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
      "              the target was compiled for. It is transmitted to the\n"
      "              afl-network-client, so it does not have to be set there.\n"
      "AFL_PRELOAD:  LD_PRELOAD / DYLD_INSERT_LIBRARIES settings for target\n"
      "AFL_KILL_SIGNAL: signal to kill the target with (default: SIGKILL)\n"
      "AFL_FORK_SERVER_KILL_SIGNAL: signal to kill the forkserver with\n"

      , argv0, EXEC_TIMEOUT, MEM_LIMIT);

  exit(1);

}

/* Receive a test case. Returns its length, or 0 if the client is gone. */

static u32 recv_testcase(int s, void **buf) {

  u32 size;

  if (!afl_network_recv(s, &size, 4)) { return 0; }

  if ((size & AFL_NETWORK_COMPRESSED) != AFL_NETWORK_COMPRESSED) {

    if (!size || size > max_testcase_len) {

      FATAL("received an illegal test case size of %u", size);

    }

    *buf = afl_realloc(buf, size);
    if (unlikely(!*buf)) { PFATAL("Alloc"); }

    if (!afl_network_recv(s, *buf, size)) {

      FATAL("did not receive the test case data");

    }

  } else {

#ifdef USE_DEFLATE
    u32    clen;
    size_t received;

    size -= AFL_NETWORK_COMPRESSED;

    if (!size || size > max_testcase_len) {

      FATAL("received an illegal test case size of %u", size);

    }

    *buf = afl_realloc(buf, size);
    if (unlikely(!*buf)) { PFATAL("Alloc"); }

    if (!afl_network_recv(s, &clen, 4)) {

      FATAL("did not receive the compressed test case length");

    }

    if (!clen || clen > AFL_NETWORK_MAX_TESTCASE) {

      FATAL("received an illegal compressed test case length of %u", clen);

    }

    in_comp = afl_realloc((void **)&in_comp, clen);
    if (unlikely(!in_comp)) { PFATAL("Alloc"); }

    if (!afl_network_recv(s, in_comp, clen)) {

      FATAL("did not receive the compressed test case data");

    }

    if (libdeflate_deflate_decompress(decompressor, in_comp, clen, *buf, size,
                                      &received) != LIBDEFLATE_SUCCESS ||
        received != size) {

      FATAL("decompression of the test case failed");

    }

#else
    FATAL("Received compressed data but not compiled with compression support");
#endif

  }

  return size;

}

/* Exchange the protocol header with the client. */

static void handshake(int s) {

  u32 header[3];

  if (!afl_network_recv(s, header, sizeof(header))) {

    FATAL("did not receive the client hello");

  }

  if (header[0] != AFL_NETWORK_HELLO) {

    FATAL(
        "incompatible afl-network-client (protocol 0x%08x, expected 0x%08x), "
        "update both sides to the same AFL++ version",
        header[0], AFL_NETWORK_HELLO);

  }

  max_testcase_len = header[2];

  if (!max_testcase_len || max_testcase_len > AFL_NETWORK_MAX_TESTCASE) {

    FATAL("client announced an illegal maximum test case size of %u",
          max_testcase_len);

  }

  net_flags &= header[1];

  header[0] = AFL_NETWORK_HELLO;
  header[1] = net_flags;
  header[2] = map_size;

  if (!afl_network_send(s, header, sizeof(header))) {

    FATAL("could not send the server hello");

  }

}

/* Main entry point */

int main(int argc, char **argv_orig, char **envp) {

  s32    opt, s, sock, on = 1, port = -1, in_len;
  u8     mem_limit_given = 0, timeout_given = 0, unicorn_mode = 0, use_wine = 0;
  char **use_argv;
  struct sockaddr_in6 serveraddr;
  char              **argv = argv_cpy_dup(argc, argv_orig);

  afl_forkserver_t  fsrv_var = {0};
  afl_forkserver_t *fsrv = &fsrv_var;
  afl_fsrv_init(fsrv);
  map_size = get_map_size();
  fsrv->map_size = map_size;

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

        if (unicorn_mode) { FATAL("Multiple -U options not supported"); }
        if (!mem_limit_given) { fsrv->mem_limit = MEM_LIMIT_UNICORN; }

        unicorn_mode = 1;
        fsrv->unicorn_mode = 1;
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
  fsrv->trace_bits = afl_shm_init(&shm, map_size, 0, fsrv->perm,
                                  fsrv->chown_needed ? fsrv->gid : -1);
  fsrv->child_sync_offset = shm.child_sync_offset;

  in_data = afl_realloc((void **)&in_data, 65536);
  if (unlikely(!in_data)) { PFATAL("Alloc"); }

  atexit(at_exit_handler);
  setup_signal_handlers();

  set_up_environment(fsrv, argv[0]);

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

    if (check_binary_signatures(fsrv->target_path) & 1) {

      fsrv->persistent_mode = 1;

    }

  }

  /* Targets that use __AFL_FUZZ_TESTCASE_BUF require the test case in shared
     memory, so offer it - the forkserver falls back to the file/stdin path
     if the target does not request it. */

  sharedmem_t shm_fuzz = {0};
  shm_fuzz.shmemfuzz_mode = true;
  u8 *fuzz_map =
      afl_shm_init(&shm_fuzz, SHM_FUZZ_MAP_SIZE_DEFAULT, 1, fsrv->perm, -1);
  if (!fuzz_map) { FATAL("BUG: Zero return from afl_shm_init."); }

  size_t shm_fuzz_map_size = SHM_FUZZ_MAP_SIZE_DEFAULT;
  u8    *shm_fuzz_map_size_str = alloc_printf("%zu", shm_fuzz_map_size);
  setenv(SHM_FUZZ_MAP_SIZE_ENV_VAR, shm_fuzz_map_size_str, 1);
  ck_free(shm_fuzz_map_size_str);

  afl_shm_fuzz_env_set(&shm_fuzz);

  fsrv->support_shmem_fuzz = true;
  fsrv->shmem_fuzz_len = (u32 *)fuzz_map;
  fsrv->shmem_fuzz = fuzz_map + sizeof(u32);

  configure_afl_kill_signals(
      fsrv, NULL, NULL, (fsrv->qemu_mode || unicorn_mode) ? SIGKILL : SIGTERM);

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

  afl_fsrv_resize_mapsize(fsrv, &shm, use_argv, map_size, &stop_soon,
                          unicorn_mode);

  map_size = fsrv->map_size;

  if ((send_buf = malloc(map_size + 4)) == NULL) { PFATAL("malloc"); }

#ifdef USE_DEFLATE
  compressor = libdeflate_alloc_compressor(1);
  decompressor = libdeflate_alloc_decompressor();
  if (!compressor || !decompressor) { FATAL("libdeflate allocation failed"); }
  out_comp_len = libdeflate_deflate_compress_bound(compressor, map_size) + 8;
  if ((out_comp = malloc(out_comp_len)) == NULL) { PFATAL("malloc"); }
  net_flags |= AFL_NETWORK_FLAG_DEFLATE;
  fprintf(stderr, "Compiled with compression support\n");
#endif

  fprintf(stderr, "Coverage map size of the target is %u bytes\n", map_size);

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

  handshake(s);

  while ((in_len = recv_testcase(s, (void **)&in_data)) > 0) {

    /* On the persistent mode fast path the forkserver does not update
       child_status, so only forward it for runs that were not classified
       as a success. */

    u32 status = run_target(fsrv, in_data, in_len) == FSRV_RUN_OK
                     ? 0
                     : (u32)fsrv->child_status;

    memcpy(send_buf, &status, 4);
    memcpy(send_buf + 4, fsrv->trace_bits, map_size);

#ifdef USE_DEFLATE
    if (net_flags & AFL_NETWORK_FLAG_DEFLATE) {

      u32 clen = (u32)libdeflate_deflate_compress(
          compressor, send_buf + 4, map_size, out_comp + 8, out_comp_len - 8);

      if (!clen) { FATAL("compression of the coverage map failed"); }

      memcpy(out_comp, send_buf, 4);
      memcpy(out_comp + 4, &clen, 4);

      if (!afl_network_send(s, out_comp, clen + 8)) {

        FATAL("could not send data");

      }

    } else

#endif
    {

      if (!afl_network_send(s, send_buf, map_size + 4)) {

        FATAL("could not send data");

      }

    }

  }

  fprintf(stderr, "Client disconnected, exiting.\n");

  close(s);
  close(sock);

  unlink(out_file);
  if (out_file_allocated) { ck_free(out_file); }
  out_file = NULL;

  afl_shm_deinit(&shm_fuzz);
  afl_shm_deinit(&shm);
  afl_fsrv_deinit(fsrv);
  if (fsrv->target_path) { ck_free(fsrv->target_path); }
  afl_free(in_data);
  free(send_buf);
#ifdef USE_DEFLATE
  afl_free(in_comp);
  free(out_comp);
  libdeflate_free_compressor(compressor);
  libdeflate_free_decompressor(decompressor);
#endif

  argv_cpy_free(argv);

  exit(0);

}

