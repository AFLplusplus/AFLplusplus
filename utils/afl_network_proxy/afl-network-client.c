/*
   american fuzzy lop++ - afl-network-client
   ---------------------------------------

   Written by Marc Heuse <mh@mh-sec.de>

   Copyright 2019-2026 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

   http://www.apache.org/licenses/LICENSE-2.0

*/

#ifdef __ANDROID__
  #include "android-ashmem.h"
#endif
#include "config.h"
#include "types.h"
#include "debug.h"
#include "afl-network-proxy.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <errno.h>

#include <netinet/in.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#ifndef USEMMAP
  #include <sys/shm.h>
#endif
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>

#ifdef USE_DEFLATE
  #include <libdeflate.h>
#endif

u8 *__afl_area_ptr;

#ifdef __ANDROID__
u32 __afl_map_size = MAP_SIZE;
#else
__thread u32 __afl_map_size = MAP_SIZE;
#endif

/* Error reporting to forkserver controller */

void send_forkserver_error(int error) {

  u32 status;
  if (!error || error > 0xffff) return;
  status = (FS_OPT_ERROR | FS_OPT_SET_ERROR(error));
  if (write(FORKSRV_FD + 1, (char *)&status, 4) != 4) return;

}

/* Map a shared region the AFL++ tool handed over as an inherited descriptor.
   Recent tools shm_unlink() their shared maps right after creating them and
   only pass the still-open descriptor number, so nothing survives if the tool
   is SIGKILLed. Returns NULL when there is no usable descriptor, which puts
   the caller back on the shm_open(name) / shmat(id) path. */

static void *__afl_map_shm_fd(const char *env, size_t len) {

  const char *fd_str = getenv(env);
  struct stat st;
  void       *ret;
  int         fd;

  if (!fd_str || !*fd_str) { return NULL; }

  fd = atoi(fd_str);

  if (fd < 0 || fstat(fd, &st) != 0 || st.st_size <= 0) { return NULL; }

  ret = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

  if (ret == MAP_FAILED) {

    fprintf(stderr, "mmap() of %s failed\n", env);
    send_forkserver_error(FS_ERROR_MMAP);
    exit(2);

  }

  return ret;

}

/* SHM setup. */

static void __afl_map_shm(void) {

  char *id_str = getenv(SHM_ENV_VAR);

  if (id_str || getenv(SHM_FD_ENV_VAR)) {

    /* Preferred path: the map was handed to us as an inherited descriptor. */
    __afl_area_ptr = __afl_map_shm_fd(SHM_FD_ENV_VAR, __afl_map_size);

    if (!__afl_area_ptr && id_str) {

#ifdef USEMMAP
      const char    *shm_file_path = id_str;
      int            shm_fd = -1;
      unsigned char *shm_base = NULL;

      /* create the shared memory segment as if it was a file */
      shm_fd = shm_open(shm_file_path, O_RDWR, 0600);
      if (shm_fd == -1) {

        fprintf(stderr, "shm_open() failed\n");
        send_forkserver_error(FS_ERROR_SHM_OPEN);
        exit(1);

      }

      /* map the shared memory segment to the address space of the process */
      shm_base = mmap(0, __afl_map_size, PROT_READ | PROT_WRITE, MAP_SHARED,
                      shm_fd, 0);

      if (shm_base == MAP_FAILED) {

        close(shm_fd);
        shm_fd = -1;

        fprintf(stderr, "mmap() failed\n");
        send_forkserver_error(FS_ERROR_MMAP);
        exit(2);

      }

      __afl_area_ptr = shm_base;
#else
      u32 shm_id = atoi(id_str);

      __afl_area_ptr = shmat(shm_id, 0, 0);

#endif

    }

    if (!__afl_area_ptr || __afl_area_ptr == (void *)-1) {

      send_forkserver_error(FS_ERROR_SHMAT);
      exit(1);

    }

    /* Write something into the bitmap so that the parent doesn't give up */

    __afl_area_ptr[0] = 1;

  }

}

/* Fork server logic. Speaks the same protocol as afl-compiler-rt so that the
   remote target's map size is what afl-fuzz sees. */

static void __afl_start_forkserver(void) {

  u32 version = 0x41464c00 + FS_NEW_VERSION_MAX;
  u32 status = 0, reply = 0;

  if (getenv("AFL_OLD_FORKSERVER")) {

    if (__afl_map_size <= FS_OPT_MAX_MAPSIZE)
      status |= (FS_OPT_SET_MAPSIZE(__afl_map_size) | FS_OPT_MAPSIZE);
    if (status) status |= (FS_OPT_ENABLED);

    /* Phone home and tell the parent that we're OK. */

    if (write(FORKSRV_FD + 1, &status, 4) != 4) return;

    return;

  }

  if (write(FORKSRV_FD + 1, &version, 4) != 4) return;

  if (read(FORKSRV_FD, &reply, 4) != 4)
    FATAL("could not read the forkserver version reply");

  if (reply != (version ^ 0xffffffff))
    FATAL("wrong forkserver message from the AFL++ tool");

  status = FS_NEW_OPT_MAPSIZE;
  if (write(FORKSRV_FD + 1, &status, 4) != 4)
    FATAL("could not send the forkserver options");

  status = __afl_map_size;
  if (write(FORKSRV_FD + 1, &status, 4) != 4)
    FATAL("could not send the map size");

  if (write(FORKSRV_FD + 1, &version, 4) != 4)
    FATAL("could not send the forkserver welcome message");

}

static u32 __afl_next_testcase(u8 *buf, u32 max_len) {

  s32 status, res = 0x0fffffff;  // res is a dummy pid

  /* Wait for parent by reading from the pipe. Abort if read fails. */
  if (read(FORKSRV_FD, &status, 4) != 4) return 0;

  /* we have a testcase - read it */
  status = read(0, buf, max_len);

  /* report that we are starting the target */
  if (write(FORKSRV_FD + 1, &res, 4) != 4) return 0;

  if (status < 1)
    return 0;
  else
    return status;

}

static void __afl_end_testcase(int status) {

  if (write(FORKSRV_FD + 1, &status, 4) != 4) exit(1);

}

/* Exchange the protocol header with the server and learn the map size. */

static u32 handshake(int s, u32 max_len) {

  u32 header[3], flags = 0;

#ifdef USE_DEFLATE
  flags |= AFL_NETWORK_FLAG_DEFLATE;
#endif

  header[0] = AFL_NETWORK_HELLO;
  header[1] = flags;
  header[2] = max_len;

  if (!afl_network_send(s, header, sizeof(header)))
    FATAL("could not send the client hello");

  if (!afl_network_recv(s, header, sizeof(header)))
    FATAL("did not receive the server hello");

  if (header[0] != AFL_NETWORK_HELLO)
    FATAL(
        "incompatible afl-network-server (protocol 0x%08x, expected 0x%08x), "
        "update both sides to the same AFL++ version",
        header[0], AFL_NETWORK_HELLO);

  if (!header[2] || header[2] > FS_OPT_MAX_MAPSIZE)
    FATAL("server announced an illegal map size of %u", header[2]);

  __afl_map_size = header[2];

  return header[1];

}

/* you just need to modify the while() loop in this main() */

int main(int argc, char *argv[]) {

  u8             *interface, *buf;
  s32             s = -1;
  struct addrinfo hints, *hres, *aip;
  u32            *lenptr, max_len = 65536, flags;
#ifdef USE_DEFLATE
  u8    *buf2 = NULL;
  size_t buf2_len, decompress_len;
  u32    compress_len;
#endif

  if (argc < 3 || argc > 4) {

    printf("Syntax: %s host port [max-input-size]\n\n", argv[0]);
    printf("Requires host and port of the remote afl-proxy-server instance.\n");
    printf(
        "IPv4 and IPv6 are supported, also binding to an interface with "
        "\"%%\"\n");
    printf("The max-input-size default is %u, the maximum is %u.\n", max_len,
           AFL_NETWORK_MAX_TESTCASE);
    printf(
        "The map size is transmitted by afl-network-server, so AFL_MAP_SIZE "
        "only\nhas to be set there.\n");
    exit(-1);

  }

  if ((interface = strchr(argv[1], '%')) != NULL) *interface++ = 0;

  if (argc > 3) {

    max_len = strtoul(argv[3], NULL, 10);
    if (max_len < 1 || max_len > AFL_NETWORK_MAX_TESTCASE)
      FATAL("max-input-size must be between 1 and %u: %s",
            AFL_NETWORK_MAX_TESTCASE, argv[3]);

  }

  if ((buf = malloc(max_len + 4)) == NULL)
    PFATAL("can not allocate %u memory", max_len + 4);
  lenptr = (u32 *)buf;

  memset(&hints, 0, sizeof(hints));
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_family = PF_UNSPEC;

  if (getaddrinfo(argv[1], argv[2], &hints, &hres) != 0)
    PFATAL("could not resolve target %s", argv[1]);

  for (aip = hres; aip != NULL && s == -1; aip = aip->ai_next) {

    if ((s = socket(aip->ai_family, aip->ai_socktype, aip->ai_protocol)) >= 0) {

#ifdef SO_BINDTODEVICE
      if (interface != NULL)
        if (setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, interface,
                       strlen(interface) + 1) < 0)
          fprintf(stderr, "Warning: could not bind to device %s\n", interface);
#else
      fprintf(stderr,
              "Warning: binding to interface is not supported for your OS\n");
#endif

#ifdef SO_PRIORITY
      int priority = 7;
      if (setsockopt(s, SOL_SOCKET, SO_PRIORITY, &priority, sizeof(priority)) <
          0) {

        priority = 6;
        if (setsockopt(s, SOL_SOCKET, SO_PRIORITY, &priority,
                       sizeof(priority)) < 0)
          WARNF("could not set priority on socket");

      }

#endif

      if (connect(s, aip->ai_addr, aip->ai_addrlen) == -1) s = -1;

    }

  }

  if (s == -1)
    FATAL("could not connect to target tcp://%s:%s", argv[1], argv[2]);
  else
    fprintf(stderr, "Connected to target tcp://%s:%s\n", argv[1], argv[2]);

  flags = handshake(s, max_len);

  fprintf(stderr, "Coverage map size of the remote target is %u bytes\n",
          __afl_map_size);

#ifdef USE_DEFLATE
  struct libdeflate_compressor   *compressor = NULL;
  struct libdeflate_decompressor *decompressor = NULL;

  if (flags & AFL_NETWORK_FLAG_DEFLATE) {

    size_t bound;

    compressor = libdeflate_alloc_compressor(1);
    decompressor = libdeflate_alloc_decompressor();
    if (!compressor || !decompressor) FATAL("libdeflate allocation failed");

    buf2_len = libdeflate_deflate_compress_bound(compressor, max_len);
    bound = libdeflate_deflate_compress_bound(compressor, __afl_map_size);
    if (bound > buf2_len) buf2_len = bound;

    if ((buf2 = malloc(buf2_len + 8)) == NULL)
      PFATAL("can not allocate %zu memory", buf2_len + 8);

    fprintf(stderr, "Using compression\n");

  }

#else
  if (flags & AFL_NETWORK_FLAG_DEFLATE) FATAL("compression is not compiled in");
#endif

  /* we initialize the shared memory map and start the forkserver */
  __afl_map_shm();
  __afl_start_forkserver();

  int status;

  while ((*lenptr = __afl_next_testcase(buf + 4, max_len)) > 0) {

#if defined(USE_DEFLATE) && defined(COMPRESS_TESTCASES)
    // we only compress the testcase if it does not fit in the TCP packet
    if (compressor && *lenptr > 1500 - 20 - 32 - 4) {

      u32 clen = (u32)libdeflate_deflate_compress(compressor, buf + 4, *lenptr,
                                                  buf2 + 8, buf2_len);

      if (!clen) FATAL("compression of the test case failed");

      // set highest byte to signify compression
      ((u32 *)buf2)[0] = *lenptr | AFL_NETWORK_COMPRESSED;
      ((u32 *)buf2)[1] = clen;

      if (!afl_network_send(s, buf2, clen + 8))
        PFATAL("sending test data failed");

    } else

#endif
    {

      if (!afl_network_send(s, buf, *lenptr + 4))
        PFATAL("sending test data failed");

    }

    if (!afl_network_recv(s, &status, 4)) FATAL("did not receive waitpid data");

#ifdef USE_DEFLATE
    if (decompressor) {

      if (!afl_network_recv(s, &compress_len, 4))
        FATAL("did not receive the compressed coverage length");

      if (!compress_len || compress_len > buf2_len)
        FATAL("received an illegal compressed coverage length of %u",
              compress_len);

      if (!afl_network_recv(s, buf2, compress_len))
        FATAL("did not receive coverage data");

      if (libdeflate_deflate_decompress(
              decompressor, buf2, compress_len, __afl_area_ptr, __afl_map_size,
              &decompress_len) != LIBDEFLATE_SUCCESS ||
          decompress_len != __afl_map_size)
        FATAL("decompression failed");

    } else

#endif
    {

      if (!afl_network_recv(s, __afl_area_ptr, __afl_map_size))
        FATAL("did not receive coverage data");

    }

    /* report the test case is done and wait for the next */
    __afl_end_testcase(status);

  }

#ifdef USE_DEFLATE
  if (compressor) libdeflate_free_compressor(compressor);
  if (decompressor) libdeflate_free_decompressor(decompressor);
  free(buf2);
#endif
  free(buf);
  close(s);

  return 0;

}

