/*
   american fuzzy lop++ - afl-network-client
   ---------------------------------------

   Written by Marc Heuse <mh@mh-sec.de>

   Copyright 2019-2022 AFLplusplus Project. All rights reserved.

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

/* SHM setup. */

static void __afl_map_shm(void) {

  char *id_str = getenv(SHM_ENV_VAR);
  char *ptr;

  if ((ptr = getenv("AFL_MAP_SIZE")) != NULL) {

    u32 val = atoi(ptr);
    if (val > 0) __afl_map_size = val;

  }

  if (__afl_map_size > MAP_SIZE) {

    if (__afl_map_size > FS_OPT_MAX_MAPSIZE) {

      fprintf(stderr,
              "Error: AFL++ tools *require* to set AFL_MAP_SIZE to %u to "
              "be able to run this instrumented program!\n",
              __afl_map_size);
      if (id_str) {

        send_forkserver_error(FS_ERROR_MAP_SIZE);
        exit(-1);

      }

    } else {

      fprintf(stderr,
              "Warning: AFL++ tools will need to set AFL_MAP_SIZE to %u to "
              "be able to run this instrumented program!\n",
              __afl_map_size);

    }

  }

  if (id_str) {

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
    shm_base =
        mmap(0, __afl_map_size, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);

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

    if (__afl_area_ptr == (void *)-1) {

      send_forkserver_error(FS_ERROR_SHMAT);
      exit(1);

    }

    /* Write something into the bitmap so that the parent doesn't give up */

    __afl_area_ptr[0] = 1;

  }

}

/* Fork server logic. */

static void __afl_start_forkserver(void) {

  u8  tmp[4] = {0, 0, 0, 0};
  u32 status = 0;

  if (__afl_map_size <= FS_OPT_MAX_MAPSIZE)
    status |= (FS_OPT_SET_MAPSIZE(__afl_map_size) | FS_OPT_MAPSIZE);
  if (status) status |= (FS_OPT_ENABLED);
  memcpy(tmp, &status, 4);

  /* Phone home and tell the parent that we're OK. */

  if (write(FORKSRV_FD + 1, tmp, 4) != 4) return;

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

/* you just need to modify the while() loop in this main() */

int main(int argc, char *argv[]) {

  u8             *interface, *buf, *ptr;
  s32             s = -1;
  struct addrinfo hints, *hres, *aip;
  u32            *lenptr, max_len = 65536;
#ifdef USE_DEFLATE
  u8    *buf2;
  u32   *lenptr1, *lenptr2, buf2_len, compress_len;
  size_t decompress_len;
#endif

  if (argc < 3 || argc > 4) {

    printf("Syntax: %s host port [max-input-size]\n\n", argv[0]);
    printf("Requires host and port of the remote afl-proxy-server instance.\n");
    printf(
        "IPv4 and IPv6 are supported, also binding to an interface with "
        "\"%%\"\n");
    printf("The max-input-size default is %u.\n", max_len);
    printf(
        "The default map size is %u and can be changed with setting "
        "AFL_MAP_SIZE.\n",
        __afl_map_size);
    exit(-1);

  }

  if ((interface = strchr(argv[1], '%')) != NULL) *interface++ = 0;

  if (argc > 3)
    if ((max_len = atoi(argv[3])) < 0)
      FATAL("max-input-size may not be negative or larger than 2GB: %s",
            argv[3]);

  if ((ptr = getenv("AFL_MAP_SIZE")) != NULL)
    if ((__afl_map_size = atoi(ptr)) < 8)
      FATAL("illegal map size, may not be < 8 or >= 2^30: %s", ptr);

  if ((buf = malloc(max_len + 4)) == NULL)
    PFATAL("can not allocate %u memory", max_len + 4);
  lenptr = (u32 *)buf;

#ifdef USE_DEFLATE
  buf2_len = (max_len > __afl_map_size ? max_len : __afl_map_size);
  if ((buf2 = malloc(buf2_len + 8)) == NULL)
    PFATAL("can not allocate %u memory", buf2_len + 8);
  lenptr1 = (u32 *)buf2;
  lenptr2 = (u32 *)(buf2 + 4);
#endif

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

#ifdef USE_DEFLATE
  struct libdeflate_compressor *compressor;
  compressor = libdeflate_alloc_compressor(1);
  struct libdeflate_decompressor *decompressor;
  decompressor = libdeflate_alloc_decompressor();
  fprintf(stderr, "Compiled with compression support\n");
#endif

  if (s == -1)
    FATAL("could not connect to target tcp://%s:%s", argv[1], argv[2]);
  else
    fprintf(stderr, "Connected to target tcp://%s:%s\n", argv[1], argv[2]);

  /* we initialize the shared memory map and start the forkserver */
  __afl_map_shm();
  __afl_start_forkserver();

  int i = 1, j, status, ret, received;

  // fprintf(stderr, "Waiting for first testcase\n");
  while ((*lenptr = __afl_next_testcase(buf + 4, max_len)) > 0) {

    // fprintf(stderr, "Sending testcase with len %u\n", *lenptr);
#ifdef USE_DEFLATE
  #ifdef COMPRESS_TESTCASES
    // we only compress the testcase if it does not fit in the TCP packet
    if (*lenptr > 1500 - 20 - 32 - 4) {

      // set highest byte to signify compression
      *lenptr1 = (*lenptr | 0xff000000);
      *lenptr2 = (u32)libdeflate_deflate_compress(compressor, buf + 4, *lenptr,
                                                  buf2 + 8, buf2_len);
      if (send(s, buf2, *lenptr2 + 8, 0) != *lenptr2 + 8)
        PFATAL("sending test data failed");
      // fprintf(stderr, "COMPRESS (%u->%u):\n", *lenptr, *lenptr2);
      // for (u32 i = 0; i < *lenptr; i++)
      //  fprintf(stderr, "%02x", buf[i + 4]);
      // fprintf(stderr, "\n");
      // for (u32 i = 0; i < *lenptr2; i++)
      //  fprintf(stderr, "%02x", buf2[i + 8]);
      // fprintf(stderr, "\n");

    } else {

  #endif
#endif
      if (send(s, buf, *lenptr + 4, 0) != *lenptr + 4)
        PFATAL("sending test data failed");
#ifdef USE_DEFLATE
  #ifdef COMPRESS_TESTCASES
      // fprintf(stderr, "unCOMPRESS (%u)\n", *lenptr);

    }

  #endif
#endif

    received = 0;
    while (received < 4 &&
           (ret = recv(s, &status + received, 4 - received, 0)) > 0)
      received += ret;
    if (received != 4)
      FATAL("did not receive waitpid data (%d, %d)", received, ret);
    // fprintf(stderr, "Received status\n");

    received = 0;
#ifdef USE_DEFLATE
    while (received < 4 &&
           (ret = recv(s, &compress_len + received, 4 - received, 0)) > 0)
      received += ret;
    if (received != 4)
      FATAL("did not receive compress_len (%d, %d)", received, ret);
    // fprintf(stderr, "Received status\n");

    received = 0;
    while (received < compress_len &&
           (ret = recv(s, buf2 + received, buf2_len - received, 0)) > 0)
      received += ret;
    if (received != compress_len)
      FATAL("did not receive coverage data (%d, %d)", received, ret);

    if (libdeflate_deflate_decompress(decompressor, buf2, compress_len,
                                      __afl_area_ptr, __afl_map_size,
                                      &decompress_len) != LIBDEFLATE_SUCCESS ||
        decompress_len != __afl_map_size)
      FATAL("decompression failed");
      // fprintf(stderr, "DECOMPRESS (%u->%u): ", compress_len, decompress_len);
      // for (u32 i = 0; i < __afl_map_size; i++) fprintf(stderr, "%02x",
      // __afl_area_ptr[i]); fprintf(stderr, "\n");
#else
    while (received < __afl_map_size &&
           (ret = recv(s, __afl_area_ptr + received, __afl_map_size - received,
                       0)) > 0)
      received += ret;
    if (received != __afl_map_size)
      FATAL("did not receive coverage data (%d, %d)", received, ret);
#endif
    // fprintf(stderr, "Received coverage\n");

    /* report the test case is done and wait for the next */
    __afl_end_testcase(status);
    // fprintf(stderr, "Waiting for next testcase %d\n", ++i);

  }

#ifdef USE_DEFLATE
  libdeflate_free_compressor(compressor);
  libdeflate_free_decompressor(decompressor);
  free(buf2);
#endif
  free(buf);

  return 0;

}

