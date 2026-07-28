/*
   american fuzzy lop++ - network proxy protocol
   ---------------------------------------------

   Written by Marc Heuse <mh@mh-sec.de>

   Copyright 2019-2026 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

   http://www.apache.org/licenses/LICENSE-2.0

   Wire protocol shared by afl-network-client and afl-network-server.

   On connect the client sends { hello, flags, max_testcase_len } and the
   server answers with { hello, negotiated flags, map_size }. Afterwards each
   iteration is a test case from the client and a { child_status, coverage }
   answer from the server.

*/

#ifndef _AFL_NETWORK_PROXY_H
#define _AFL_NETWORK_PROXY_H

#include <sys/types.h>
#include <sys/socket.h>

#include "types.h"

#define AFL_NETWORK_VERSION 1
#define AFL_NETWORK_HELLO (0x414e5000U + AFL_NETWORK_VERSION)

#define AFL_NETWORK_FLAG_DEFLATE 0x00000001U

#define AFL_NETWORK_COMPRESSED 0xff000000U
#define AFL_NETWORK_MAX_TESTCASE 0x00ffffffU

static inline int afl_network_recv(int s, void *buf, size_t len) {

  size_t offset = 0;

  while (offset < len) {

    ssize_t ret = recv(s, (u8 *)buf + offset, len - offset, 0);
    if (ret <= 0) { return 0; }
    offset += (size_t)ret;

  }

  return 1;

}

static inline int afl_network_send(int s, const void *buf, size_t len) {

  size_t offset = 0;

  while (offset < len) {

    ssize_t ret = send(s, (const u8 *)buf + offset, len - offset, 0);
    if (ret <= 0) { return 0; }
    offset += (size_t)ret;

  }

  return 1;

}

#endif

