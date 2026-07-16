/*
   american fuzzy lop++ - cmplog header
   ------------------------------------

   Originally written by Michal Zalewski

   Forkserver design by Jann Horn <jannhorn@googlemail.com>

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                     Heiko Eissfeldt <heiko.eissfeldt@hexco.de>,
                     Andrea Fioraldi <andreafioraldi@gmail.com>,
                     Dominik Maier <mail@dmnk.co>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2026 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

   Shared code to handle the shared memory. This is used by the fuzzer
   as well the other components like afl-tmin, afl-showmap, etc...

 */

#ifndef _AFL_CMPLOG_H
#define _AFL_CMPLOG_H

#include "config.h"

#define CMPLOG_LVL_MAX 3

#define CMP_MAP_W 65536
#define CMP_MAP_H 32
#define CMP_MAP_RTN_H (CMP_MAP_H / 2)

#define SHAPE_BYTES(x) (x + 1)

#define CMP_TYPE_INS 0
#define CMP_TYPE_RTN 1

#define ADDR_ATTR_COMBINE(v0attr, v1attr) ((v0attr & 3) + ((v1attr & 3) << 2))
#define ADDR_ATTR_V0(x) (x & 3)
#define ADDR_ATTR_V1(x) ((x >> 2) & 3)

struct cmp_header {  // 16 bit = 2 bytes

  unsigned hits : 6;       // up to 63 entries, we have CMP_MAP_H = 32
  unsigned shape : 5;      // 31+1 bytes max
  unsigned type : 1;       // 2: cmp, rtn
  unsigned attribute : 4;  // 16 for arithmetic comparison types

} __attribute__((packed));

#ifndef likely
  #define likely(cond) __builtin_expect(!!(cond), 1)
#endif

#ifndef unlikely
  #define unlikely(cond) __builtin_expect(!!(cond), 0)
#endif

static inline u32 cmp_map_reserve(struct cmp_header *header, u8 *cursor,
                                  u32 capacity) {

  if (unlikely(header->hits == 0)) { *cursor = 0; }
  u32 slot = *cursor & (capacity - 1);
  *cursor = (*cursor + 1) & 63;
  if (likely(header->hits < capacity)) { ++header->hits; }
  return slot;

}

struct cmp_operands {

  u64 v0;
  u64 v0_128;
  u64 v0_256_0;  // u256 is unsupported by any compiler for now, so future use
  u64 v0_256_1;
  u64 v1;
  u64 v1_128;
  u64 v1_256_0;
  u64 v1_256_1;
  u8  unused[8];  // 2 bits could be used for "is constant operand"

} __attribute__((packed));

struct cmpfn_operands {

  u8 v0[32];
  u8 v1[32];
  u8 v0_len;
  u8 v1_len;
  u8 addr_attr;
  u8 unused[5];  // 2 bits could be used for "is constant operand"

} __attribute__((packed));

typedef struct cmp_operands cmp_map_list[CMP_MAP_H];

struct cmp_map {

  struct cmp_header   headers[CMP_MAP_W];
  struct cmp_operands log[CMP_MAP_W][CMP_MAP_H];

};

/* Execs the child */

struct afl_forkserver;
void cmplog_exec_child(struct afl_forkserver *fsrv, char **argv);

// Attribute of whether the Buffer points to the memory area mapped by ELF
enum {

  ADDR_ATTR_NOTFOUND = 0,
  ADDR_ATTR_RO = 1,
  ADDR_ATTR_RW = 2,

};

#endif

