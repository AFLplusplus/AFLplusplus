/*
   american fuzzy lop++ - cmplog header
   ------------------------------------

   Originally written by Michal Zalewski

   Forkserver design by Jann Horn <jannhorn@googlemail.com>

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                     Heiko Eißfeldt <heiko.eissfeldt@hexco.de>,
                     Andrea Fioraldi <andreafioraldi@gmail.com>,
                     Dominik Maier <mail@dmnk.co>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2022 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   Shared code to handle the shared memory. This is used by the fuzzer
   as well the other components like afl-tmin, afl-showmap, etc...

 */

#ifndef _AFL_CMPLOG_H
#define _AFL_CMPLOG_H

#include "config.h"

#define CMPLOG_LVL_MAX 3

#define CMP_MAP_W 65536
#define CMP_MAP_H 32
#define CMP_MAP_RTN_H (CMP_MAP_H / 4)

#define SHAPE_BYTES(x) (x + 1)

#define CMP_TYPE_INS 1
#define CMP_TYPE_RTN 2

// #define VARIABLE_VALUE 1
// #define VARIABLE_VALUE_BY_INPUT 2
// #define VARIABLE_INCONSISTENT 3
// #define VARIABLE_INCONSISTENT_BY_INPUT 4

struct cmp_header {

  unsigned hits : 24;
  unsigned id : 24;
  unsigned shape : 5;
  unsigned type : 2;
  unsigned attribute : 4;
  unsigned overflow : 1;
  unsigned unchanging : 1;

} __attribute__((packed));

struct cmp_operands {

  u64 v0;
  u64 v1;
  u64 v0_128;
  u64 v1_128;
  // unsigned v0_variable : 2;
  // unsigned v1_variable : 2;

} __attribute__((packed));

struct cmpfn_operands {

  u8 v0[31];
  u8 v0_len;
  u8 v1[31];
  u8 v1_len;
  // unsigned v0_variable : 2;
  // unsigned v1_variable : 2;

} __attribute__((packed));

typedef struct cmp_operands cmp_map_list[CMP_MAP_H];

struct cmp_map {

  struct cmp_header   headers[CMP_MAP_W];
  struct cmp_operands log[CMP_MAP_W][CMP_MAP_H];

};

/* Compare to taint mapping */

struct taint_logged {
  u32 nv0;
  u32 nv1;
  struct tainted ** v0;
  struct tainted ** v1;
};

struct taint_cmp {
  u32 key;
  struct taint_logged * taint_loggeds;
};

struct taint_mapping{
  u32 n;
  struct taint_cmp * taint_cmps;
};

/* Cache try out */

struct byte_replacement{
  u8 repl_u8_00;
  u8 repl_u8_01;
  u8 repl_u16_00;
  u8 repl_u16_01;
};

/* Execs the child */

struct afl_forkserver;
void cmplog_exec_child(struct afl_forkserver *fsrv, char **argv);

#endif

