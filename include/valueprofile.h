/*
   american fuzzy lop++ - value profile header
   ------------------------------------

   Originally written by Michal Zalewski

   Forkserver design by Jann Horn <jannhorn@googlemail.com>

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                     Dominik Maier <mail@dmnk.co>,
                     Andrea Fioraldi <andreafioraldi@gmail.com>,
                     Heiko Eissfeldt <heiko.eissfeldt@hexco.de>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2024 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   Shared code to handle the shared memory. This is used by the fuzzer
   as well the other components like afl-tmin, afl-showmap, etc...

 */

#ifndef _AFL_VALUEPROFILE_H
#define _AFL_VALUEPROFILE_H

#include "config.h"

#define VP_MAP_SIZE 65536

#define VP_TYPE_CMP 1
#define VP_TYPE_FCMP 2
#define VP_TYPE_RTN 3
#define VP_TYPE_STR 4

struct vp_header {  // 16 bit = 2 bytes

  u64 value;      // up to u64
  u64 value_ext;  // u65 to u128
  u8  type;       // 0-2
  u8  status;     // 0-1
  u8  len;        // 2-16
  u8  attribute;  // 0-15
  u32 reserved2;

} __attribute__((packed));

struct vp_map {

  struct vp_header header[VP_MAP_SIZE];
  u32              control[VP_MAP_SIZE + 1];

};

#endif

