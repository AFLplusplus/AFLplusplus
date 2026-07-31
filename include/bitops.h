/*
   american fuzzy lop++ - common bit operations
   --------------------------------------------

   Originally written by Michal Zalewski

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

 */

#ifndef _AFL_BITOPS_H
#define _AFL_BITOPS_H

#include "types.h"

/* Popcount for 64-bit operands. */
static inline u32 popcount_u64(u64 v) {

  return (u32)__builtin_popcountll(v);

}

/* Popcount for 32-bit operands. */
static inline u32 popcount_u32(u32 v) {

  return (u32)__builtin_popcount(v);

}

/* Popcount for 8-bit operands (promoted to u32 for builtin). */
static inline u32 popcount_u8(u8 v) {

  return (u32)__builtin_popcount((u32)v);

}

/* Number of significant bits (0 for input 0). */
static inline u32 bit_length_u64(u64 v) {

  return v ? (64U - (u32)__builtin_clzll(v)) : 0U;

}

#endif

