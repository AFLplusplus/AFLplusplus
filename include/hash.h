/*
   american fuzzy lop++ - hashing function
   ---------------------------------------

   Copyright 2016 Google Inc. All rights reserved.
   Copyright 2019-2026 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

 */

#ifndef _HAVE_HASH_H
#define _HAVE_HASH_H

#include "types.h"

/* Murmur3 32-bit finalizer.
   We use this for value-profile feature scattering. Properties that make it a
   good fit here:
   - Bijective: every u32 input maps to a unique u32 output (each step -
     xor-right-shift and odd-constant multiply - is invertible over u32), so
     no collisions are introduced before the final modulo into the bitmap.
   - Full avalanche: every output bit depends on every input bit, ensuring
     features from different comparison sites are uniformly distributed.
   - Fast: 2 multiplies + 3 xor-shifts (~3-4 cycles on modern CPUs).
   The constants were specifically optimized by Austin Appleby for avalanche
   quality in the Murmur3 hash family. */
static inline u32 hash_fmix32(u32 h) {

  h ^= h >> 16;
  h *= 0x85ebca6b;
  h ^= h >> 13;
  h *= 0xc2b2ae35;
  h ^= h >> 16;
  return h;

}

/* MurmurHash3 64-bit finalizer (fmix64).
   Same role as hash_fmix32() but for u64 inputs. */
static inline u64 hash_fmix64(u64 k) {

  k ^= k >> 33;
  k *= 0xff51afd7ed558ccdULL;
  k ^= k >> 33;
  k *= 0xc4ceb9fe1a85ec53ULL;
  k ^= k >> 33;
  return k;

}

u32 hash32(u8 *key, u32 len, u32 seed);
u64 hash64(u8 *key, u32 len, u64 seed);

#endif                                                     /* !_HAVE_HASH_H */

