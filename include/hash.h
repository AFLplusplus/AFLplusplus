/*
   american fuzzy lop++ - hashing function
   ---------------------------------------

   Copyright 2016 Google Inc. All rights reserved.
   Copyright 2019-2024 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

 */

#ifndef _HAVE_HASH_H
#define _HAVE_HASH_H

#include "types.h"

u32 hash32(u8 *key, u32 len, u32 seed);
u64 hash64(u8 *key, u32 len, u64 seed);

#endif                                                     /* !_HAVE_HASH_H */

