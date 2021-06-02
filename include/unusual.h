/*
   american fuzzy lop++ - unusual values header
   --------------------------------------------

   Written by Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2021 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

 */

#ifndef _AFL_UNUSUAL_H
#define _AFL_UNUSUAL_H

#include "config.h"
#include "types.h"

#define UNUSUAL_MAP_SIZE 65536
#define UNUSUAL_MAP_BYTES \
  (UNUSUAL_MAP_SIZE * sizeof(struct unusual_values_state))

struct unusual_values_state {

  u64    m[2];
  u64    s[2];
  size_t n;

};

#endif

