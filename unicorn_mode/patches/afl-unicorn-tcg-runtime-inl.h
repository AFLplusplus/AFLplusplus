/*
   american fuzzy lop++ - unicorn instrumentation
   ----------------------------------------------

   Originally written by Andrew Griffiths <agriffiths@google.com> and
                         Michal Zalewski

   Adapted for afl-unicorn by Dominik Maier <mail@dmnk.co>

   CompareCoverage and NeverZero counters by Andrea Fioraldi
                                  <andreafioraldi@gmail.com>

   Copyright 2015, 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This code is a shim patched into the separately-distributed source
   code of Unicorn 1.0.1. It leverages the built-in QEMU tracing functionality
   to implement AFL-style instrumentation and to take care of the remaining
   parts of the AFL fork server logic.

   The resulting libunicorn binary is essentially a standalone instrumentation
   tool; for an example of how to leverage it for other purposes, you can
   have a look at afl-showmap.c.

 */

#include "uc_priv.h"
#include "afl-unicorn-common.h"

void HELPER(afl_compcov_log_16)(void* uc_ptr, uint64_t cur_loc, uint64_t arg1,
                                uint64_t arg2) {

  u8* afl_area_ptr = ((struct uc_struct*)uc_ptr)->afl_area_ptr;

  if ((arg1 & 0xff00) == (arg2 & 0xff00)) { INC_AFL_AREA(cur_loc); }

}

void HELPER(afl_compcov_log_32)(void* uc_ptr, uint64_t cur_loc, uint64_t arg1,
                                uint64_t arg2) {

  u8* afl_area_ptr = ((struct uc_struct*)uc_ptr)->afl_area_ptr;

  if ((arg1 & 0xff000000) == (arg2 & 0xff000000)) {

    INC_AFL_AREA(cur_loc + 2);
    if ((arg1 & 0xff0000) == (arg2 & 0xff0000)) {

      INC_AFL_AREA(cur_loc + 1);
      if ((arg1 & 0xff00) == (arg2 & 0xff00)) { INC_AFL_AREA(cur_loc); }

    }

  }

}

void HELPER(afl_compcov_log_64)(void* uc_ptr, uint64_t cur_loc, uint64_t arg1,
                                uint64_t arg2) {

  u8* afl_area_ptr = ((struct uc_struct*)uc_ptr)->afl_area_ptr;

  if ((arg1 & 0xff00000000000000) == (arg2 & 0xff00000000000000)) {

    INC_AFL_AREA(cur_loc + 6);
    if ((arg1 & 0xff000000000000) == (arg2 & 0xff000000000000)) {

      INC_AFL_AREA(cur_loc + 5);
      if ((arg1 & 0xff0000000000) == (arg2 & 0xff0000000000)) {

        INC_AFL_AREA(cur_loc + 4);
        if ((arg1 & 0xff00000000) == (arg2 & 0xff00000000)) {

          INC_AFL_AREA(cur_loc + 3);
          if ((arg1 & 0xff000000) == (arg2 & 0xff000000)) {

            INC_AFL_AREA(cur_loc + 2);
            if ((arg1 & 0xff0000) == (arg2 & 0xff0000)) {

              INC_AFL_AREA(cur_loc + 1);
              if ((arg1 & 0xff00) == (arg2 & 0xff00)) { INC_AFL_AREA(cur_loc); }

            }

          }

        }

      }

    }

  }

}

