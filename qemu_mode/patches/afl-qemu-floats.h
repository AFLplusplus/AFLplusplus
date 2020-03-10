/*
   american fuzzy lop++ - high-performance binary-only instrumentation
   -------------------------------------------------------------------

   Originally written by Andrew Griffiths <agriffiths@google.com> and
                         Michal Zalewski

   TCG instrumentation and block chaining support by Andrea Biondo
                                      <andrea.biondo965@gmail.com>

   QEMU 3.1.1 port, TCG thread-safety, CompareCoverage and NeverZero
   counters by Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2015, 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This code is a shim patched into the separately-distributed source
   code of QEMU 3.1.0. It leverages the built-in QEMU tracing functionality
   to implement AFL-style instrumentation and to take care of the remaining
   parts of the AFL fork server logic.

   The resulting QEMU binary is essentially a standalone instrumentation
   tool; for an example of how to leverage it for other purposes, you can
   have a look at afl-showmap.c.

 */

#include "tcg.h"
#include "afl-qemu-common.h"

union afl_float32 {

  float32 f;
  struct {

    u64 sign : 1;
    u64 exp : 7;
    u64 frac : 24;

  };

};

union afl_float64 {

  float64 f;
  struct {

    u64 sign : 1;
    u64 exp : 11;
    u64 frac : 52;

  };

};

// TODO 16 and 128 bits floats
// TODO figure out why float*_unpack_canonical does not work

void afl_float_compcov_log_32(target_ulong cur_loc, float32 arg1, float32 arg2,
                              void *status) {

  cur_loc = (cur_loc >> 4) ^ (cur_loc << 8);
  cur_loc &= MAP_SIZE - 7;

  if (cur_loc >= afl_inst_rms) return;

  // float_status*s = (float_status*)status;
  // FloatParts    a = float32_unpack_canonical(arg1, s);
  // FloatParts    b = float32_unpack_canonical(arg2, s);
  union afl_float32 a = {.f = arg1};
  union afl_float32 b = {.f = arg2};

  // if (is_nan(a.cls) || is_nan(b.cls)) return;

  register uintptr_t idx = cur_loc;

  if (a.sign != b.sign) return;
  INC_AFL_AREA(idx);
  if (a.exp != b.exp) return;
  INC_AFL_AREA(idx + 1);

  if ((a.frac & 0xff0000) == (b.frac & 0xff0000)) {

    INC_AFL_AREA(idx + 2);
    if ((a.frac & 0xff00) == (b.frac & 0xff00)) { INC_AFL_AREA(idx + 3); }

  }

}

void afl_float_compcov_log_64(target_ulong cur_loc, float64 arg1, float64 arg2,
                              void *status) {

  cur_loc = (cur_loc >> 4) ^ (cur_loc << 8);
  cur_loc &= MAP_SIZE - 7;

  if (cur_loc >= afl_inst_rms) return;

  // float_status*s = (float_status*)status;
  // FloatParts    a = float64_unpack_canonical(arg1, s);
  // FloatParts    b = float64_unpack_canonical(arg2, s);
  union afl_float64 a = {.f = arg1};
  union afl_float64 b = {.f = arg2};

  // if (is_nan(a.cls) || is_nan(b.cls)) return;

  register uintptr_t idx = cur_loc;

  if (a.sign == b.sign) INC_AFL_AREA(idx);
  if ((a.exp & 0xff00) == (b.exp & 0xff00)) {

    INC_AFL_AREA(idx + 1);
    if ((a.exp & 0xff) == (b.exp & 0xff)) INC_AFL_AREA(idx + 2);

  }

  if ((a.frac & 0xff000000000000) == (b.frac & 0xff000000000000)) {

    INC_AFL_AREA(idx + 3);
    if ((a.frac & 0xff0000000000) == (b.frac & 0xff0000000000)) {

      INC_AFL_AREA(idx + 4);
      if ((a.frac & 0xff00000000) == (b.frac & 0xff00000000)) {

        INC_AFL_AREA(idx + 5);
        if ((a.frac & 0xff000000) == (b.frac & 0xff000000)) {

          INC_AFL_AREA(idx + 6);
          if ((a.frac & 0xff0000) == (b.frac & 0xff0000)) {

            INC_AFL_AREA(idx + 7);
            if ((a.frac & 0xff00) == (b.frac & 0xff00)) INC_AFL_AREA(idx + 8);

          }

        }

      }

    }

  }

}

void afl_float_compcov_log_80(target_ulong cur_loc, floatx80 arg1,
                              floatx80 arg2) {

  cur_loc = (cur_loc >> 4) ^ (cur_loc << 8);
  cur_loc &= MAP_SIZE - 7;

  if (cur_loc >= afl_inst_rms) return;

  if (floatx80_invalid_encoding(arg1) || floatx80_invalid_encoding(arg2))
    return;

  flag a_sign = extractFloatx80Sign(arg1);
  flag b_sign = extractFloatx80Sign(arg2);

  /*if (((extractFloatx80Exp(arg1) == 0x7fff) &&
       (extractFloatx80Frac(arg1) << 1)) ||
      ((extractFloatx80Exp(arg2) == 0x7fff) &&
       (extractFloatx80Frac(arg2) << 1)))
    return;*/

  register uintptr_t idx = cur_loc;

  if (a_sign == b_sign) INC_AFL_AREA(idx);

  if ((arg1.high & 0x7f00) == (arg2.high & 0x7f00)) {

    INC_AFL_AREA(idx + 1);
    if ((arg1.high & 0xff) == (arg2.high & 0xff)) INC_AFL_AREA(idx + 2);

  }

  if ((arg1.low & 0xff00000000000000) == (arg2.low & 0xff00000000000000)) {

    INC_AFL_AREA(idx + 3);
    if ((arg1.low & 0xff000000000000) == (arg2.low & 0xff000000000000)) {

      INC_AFL_AREA(idx + 4);
      if ((arg1.low & 0xff0000000000) == (arg2.low & 0xff0000000000)) {

        INC_AFL_AREA(idx + 5);
        if ((arg1.low & 0xff00000000) == (arg2.low & 0xff00000000)) {

          INC_AFL_AREA(idx + 6);
          if ((arg1.low & 0xff000000) == (arg2.low & 0xff000000)) {

            INC_AFL_AREA(idx + 7);
            if ((arg1.low & 0xff0000) == (arg2.low & 0xff0000)) {

              INC_AFL_AREA(idx + 8);
              if ((arg1.low & 0xff00) == (arg2.low & 0xff00)) {

                INC_AFL_AREA(idx + 9);
                // if ((arg1.low & 0xff) == (arg2.low & 0xff))
                //  INC_AFL_AREA(idx + 10);

              }

            }

          }

        }

      }

    }

  }

}

