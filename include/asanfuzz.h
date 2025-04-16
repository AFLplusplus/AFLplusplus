/*
   american fuzzy lop++ - cmplog header
   ------------------------------------

   Originally written by Michal Zalewski

   Forkserver design by Jann Horn <jannhorn@googlemail.com>

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                     Dominik Maier <mail@dmnk.co>,
                     Andrea Fioraldi <andreafioraldi@gmail.com>,
                     Heiko Eissfeldt <heiko.eissfeldt@hexco.de>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2023 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   Shared code to handle the shared memory. This is used by the fuzzer
   as well the other components like afl-tmin, afl-showmap, etc...

 */

#ifndef _AFL_ASAMFUZZ_H
#define _AFL_ASAMFUZZ_H

#include "config.h"

// new_bits for describe_op
// new_bits value 1, 2 and 0x80 are already used!
#define SAN_CRASH_ONLY (1 << 4)
#define NON_COV_INCREASE_BUG (1 << 5)

enum SanitizerAbstraction {

  SIMPLIFY_TRACE = 0,  // Feed all simplified trace to sanitizers, moderate
                       // sensitive and default for SAND. Not missing bugs.
  UNIQUE_TRACE,      // Feed all unique trace to sanitizers, the most sensitive
                     // and not missing bugs.
  COVERAGE_INCREASE  // Feed all coverage increasing cases to sanitizers, the
                     // least sensitive at a risk of missing ~20% bugs.

};

/* Execs the child */

struct afl_forkserver;
void sanfuzz_exec_child(struct afl_forkserver *fsrv, char **argv);

#endif

