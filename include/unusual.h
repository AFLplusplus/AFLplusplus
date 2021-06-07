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

#define INV_ONEOF_MAX_NUM_VALS 8

enum {

  INV_NONE = 0,
  INV_LT,
  INV_LE,
  INV_GT,
  INV_GE,
  INV_EQ,
  INV_NE,
  INV_ONEOF,
  INV_ALL,

};

struct single_var_invariant {

  // u64 max, min;
  u64 vals[INV_ONEOF_MAX_NUM_VALS];
  u8  num_vals;
  u8  invariant;

};

struct unusual_values_state {

  u8 map[UNUSUAL_MAP_SIZE / 8];
  u8 virgin[UNUSUAL_MAP_SIZE / 8];

  struct single_var_invariant single_invariants[UNUSUAL_MAP_SIZE];
  u8                          pair_invariants[UNUSUAL_MAP_SIZE];

  u8 found_new, learning;

};

/* Execs the child */

struct afl_forkserver;
void unusual_exec_child(struct afl_forkserver *fsrv, char **argv);

#endif

