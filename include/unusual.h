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
#include <string.h>

#define UNUSUAL_MAP_SIZE 65536

#define INV_ONEOF_MAX_NUM_VALS 8
#define INV_EXECS_MIN_BOUND 32

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

  // ptr invariants (reuse INV_EQ and INV_GT)
  INV_GT_PAGE,  // greater than PAGE_SIZE
  INV_HEAP,     // future use, maybe with sbrk(0)
  INV_STACK,    // check if below __builtin_frame_address(0)

};

struct single_var_invariant {

  u64 vals[INV_ONEOF_MAX_NUM_VALS];
  u8  num_vals;
  u8  execs;
  u8  invariant;

};

struct single_ptr_invariant {

  u8 execs;
  u8 invariant;

};

struct __attribute__((__packed__)) pair_vars_invariant {

  u8 invariant;
  u8 execs;

};

struct unusual_values_state {

  u8 map[UNUSUAL_MAP_SIZE / 8];
  u8 virgin[UNUSUAL_MAP_SIZE / 8];

  struct single_var_invariant single_invariants[UNUSUAL_MAP_SIZE];
  struct pair_vars_invariant  pair_invariants[UNUSUAL_MAP_SIZE];

  u8 learning;

};

inline void unusual_values_state_init(struct unusual_values_state *state) {

  // memset(state->map, 0, UNUSUAL_MAP_SIZE / 8);
  memset(state->virgin, 0xff, UNUSUAL_MAP_SIZE / 8);
  state->learning = 1;

}

inline void unusual_values_state_reset(struct unusual_values_state *state) {

  memset(state->map, 0, UNUSUAL_MAP_SIZE / 8);

}

/* Execs the child */

struct afl_forkserver;
void unusual_exec_child(struct afl_forkserver *fsrv, char **argv);

#endif

