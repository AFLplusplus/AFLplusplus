/*
   american fuzzy lop++ - LLVM instrumentation bootstrap
   -----------------------------------------------------

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

*/

#include "unusual.h"

#define OUTLIER_TRESHOLD 3

static u64 welford_sigma(struct unusual_values_state *state) {

  if (state->n >= 2) return sqrt(state->s[0] / (state->n - 1.0));
  return 0;  // TODO err

}

void welford_add(struct unusual_values_state *state, u64 x) {

  size_t n = ++state->n;
  if (n == 1) {

    state->m[0] = x;

  } else {

    state->m[1] = state->m[0] + (x - state->m[0]) / n;
    state->s[1] = state->s[0] + (x - state->m[0]) * (x - state->m[1]);
    state->m[0] = state->m[1];                             /* for next time */
    state->s[0] = state->s[1];                             /* for next time */

  }

}

int welford_is_outlier() {

  if (state->n < 2) return 0;
  uint64_t upper = state->m[0] + OUTLIER_TRESHOLD * state->s[0];
  uint64_t lower = state->m[0] - OUTLIER_TRESHOLD * state->s[0];
  return x > upper || x < lower;

}

