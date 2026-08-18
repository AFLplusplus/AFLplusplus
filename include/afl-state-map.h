/*
   american fuzzy lop++ - state fuzzing transition map
   ---------------------------------------------------

   Written by Marc Heuse <mh@mh-sec.de>

   Copyright 2019-2026 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

   Shared memory layout of the state-transition map used by state fuzzing
   mode (-J s). The region is a segment of its own, addressed through
   STATE_SHM_ENV_VAR, so that the state signal stays separable from edge
   coverage. Both the instrumentation runtime and afl-fuzz include this
   header, so a transition index can be recomputed offline from a triple.

 */

#ifndef _AFL_STATE_MAP_H
#define _AFL_STATE_MAP_H

#include <stdint.h>
#include "config.h"

typedef struct state_map {

  uint8_t  map[STATE_MAP_SIZE];        /* (prev, cur, action) hit counts    */
  uint32_t cur_state;                  /* state after the last transition   */
  uint32_t prev_state;                 /* state before the last transition  */
  uint32_t action;                     /* action class set by the harness   */
  uint32_t transitions;                /* transitions taken this execution  */
  uint32_t hot_off;                    /* harness-declared hot region start */
  uint32_t hot_len;                    /* harness-declared hot region size  */

  /* Which slots this execution touched, so neither side has to walk 64KB for
     the two or three states a real target visits. touched_ovf says the list
     ran out and the whole map has to be handled after all. A target built
     before these fields existed leaves them zero, and transitions != 0 with
     touched_n == 0 is how that is recognised. */
  uint32_t touched_n;                  /* distinct slots touched            */
  uint8_t  touched_ovf;                /* list overflowed, walk the map     */
  uint8_t  touched_ok;                 /* target maintains the list at all  */
  uint32_t touched[STATE_TOUCHED_MAX]; /* the slots themselves              */

  /* The situations themselves, in the order the execution went through them,
     so the fuzzer can report how many distinct IJON_STATE values a campaign
     ever reached and how deep into a chain each one first appeared. The
     transition map cannot answer either question: its index is a hash of a
     triple and does not carry the state value back. A chain longer than the
     list keeps counting in transitions but stops being recorded here.
     sit_ok distinguishes a target built before these fields existed from one
     that took no transition. */

  uint32_t sit_n;                     /* situations recorded this execution */
  uint8_t  sit_ok;                    /* target maintains the list at all   */
  uint32_t sit[STATE_TOUCHED_MAX];    /* the situation values in order      */

} state_map_t;

/* Index of the (previous state, current state, action) triple. Two steps of
   context: full state histories explode the corpus, one step cannot tell
   INIT->AUTH->READY from INIT->AUTH->ERROR->AUTH->READY. */

static inline uint32_t state_transition_index(uint32_t prev, uint32_t cur,
                                              uint32_t action) {

  uint64_t h = ((uint64_t)prev * 0x9E3779B97F4A7C15ULL) ^
               ((uint64_t)cur * 0xC2B2AE3D27D4EB4FULL) ^
               ((uint64_t)action * 0x165667B19E3779F9ULL);
  h ^= h >> 29;
  h *= 0xBF58476D1CE4E5B9ULL;
  h ^= h >> 32;
  return (uint32_t)(h & (uint64_t)(STATE_MAP_SIZE - 1));

}

#endif                                                  /* _AFL_STATE_MAP_H */

