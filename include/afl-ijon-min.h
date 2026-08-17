/*
   american fuzzy lop++ - part of the AFL++ project
   ------------------------------------------------

   Copyright 2019-2026 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may obtain a copy at https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

 */

#ifndef _HAVE_AFL_IJON_MIN_H
#define _HAVE_AFL_IJON_MIN_H

#include "config.h"
#include "types.h"

#define IJON_MAX_INPUT_SIZE (64 * 1024)
#define IJON_REPLAY_INTERVAL 16

typedef struct {

  char  *filename;
  int    slot_id;
  size_t len;

} ijon_input_info;

typedef struct {

  u64              max_map[MAP_SIZE_IJON_ENTRIES];
  ijon_input_info *infos[MAP_SIZE_IJON_ENTRIES];
  size_t           num_entries;
  size_t           num_updates;
  char            *max_dir;
  u8               persisted[MAP_SIZE_IJON_ENTRIES];
  int              schedule_prob;
  u32              next_entry;
  u32              max_input_size;

  /* Rolling history bookkeeping (owned per state, not process-global) */
  int history_index;
  int variable_discovered[MAP_SIZE_IJON_ENTRIES];
  int num_discovered_vars;

} ijon_min_state;

/* SHARED MEMORY LAYOUT
 *
 * One region, three areas, cov being the coverage size the instrumentation
 * ended up with (rounded up to 64):
 *
 *   [0, cov)                          coverage bitmap, one byte per edge
 *   [cov, cov + IJON_MAP)             IJON_SET / IJON_INC / IJON_STATE
 *   [cov + IJON_MAP, ... + IJON_BYTES) IJON_MAX / IJON_MIN slots, u64 each
 *
 * Target side (afl-compiler-rt.o.c):
 *   __afl_cov_map_size = cov
 *   __afl_map_size     = cov + MAP_SIZE_IJON_MAP + MAP_SIZE_IJON_BYTES
 *   __afl_set_map_size = cov + MAP_SIZE_IJON_MAP, which is both the start of
 *                        the max slots (__afl_ijon_bits) and how much of the
 *                        region a persistent loop clears
 *
 * Fuzzer side: the forkserver reports __afl_map_size, and
 * configure_ijon_runtime() takes MAP_SIZE_IJON_BYTES off it, so
 * afl->fsrv.map_size == __afl_set_map_size and ijon_bits lands on the same
 * offset as the target's. The set/inc area stays *inside* the fuzzer's map on
 * purpose: a byte written there has to register as new coverage for the
 * IJON_SET channel to feed anything back. The coverage area alone is therefore
 * afl->fsrv.map_size - MAP_SIZE_IJON_MAP, and total_edges is the whole
 * afl->fsrv.map_size.
 */

// Dynamic shared memory access structure for all map sizes
typedef struct {

  u64 *ijon_max_area;  // Points to IJON max start (dynamic offset)
  u32  ijon_offset;    // Where IJON data starts

} dynamic_shared_access_t;

/* ijon global state variable*/
extern int afl_ijon_retire_max;

/* Function prototypes */
ijon_min_state  *new_ijon_min_state(char *max_dir);
ijon_min_state  *new_ijon_min_state_with_limit(char *max_dir,
                                               u32   max_input_size);
void             ijon_load_existing_state(ijon_min_state *self);
u8               ijon_should_schedule(ijon_min_state *self);
ijon_input_info *ijon_get_input(ijon_min_state *self);
u8 ijon_read_input(ijon_min_state *self, ijon_input_info *info, u8 **data,
                   u32 *len);
u8 ijon_store_max_input(ijon_min_state *self, int i, uint8_t *data, size_t len);
void ijon_store_history_if_best(ijon_min_state *self, int i, uint8_t *data,
                                size_t len);
void ijon_store_history_unconditional(ijon_min_state *self, int i,
                                      uint8_t *data, size_t len);
void destroy_ijon_min_state(ijon_min_state *self);

/* Unified dynamic shared memory access functions for all map sizes */
dynamic_shared_access_t *setup_dynamic_shared_access(u8 *trace_bits,
                                                     u32 map_size,
                                                     u32 real_map_size);
void cleanup_dynamic_shared_access(dynamic_shared_access_t *access);
void ijon_update_max_dynamic(ijon_min_state          *self,
                             dynamic_shared_access_t *shared, uint8_t *data,
                             size_t len);

/* Structure for comprehensive IJON state persistence */
typedef struct {

  u32 ijon_offset;
  u32 map_size;
  u32 real_map_size;
  u32 target_map_size;                        /* __afl_map_size from target */
  u8  is_initialized;

} ijon_fastresume_state_t;

/* IJON comprehensive state save/load for fastresume */
void save_ijon_state_for_fastresume(u32 offset, u32 map_size, u32 real_map_size,
                                    u32 target_map_size);
ijon_fastresume_state_t *get_saved_ijon_state(void);
u8                       has_saved_ijon_state(void);
void                     clear_saved_ijon_state(void);

/* IJON offset save/load for fastresume (legacy compatibility) */
void save_ijon_offset_for_fastresume(u32 offset);
u32  get_saved_ijon_offset(void);
u8   has_saved_ijon_offset(void);

/* IJON max tracking runtime functions */
#ifdef __cplusplus
extern "C" {

#endif

void ijon_max(uint32_t addr, u64 val);
void ijon_min(uint32_t addr, u64 val);
void ijon_max_until(uint32_t addr, u64 val, u64 limit);
void ijon_max_variadic(uint32_t addr, ...);
void ijon_min_variadic(uint32_t addr, ...);
void ijon_set(uint32_t addr, uint32_t val);
void ijon_inc(uint32_t addr, uint32_t val);

/* IJON state management functions */
void ijon_xor_state(uint32_t val);
void ijon_reset_state(void);

/* State fuzzing (-J s) annotations, see docs/fuzzing_stateful_targets.md */
void afl_state_action(uint32_t a);
void afl_state_hot(uint32_t off, uint32_t len);

/* Supporting hash functions */
uint64_t ijon_simple_hash(uint64_t x);
uint32_t ijon_hashint(uint32_t old, uint32_t val);
uint32_t ijon_hashstr(uint32_t old, char *val);
uint32_t ijon_hashmem(uint32_t old, char *val, size_t len);

/* Stack hashing functions - cross-platform backtrace support */
uint32_t ijon_hashstack_backtrace(void);
uint32_t ijon_hashstack(void);

/* String and memory distance functions */
uint32_t ijon_strdist(char *a, char *b);
uint32_t ijon_memdist(char *a, char *b, size_t len);

#ifdef __cplusplus

}

#endif

/* IJON max tracking macros */
#define IJON_MAX(...)                                      \
  do {                                                     \
                                                           \
    static uint32_t _ijon_loc_cache = 0;                   \
    if (unlikely(_ijon_loc_cache == 0)) {                  \
                                                           \
      _ijon_loc_cache = ijon_hashstr(__LINE__, __FILE__);  \
                                                           \
    }                                                      \
    ijon_max_variadic(_ijon_loc_cache, __VA_ARGS__, 0ULL); \
                                                           \
  } while (0)

// Single unified IJON_MIN macro - calls one runtime function
#define IJON_MIN(...)                                      \
  do {                                                     \
                                                           \
    static uint32_t _ijon_loc_cache = 0;                   \
    if (unlikely(_ijon_loc_cache == 0)) {                  \
                                                           \
      _ijon_loc_cache = ijon_hashstr(__LINE__, __FILE__);  \
                                                           \
    }                                                      \
    ijon_min_variadic(_ijon_loc_cache, __VA_ARGS__, 0ULL); \
                                                           \
  } while (0)

// IJON set macro - takes only ONE variable (not variadic like IJON_MAX)
#define IJON_SET(x)                                           \
  do {                                                        \
                                                              \
    static uint32_t _ijon_set_loc_cache = 0;                  \
    if (unlikely(_ijon_set_loc_cache == 0)) {                 \
                                                              \
      _ijon_set_loc_cache = ijon_hashstr(__LINE__, __FILE__); \
                                                              \
    }                                                         \
    ijon_set(_ijon_set_loc_cache, (x));                       \
                                                              \
  } while (0)

// IJON inc macro - takes only ONE variable and increments coverage counter
#define IJON_INC(x)                                           \
  do {                                                        \
                                                              \
    static uint32_t _ijon_inc_loc_cache = 0;                  \
    if (unlikely(_ijon_inc_loc_cache == 0)) {                 \
                                                              \
      _ijon_inc_loc_cache = ijon_hashstr(__LINE__, __FILE__); \
                                                              \
    }                                                         \
    ijon_inc(_ijon_inc_loc_cache, (x));                       \
                                                              \
  } while (0)

// IJON state macro - changes global state that affects ALL subsequent edge
// coverage
#define IJON_STATE(n) ijon_xor_state(n)

// Names the operation about to be performed, keying the state transition on
// (previous state, current state, action)
#define AFL_STATE_ACTION(a) afl_state_action((uint32_t)(a))

// Declares the input span the harness considers interesting
#define AFL_HOT_REGION(o, l) afl_state_hot((uint32_t)(o), (uint32_t)(l))

// IJON context macro - temporary state change that reverses itself
#define IJON_CTX(x)                                   \
  ({                                                  \
                                                      \
    uint32_t hash = ijon_hashstr(__LINE__, __FILE__); \
    ijon_xor_state(hash);                             \
    __typeof__(x) temp = (x);                         \
    ijon_xor_state(hash);                             \
    temp;                                             \
                                                      \
  })

// Alternative: explicit address version for high-performance cases
#define IJON_MAX_AT(addr, x) ijon_max((addr), (x))
#define IJON_MIN_AT(addr, x) ijon_min((addr), (x))
#define IJON_MAX_UNTIL_AT(addr, x, limit) ijon_max_until((addr), (x), (limit))

#define IJON_MAX_UNTIL(x, limit)                                \
  do {                                                          \
                                                                \
    static uint32_t _ijon_until_loc_cache = 0;                  \
    if (unlikely(_ijon_until_loc_cache == 0)) {                 \
                                                                \
      _ijon_until_loc_cache = ijon_hashstr(__LINE__, __FILE__); \
                                                                \
    }                                                           \
    ijon_max_until(_ijon_until_loc_cache, (x), (limit));        \
                                                                \
  } while (0)

// Helper macro for absolute distance calculation
#define _IJON_ABS_DIST(x, y) ((x) < (y) ? (y) - (x) : (x) - (y))

// IJON bit counting macro - counts leading zeros (position of highest bit)
#define IJON_BITS(x) \
  IJON_SET(ijon_hashint(ijon_hashstack(), ((x) == 0) ? 0 : __builtin_clz(x)))

// IJON distance and comparison macros - incorporate stack context automatically
#define IJON_STRDIST(x, y) \
  IJON_SET(ijon_hashint(ijon_hashstack(), ijon_strdist(x, y)))
#define IJON_DIST(x, y) \
  IJON_SET(ijon_hashint(ijon_hashstack(), _IJON_ABS_DIST(x, y)))
#define IJON_CMP(x, y) \
  IJON_INC(ijon_hashint(ijon_hashstack(), __builtin_popcount((x) ^ (y))))

// Stack-aware IJON macros - incorporate call stack context
// Note: IJON_DIST and IJON_CMP already incorporate stack context automatically
#define IJON_STACK_MAX(x)                                           \
  do {                                                              \
                                                                    \
    static uint32_t _ijon_stack_loc = 0;                            \
    if (unlikely(_ijon_stack_loc == 0)) {                           \
                                                                    \
      _ijon_stack_loc = ijon_hashstr(__LINE__, __FILE__);           \
                                                                    \
    }                                                               \
    ijon_max(ijon_hashint(_ijon_stack_loc, ijon_hashstack()), (x)); \
                                                                    \
  } while (0)

#define IJON_STACK_MIN(x)                                           \
  do {                                                              \
                                                                    \
    static uint32_t _ijon_stack_loc = 0;                            \
    if (unlikely(_ijon_stack_loc == 0)) {                           \
                                                                    \
      _ijon_stack_loc = ijon_hashstr(__LINE__, __FILE__);           \
                                                                    \
    }                                                               \
    ijon_min(ijon_hashint(_ijon_stack_loc, ijon_hashstack()), (x)); \
                                                                    \
  } while (0)

#endif                                              /* _HAVE_AFL_IJON_MIN_H */

