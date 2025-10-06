#ifndef _HAVE_AFL_IJON_MIN_H
#define _HAVE_AFL_IJON_MIN_H

#include "config.h"
#include "types.h"

#define IJON_MAX_INPUT_SIZE (64 * 1024)

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
  int              schedule_prob;

} ijon_min_state;

/* UNIFIED SHARED MEMORY LAYOUT - DYNAMIC DESIGN
 *
 * Dynamic shared memory layout for all map sizes:
 * [0...coverage_size-1]                           : Coverage bitmap (variable
 * size) [coverage_size...coverage_size+IJON_MAP-1]      : IJON set/inc area
 * (65536 bytes) [coverage_size+IJON_MAP...coverage_size+IJON_MAP+IJON_BYTES-1]
 * : IJON max area (4096 bytes)
 *
 * Where coverage_size = map_size - MAP_SIZE_IJON_MAP - MAP_SIZE_IJON_BYTES
 *
 * OFFSET CALCULATIONS (ALIGNED):
 * Target IJON offset: __afl_map_size - 2*MAP_SIZE_IJON_BYTES -
 * MAP_SIZE_IJON_MAP Fuzzer IJON offset: map_size - MAP_SIZE_IJON_BYTES -
 * MAP_SIZE_IJON_MAP
 *
 * Both calculations produce identical results:
 * - Target __afl_map_size includes full IJON areas (coverage + IJON_MAP +
 * IJON_BYTES)
 * - Fuzzer map_size has MAP_SIZE_IJON_BYTES subtracted by
 * afl->fsrv.real_map_size -= MAP_SIZE_IJON_BYTES
 * - Target compensates by subtracting extra MAP_SIZE_IJON_BYTES in calculation
 */

// Dynamic shared memory access structure for all map sizes
typedef struct {

  u64 *ijon_max_area;  // Points to IJON max start (dynamic offset)
  u32  ijon_offset;    // Where IJON data starts

} dynamic_shared_access_t;

/* Function prototypes */
ijon_min_state  *new_ijon_min_state(char *max_dir);
u8               ijon_should_schedule(ijon_min_state *self);
ijon_input_info *ijon_get_input(ijon_min_state *self);
void ijon_store_max_input(ijon_min_state *self, int i, uint8_t *data,
                          size_t len);
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
void ijon_max_variadic(uint32_t addr, ...);
void ijon_min_variadic(uint32_t addr, ...);
void ijon_set(uint32_t addr, uint32_t val);
void ijon_inc(uint32_t addr, uint32_t val);

/* IJON state management functions */
void ijon_xor_state(uint32_t val);
void ijon_reset_state(void);

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

