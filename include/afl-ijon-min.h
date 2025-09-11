#ifndef _HAVE_AFL_IJON_MIN_H
#define _HAVE_AFL_IJON_MIN_H

#include "config.h"
#include "types.h"

#define IJON_MAX_INPUT_SIZE (64*1024)


typedef struct {
  char* filename;
  int slot_id;
  size_t len;
} ijon_input_info;

typedef struct {
  u64 max_map[MAP_SIZE_IJON_ENTRIES];
  ijon_input_info* infos[MAP_SIZE_IJON_ENTRIES];
  size_t num_entries;
  size_t num_updates;
  char* max_dir;
  int schedule_prob;

  /* Note: Callback fields removed - no longer needed with atomic file operations */
} ijon_min_state;

/* UNIFIED SHARED MEMORY LAYOUT - STATIC DESIGN
 *
 * shared_data_t overlays the shared memory region directly:
 * [0...MAP_SIZE-1]                    : Coverage bitmap (afl_area)
 * [MAP_SIZE...MAP_SIZE+IJON_SIZE-1]   : IJON max values (afl_max)
 *
 * This eliminates dynamic allocation and provides predictable memory layout.
 */

// Shared memory structure that overlays fsrv->trace_bits directly (≤65k maps only)
typedef struct {
  u8 afl_area[MAP_SIZE];                    // Standard coverage map
  u64 afl_max[MAP_SIZE_IJON_ENTRIES];       // IJON max tracking map
} shared_data_t;

// Compile-time verification that our structure matches the total allocation (≤65k only)
_Static_assert(sizeof(shared_data_t) == MAP_SIZE_TOTAL,
    "shared_data_t size must match MAP_SIZE_TOTAL");

// Dynamic shared memory access structure for >65k maps
typedef struct {
  u8  *coverage_area;      // Points to coverage start
  u64 *ijon_max_area;      // Points to IJON max start (dynamic offset)
  u32  coverage_size;      // Actual coverage map size
  u32  ijon_offset;        // Where IJON data starts
  u8   is_dynamic;         // Flag: 0=fixed layout, 1=dynamic layout
} dynamic_shared_access_t;

/* Function prototypes */
ijon_min_state* new_ijon_min_state(char* max_dir);
u8 ijon_should_schedule(ijon_min_state* self);
ijon_input_info* ijon_get_input(ijon_min_state* self);
void ijon_update_max(ijon_min_state* self, shared_data_t* shared, uint8_t* data, size_t len);
void ijon_store_max_input(ijon_min_state* self, int i, uint8_t* data, size_t len);
void ijon_store_history_if_best(ijon_min_state* self, int i, uint8_t* data, size_t len);
void ijon_store_history_unconditional(ijon_min_state* self, int i, uint8_t* data, size_t len);
void destroy_ijon_min_state(ijon_min_state* self);

/* Dynamic shared memory access functions for >65k maps */
dynamic_shared_access_t* setup_dynamic_shared_access(u8 *trace_bits, u32 map_size);
void cleanup_dynamic_shared_access(dynamic_shared_access_t *access);
shared_data_t* get_legacy_shared_data(u8 *trace_bits, u32 map_size);
void ijon_update_max_dynamic(ijon_min_state* self, dynamic_shared_access_t* shared, uint8_t* data, size_t len);

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
void ijon_push_state(uint32_t x);
void ijon_reset_state(void);

/* Supporting hash functions */
uint64_t ijon_simple_hash(uint64_t x);
uint32_t ijon_hashint(uint32_t old, uint32_t val);
uint32_t ijon_hashstr(uint32_t old, char* val);
uint32_t ijon_hashmem(uint32_t old, char* val, size_t len);

/* Stack hashing functions - cross-platform backtrace support */
uint32_t ijon_hashstack_backtrace(void);
uint32_t ijon_hashstack(void);

/* String and memory distance functions */
uint32_t ijon_strdist(char* a, char* b);
uint32_t ijon_memdist(char* a, char* b, size_t len);

#ifdef __cplusplus
}
#endif

/* IJON max tracking macros */
// Single unified IJON_MAX macro - calls one runtime function
#define IJON_MAX(...) do { \
    static uint32_t _ijon_loc_cache = 0; \
    if (unlikely(_ijon_loc_cache == 0)) { \
        _ijon_loc_cache = ijon_hashstr(__LINE__, __FILE__); \
    } \
    ijon_max_variadic(_ijon_loc_cache, __VA_ARGS__, 0ULL); \
} while(0)

// Single unified IJON_MIN macro - calls one runtime function
#define IJON_MIN(...) do { \
    static uint32_t _ijon_loc_cache = 0; \
    if (unlikely(_ijon_loc_cache == 0)) { \
        _ijon_loc_cache = ijon_hashstr(__LINE__, __FILE__); \
    } \
    ijon_min_variadic(_ijon_loc_cache, __VA_ARGS__, 0ULL); \
} while(0)

// IJON set macro - takes only ONE variable (not variadic like IJON_MAX)
#define IJON_SET(x) do { \
    static uint32_t _ijon_set_loc_cache = 0; \
    if (unlikely(_ijon_set_loc_cache == 0)) { \
        _ijon_set_loc_cache = ijon_hashstr(__LINE__, __FILE__); \
    } \
    ijon_set(_ijon_set_loc_cache, (x)); \
} while(0)

// IJON inc macro - takes only ONE variable and increments coverage counter
#define IJON_INC(x) do { \
    static uint32_t _ijon_inc_loc_cache = 0; \
    if (unlikely(_ijon_inc_loc_cache == 0)) { \
        _ijon_inc_loc_cache = ijon_hashstr(__LINE__, __FILE__); \
    } \
    ijon_inc(_ijon_inc_loc_cache, (x)); \
} while(0)

// IJON state macro - changes global state that affects ALL subsequent edge coverage
#define IJON_STATE(n) ijon_xor_state(n)

// IJON context macro - temporary state change that reverses itself
#define IJON_CTX(x) ({ \
    uint32_t hash = ijon_hashstr(__LINE__, __FILE__); \
    ijon_xor_state(hash); \
    __typeof__(x) temp = (x); \
    ijon_xor_state(hash); \
    temp; \
})

// Alternative: explicit address version for high-performance cases
#define IJON_MAX_AT(addr, x) ijon_max((addr), (x))
#define IJON_MIN_AT(addr, x) ijon_min((addr), (x))

// Helper macro for absolute distance calculation
#define _IJON_ABS_DIST(x,y) ((x)<(y) ? (y)-(x) : (x)-(y))

// IJON bit counting macro - counts leading zeros (position of highest bit)
#define IJON_BITS(x) IJON_SET(ijon_hashint(ijon_hashstack(), ((x)==0) ? 0 : __builtin_clz(x)))

// IJON distance and comparison macros - incorporate stack context automatically
#define IJON_STRDIST(x, y) IJON_SET(ijon_hashint(ijon_hashstack(), ijon_strdist(x, y)))
#define IJON_DIST(x, y) IJON_SET(ijon_hashint(ijon_hashstack(), _IJON_ABS_DIST(x, y)))
#define IJON_CMP(x, y) IJON_INC(ijon_hashint(ijon_hashstack(), __builtin_popcount((x)^(y))))

// Stack-aware IJON macros - incorporate call stack context
// Note: IJON_DIST and IJON_CMP already incorporate stack context automatically
#define IJON_STACK_MAX(x) do { \
    static uint32_t _ijon_stack_loc = 0; \
    if (unlikely(_ijon_stack_loc == 0)) { \
        _ijon_stack_loc = ijon_hashstr(__LINE__, __FILE__); \
    } \
    ijon_max(ijon_hashint(_ijon_stack_loc, ijon_hashstack()), (x)); \
} while(0)
#define IJON_STACK_MIN(x) do { \
    static uint32_t _ijon_stack_loc = 0; \
    if (unlikely(_ijon_stack_loc == 0)) { \
        _ijon_stack_loc = ijon_hashstr(__LINE__, __FILE__); \
    } \
    ijon_min(ijon_hashint(_ijon_stack_loc, ijon_hashstack()), (x)); \
} while(0)

#endif /* _HAVE_AFL_IJON_MIN_H */