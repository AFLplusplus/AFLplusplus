// include/bug-pass.h
#ifndef AFL_BUG_PASS_H
#define AFL_BUG_PASS_H

#include <stdint.h>

// Env vars selecting modes. Any of these enables loading the pass.
#define AFL_BUG_ENV_ALL     "AFL_LLVM_BUG"
#define AFL_BUG_ENV_SCALAR  "AFL_LLVM_BUG_SCALAR"
#define AFL_BUG_ENV_BUDGET  "AFL_LLVM_BUG_BUDGET"
#define AFL_BUG_ENV_SIZEFILL "AFL_LLVM_BUG_SIZEFILL"
#define AFL_BUG_ENV_ALLOCSIZE        "AFL_LLVM_BUG_ALLOCSIZE"
#define AFL_BUG_ENV_ALLOCSIZE_FUNCS  "AFL_LLVM_BUG_ALLOCSIZE_FUNCS"
#define AFL_BUG_ENV_ALLOCSIZE_DERIVE "AFL_LLVM_BUG_ALLOCSIZE_DERIVE"

// Number of u32 slots in the bug map (max-value coverage channel).
// Must be a power of two. Sized like IJON (512) but wider because we
// instrument many arithmetic sites.
#define MAP_SIZE_BUG_ENTRIES (1U << 14)              // 16384 slots
#define MAP_SIZE_BUG (MAP_SIZE_BUG_ENTRIES * sizeof(uint32_t))

// Runtime hook signatures (called from instrumented IR).
#ifdef __cplusplus
extern "C" {
#endif

// SCALAR: update bug_map[id] = max(bug_map[id], val_log2_bucket).
void __afl_bug_scalar_max(uint32_t id, uint64_t val);
// SCALAR: loop iteration counter (called once per loop header, finalized on
// function exit).
void __afl_bug_loop_iter_inc(uint32_t id);
void __afl_bug_loop_iter_flush(uint32_t id, uint32_t local_count);

// BUDGET: write-set tracking around `ptr += func()`.
void __afl_bug_ws_begin(const void *ptr_before);
void __afl_bug_ws_store(const void *addr, uint32_t size);
void __afl_bug_ws_check_budget(const void *ptr_before, uint64_t ret_size);

// SIZEFILL: post-call check for size-or-fill idioms.
void __afl_bug_sizefill_check(const void *ptr_arg, uint64_t ret_size,
                              uint64_t caller_buf_size);

// ALLOCSIZE: allocation tracking and per-store oracle.
// All __afl_track_* return the underlying allocator's result, side-effect:
// register the new region in the runtime shadow table.
void *__afl_track_malloc(uint64_t size, uint32_t alloc_site_id);
void *__afl_track_calloc(uint64_t nmemb, uint64_t size,
                         uint32_t alloc_site_id);
void *__afl_track_realloc(void *ptr, uint64_t size, uint32_t alloc_site_id);
int   __afl_track_posix_memalign(void **memptr, uint64_t alignment,
                                 uint64_t size, uint32_t alloc_site_id);
void  __afl_track_free(void *ptr);

// Manual registration entrypoint for custom allocators that the pass
// can't (or shouldn't) rewrite — e.g., if a user wants to wrap them by
// hand. The pass calls this for any function name listed in
// AFL_LLVM_BUG_ALLOCSIZE_FUNCS.
void  __afl_alloc_register(void *ptr, uint64_t size, uint32_t alloc_site_id);
void  __afl_alloc_unregister(void *ptr);

// Per-store oracle. Takes a single pointer; runtime decides whether
// the address is tracked (cheap shadow lookup) and emits feedback.
void  __afl_alloc_oracle(const void *ptr);

// Initialized to 0, set to 1 by runtime if any mode is active. Pass-emitted
// hooks short-circuit on this.
extern uint8_t __afl_bug_active;

#ifdef __cplusplus
}
#endif

#endif  // AFL_BUG_PASS_H
