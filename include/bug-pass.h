/*
   american fuzzy lop++ - LLVM bug-finding pass shared definitions
   ---------------------------------------------------------------

   Originally based on AFL by Michal "lcamtuf" Zalewski.
   Now maintained by the AFLplusplus project.

   Copyright 2024-2026 AFLplusplus Project. All rights reserved.

   This file is part of AFL++ and, unlike the original Apache-2.0 source files,
   is licensed under the GNU Affero General Public License as published by the
   Free Software Foundation, either version 3 of the License, or (at your
   option) any later version.

   AFL++ is distributed in the hope that it will be useful, but WITHOUT ANY
   WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
   FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
   details: https://www.gnu.org/licenses/agpl-3.0.html

   A commercial license is available for organizations that cannot use the
   AGPL; see LICENSE.COMMERCIAL.

   SPDX-License-Identifier: AGPL-3.0-or-later

 */

// include/bug-pass.h
#ifndef AFL_BUG_PASS_H
#define AFL_BUG_PASS_H

#include <stdint.h>

// Env vars selecting modes. Any of these enables loading the pass.
#define AFL_BUG_ENV_ALL "AFL_LLVM_BUG"
#define AFL_BUG_ENV_SCALAR "AFL_LLVM_BUG_SCALAR"
#define AFL_BUG_ENV_BUDGET "AFL_LLVM_BUG_BUDGET"
#define AFL_BUG_ENV_SIZEFILL "AFL_LLVM_BUG_SIZEFILL"
#define AFL_BUG_ENV_ALLOCSIZE "AFL_LLVM_BUG_ALLOCSIZE"
#define AFL_BUG_ENV_ALLOCSIZE_FUNCS "AFL_LLVM_BUG_ALLOCSIZE_FUNCS"
#define AFL_BUG_ENV_ALLOCSIZE_FREE_FUNCS "AFL_LLVM_BUG_ALLOCSIZE_FREE_FUNCS"
#define AFL_BUG_ENV_ALLOCSIZE_DERIVE "AFL_LLVM_BUG_ALLOCSIZE_DERIVE"
// Stack-alloca tracking under ALLOCSIZE. On by default when ALLOCSIZE is
// enabled; users hitting pathological targets (deep recursion, many tiny
// locals) can opt out with AFL_LLVM_BUG_ALLOCSIZE_STACK=0.
#define AFL_BUG_ENV_ALLOCSIZE_STACK "AFL_LLVM_BUG_ALLOCSIZE_STACK"
#define AFL_BUG_ENV_SLACK "AFL_LLVM_BUG_SLACK"
// Optional opt-in: restricts SCALAR's arithmetic-site instrumentation to
// BinaryOperators that flow into a memory-size sink (allocator size args,
// GEP indices, memcpy/memset lengths). Off by default — turning it on
// silences pure-compute accumulators like hash-builders or non-memory
// counters, which is exactly the libwebp-style signal SCALAR otherwise
// captures. Use only when you want to cut SCALAR map pollution on very
// large targets and accept the loss of pure-compute coverage.
#define AFL_BUG_ENV_SCALAR_SLICE "AFL_LLVM_BUG_SCALAR_SLICE"
// When set, every mode prints per-function instrumentation counts
// after its module pass (in addition to the existing aggregate
// one-liner).  Useful for auditing "is mode X actually firing in
// my function Y?" without parsing the post-pass IR by hand.
#define AFL_BUG_ENV_DUMP_SUMMARY "AFL_LLVM_BUG_DUMP_SUMMARY"

// Number of u32 slots in the bug map (max-value coverage channel).
// Must be a power of two. Sized like IJON (512) but wider because we
// instrument many arithmetic sites.
//
// Canonical definition lives in include/config.h. We include it here so
// instrumentation pass code (which doesn't always pull config.h) sees the
// same value as the fuzzer and runtime.
#include "config.h"
#ifndef MAP_SIZE_BUG_ENTRIES
  #error "include/config.h must define MAP_SIZE_BUG_ENTRIES"
#endif
#ifndef MAP_SIZE_BUG
  #define MAP_SIZE_BUG MAP_SIZE_BUG_BYTES
#endif

#define AFL_BUG_MODE_SCALAR (1U << 0)
#define AFL_BUG_MODE_BUDGET (1U << 1)
#define AFL_BUG_MODE_SIZEFILL (1U << 2)
#define AFL_BUG_MODE_ALLOCSIZE (1U << 3)
#define AFL_BUG_MODE_SLACK (1U << 4)
#define AFL_BUG_MODE_DERIVE (1U << 5)

// Runtime hook signatures (called from instrumented IR).
#ifdef __cplusplus
extern "C" {

#endif

// SCALAR: update bug_map[id] = max(bug_map[id], val_log2_bucket).
void __afl_bug_scalar_max(uint32_t id, uint64_t val);
// SCALAR: per-loop iteration counter. Pass-emitted code maintains the
// counter as a header PHI and flushes the final value once per loop run.
void __afl_bug_loop_iter_flush(uint32_t id, uint32_t local_count);

// BUDGET: write-set tracking around `ptr += func()`.
void __afl_bug_ws_begin(const void *ptr_before);
void __afl_bug_ws_store(const void *addr, uint32_t size);
void __afl_bug_ws_check_budget(const void *ptr_before, uint64_t ret_size);

// SIZEFILL: post-call check for size-or-fill idioms. Uses dedicated
// __afl_bug_sf_* state so BUDGET and SIZEFILL don't share a base/max.
//
// sf_begin now takes the caller-buffer size so the runtime can range-
// gate every sf_store as `addr < base + size`. Without the bound, an
// unrelated higher-address store inside the callee would inflate the
// tracked max_off and trip a spurious SIZEFILL abort.
void __afl_bug_sf_begin(const void *ptr_arg, uint64_t caller_buf_size);
void __afl_bug_sf_store(const void *addr, uint32_t size);
void __afl_bug_sizefill_check(const void *ptr_arg, uint64_t ret_size,
                              uint64_t caller_buf_size);

// SLACK: per-icmp |op0 - op1| feedback. Semantically a MIN-channel (smaller
// slack = tighter match = more interesting), but mapped onto the shared
// MAX-based __afl_bug_map via inverse-bucket so it can coexist with scalar /
// loop hooks without clobbering. Slot is hashed with a SLACK-specific salt
// to keep collisions with scalar/loop IDs at the noise floor.
void __afl_bug_slack_min(uint32_t id, uint64_t slack);

// ALLOCSIZE: allocation tracking and per-store oracle.
// All __afl_track_* return the underlying allocator's result, side-effect:
// register the new region in the runtime shadow table.
void *__afl_track_malloc(uint64_t size, uint32_t alloc_site_id);
void *__afl_track_calloc(uint64_t nmemb, uint64_t size, uint32_t alloc_site_id);
void *__afl_track_realloc(void *ptr, uint64_t size, uint32_t alloc_site_id);
void *__afl_track_reallocarray(void *ptr, uint64_t nmemb, uint64_t size,
                               uint32_t alloc_site_id);
int __afl_track_posix_memalign(void **memptr, uint64_t alignment, uint64_t size,
                               uint32_t alloc_site_id);
// C++17 aligned operator new replacement — preserves the alignment
// contract by routing through posix_memalign rather than plain malloc.
void *__afl_track_aligned_alloc(uint64_t size, uint64_t alignment,
                                uint32_t alloc_site_id);
// strdup / strndup return a fresh malloc'd buffer the runtime must
// register so subsequent stores against the result are oracle-checked.
char *__afl_track_strdup(const char *s, uint32_t alloc_site_id);
char *__afl_track_strndup(const char *s, uint64_t n, uint32_t alloc_site_id);
void  __afl_track_free(void *ptr);

// Manual registration entrypoint for custom allocators that the pass
// can't (or shouldn't) rewrite — e.g., if a user wants to wrap them by
// hand. The pass calls this for any function name listed in
// AFL_LLVM_BUG_ALLOCSIZE_FUNCS.
void __afl_alloc_register(void *ptr, uint64_t size, uint32_t alloc_site_id);
void __afl_alloc_unregister(void *ptr);

// Per-store oracle. Takes the store address and the width of the store in
// bytes; runtime decides whether the address is tracked (cheap shadow
// lookup) and uses `addr + size` as the post-write end so a 4-byte store at
// the last byte of a buffer is correctly classified as OOB.
void __afl_alloc_oracle(const void *ptr, uint32_t store_size);

// Wide-length variant of the per-store oracle. memcpy/memmove/memset
// emit i64 lengths in IR; truncating to i32 would hide overflow bugs
// where a computed length wraps but a tiny i32 value still passes the
// shadow check. Same shadow lookup, same `addr + size` end.
void __afl_alloc_oracle_n(const void *ptr, uint64_t store_size);

// Type-confusion smell. The runtime remembers the first (element-size,
// alignment) pair observed at each tracked allocation; later stores
// with a different element-size are reported on stderr (informational,
// not fatal). Useful for catching realloc-with-different-type and
// C++ type-punning patterns.
void __afl_alloc_oracle_typed(const void *ptr, uint32_t elem_size,
                              uint32_t alignment);

// Initialized to 0, set to 1 by runtime if any mode is active. Pass-emitted
// hooks short-circuit on this.
extern uint8_t  __afl_bug_active;
extern uint32_t __afl_bug_mode;

// ALLOCSIZE record table layout. Exposed so test programs and external
// inspection tools see the canonical struct and don't drift from the
// runtime's actual layout when fields are added. The runtime defines
// `__afl_alloc_records[MAP_SIZE_ALLOCRECORDS]`; consumers index it with
// indices read from the live shadow.
typedef struct AllocSizeRecord {

  uintptr_t base;
  uint64_t  size;
  uint32_t  alloc_site_id;
  uint8_t   in_use;
  uint64_t  max_observed_off;              /* tracked by __afl_alloc_oracle */
  uint8_t   derive_logged;                     /* set after size-derive log */
  /* Type-confusion fingerprint (one-shot warning per allocation). */
  uint32_t first_elem_size;
  uint32_t first_elem_align;
  uint8_t  type_warned;

} AllocSizeRecord;

#ifdef __cplusplus

}

#endif

#endif  // AFL_BUG_PASS_H

