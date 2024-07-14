
#include "entry.h"
#include "instrument.h"
#include "js.h"
#include "output.h"
#include "persistent.h"
#include "prefetch.h"
#include "ranges.h"
#include "seccomp.h"
#include "stalker.h"
#include "stats.h"
#include "util.h"

typedef uint8_t u8;

extern void __afl_set_persistent_mode(u8 mode);

__attribute__((visibility("default"))) void js_api_done() {

  js_done = TRUE;

}

__attribute__((visibility("default"))) void js_api_error(char *msg) {

  FFATAL("%s", msg);

}

__attribute__((visibility("default"))) void js_api_set_entrypoint(
    void *address) {

  if (address == NULL) {

    js_api_error("js_api_set_entrypoint called with NULL");

  }

  entry_point = GPOINTER_TO_SIZE(address);

}

__attribute__((visibility("default"))) void js_api_set_persistent_address(
    void *address) {

  if (address == NULL) {

    js_api_error("js_api_set_persistent_address called with NULL");

  }

  persistent_start = GPOINTER_TO_SIZE(address);

  __afl_set_persistent_mode(1);

}

__attribute__((visibility("default"))) void js_api_set_persistent_return(
    void *address) {

  if (address == NULL) {

    js_api_error("js_api_set_persistent_return called with NULL");

  }

  persistent_ret = GPOINTER_TO_SIZE(address);

}

__attribute__((visibility("default"))) void js_api_set_persistent_count(
    uint64_t count) {

  persistent_count = count;

}

__attribute__((visibility("default"))) void js_api_set_persistent_debug() {

  persistent_debug = TRUE;

}

__attribute__((visibility("default"))) void js_api_set_debug_maps() {

  ranges_debug_maps = TRUE;

}

__attribute__((visibility("default"))) void js_api_add_include_range(
    void *address, gsize size) {

  GumMemoryRange range = {.base_address = GUM_ADDRESS(address), .size = size};
  ranges_add_include(&range);

}

__attribute__((visibility("default"))) void js_api_add_exclude_range(
    void *address, gsize size) {

  GumMemoryRange range = {.base_address = GUM_ADDRESS(address), .size = size};
  ranges_add_exclude(&range);

}

__attribute__((visibility("default"))) void js_api_set_instrument_jit() {

  ranges_inst_jit = TRUE;

}

__attribute__((visibility("default"))) void js_api_set_instrument_libraries() {

  ranges_inst_libs = TRUE;

}

__attribute__((visibility("default"))) void
js_api_set_instrument_coverage_absolute(void) {

  instrument_coverage_absolute = true;

}

__attribute__((visibility("default"))) void js_api_set_instrument_coverage_file(
    char *path) {

  instrument_coverage_filename = g_strdup(path);

}

__attribute__((visibility("default"))) void js_api_set_instrument_debug_file(
    char *path) {

  instrument_debug_filename = g_strdup(path);

}

__attribute__((visibility("default"))) void js_api_set_prefetch_disable(void) {

  prefetch_enable = FALSE;

}

__attribute__((visibility("default"))) void
js_api_set_prefetch_backpatch_disable(void) {

  prefetch_backpatch = FALSE;

}

__attribute__((visibility("default"))) void js_api_set_instrument_instructions(
    void) {

  instrument_coverage_insn = TRUE;

}

__attribute__((visibility("default"))) void
js_api_set_instrument_no_dynamic_load(void) {

  ranges_inst_dynamic_load = FALSE;

}

__attribute__((visibility("default"))) void js_api_set_instrument_no_optimize(
    void) {

  instrument_optimize = FALSE;

}

__attribute__((visibility("default"))) void js_api_set_instrument_regs_file(
    char *path) {

  instrument_regs_filename = g_strdup(path);

}

__attribute__((visibility("default"))) void js_api_set_instrument_seed(
    guint64 seed) {

  instrument_use_fixed_seed = TRUE;
  instrument_fixed_seed = seed;

}

__attribute__((visibility("default"))) void js_api_set_instrument_trace(void) {

  instrument_tracing = TRUE;

}

__attribute__((visibility("default"))) void js_api_set_instrument_trace_unique(
    void) {

  instrument_unique = TRUE;

}

__attribute__((visibility("default"))) void
js_api_set_instrument_unstable_coverage_file(char *path) {

  instrument_coverage_unstable_filename = g_strdup(path);

}

__attribute__((visibility("default"))) void js_api_set_seccomp_file(
    char *file) {

  seccomp_filename = g_strdup(file);

}

__attribute__((visibility("default"))) void js_api_set_stdout(char *file) {

  output_stdout = g_strdup(file);

}

__attribute__((visibility("default"))) void js_api_set_stderr(char *file) {

  output_stderr = g_strdup(file);

}

__attribute__((visibility("default"))) void js_api_set_stats_file(char *file) {

  stats_filename = g_strdup(file);

}

__attribute__((visibility("default"))) void js_api_set_stats_interval(
    uint64_t interval) {

  stats_interval = interval;

}

__attribute__((visibility("default"))) void js_api_set_persistent_hook(
    void *address) {

  if (address == NULL) {

    js_api_error("js_api_set_persistent_hook called with NULL");

  }

  persistent_hook = address;

}

__attribute__((visibility("default"))) void js_api_set_stalker_callback(
    const js_api_stalker_callback_t callback) {

  js_user_callback = callback;

}

__attribute__((visibility("default"))) void js_api_set_stalker_ic_entries(
    guint val) {

  stalker_ic_entries = val;

}

__attribute__((visibility("default"))) void js_api_set_traceable(void) {

  traceable = TRUE;

}

__attribute__((visibility("default"))) void js_api_set_backpatch_disable(void) {

  backpatch_enable = FALSE;

}

__attribute__((visibility("default"))) void js_api_set_stalker_adjacent_blocks(
    guint val) {

  stalker_adjacent_blocks = val;

}

__attribute__((visibility("default"))) void js_api_set_cache_disable(void) {

  instrument_cache_enabled = FALSE;

}

__attribute__((visibility("default"))) void js_api_set_instrument_cache_size(
    gsize size) {

  instrument_cache_size = size;

}

__attribute__((visibility("default"))) void
js_api_set_instrument_suppress_disable(void) {

  instrument_suppress = false;

}

__attribute__((visibility("default"))) void js_api_set_js_main_hook(
    const js_main_hook_t hook) {

  js_main_hook = hook;

}

__attribute__((visibility("default"))) void js_api_set_verbose(void) {

  util_verbose = TRUE;

}

__attribute__((visibility("default"))) void js_api_ijon_set(uint32_t edge) {

  ijon_set(edge);

}

