#include "debug.h"

#include "entry.h"
#include "instrument.h"
#include "js.h"
#include "output.h"
#include "persistent.h"
#include "prefetch.h"
#include "ranges.h"
#include "stats.h"
#include "util.h"

void js_api_done() {

  js_done = TRUE;

}

void js_api_error(char *msg) {

  FATAL("%s", msg);

}

void js_api_set_entrypoint(void *address) {

  entry_point = GPOINTER_TO_SIZE(address);

}

void js_api_set_persistent_address(void *address) {

  persistent_start = GPOINTER_TO_SIZE(address);

}

void js_api_set_persistent_return(void *address) {

  persistent_ret = GPOINTER_TO_SIZE(address);

}

void js_api_set_persistent_count(uint64_t count) {

  persistent_count = count;

}

void js_api_set_persistent_debug() {

  persistent_debug = TRUE;

}

void js_api_set_debug_maps() {

  ranges_debug_maps = TRUE;

}

void js_api_add_include_range(void *address, gsize size) {

  GumMemoryRange range = {.base_address = GUM_ADDRESS(address), .size = size};
  ranges_add_include(&range);

}

void js_api_add_exclude_range(void *address, gsize size) {

  GumMemoryRange range = {.base_address = GUM_ADDRESS(address), .size = size};
  ranges_add_exclude(&range);

}

void js_api_set_instrument_libraries() {

  ranges_inst_libs = TRUE;

}

void js_api_set_instrument_debug_file(char *path) {

  instrument_debug_filename = g_strdup(path);

}

void js_api_set_prefetch_disable(void) {

  prefetch_enable = FALSE;

}

void js_api_set_instrument_no_optimize(void) {

  instrument_optimize = FALSE;

}

void js_api_set_instrument_trace(void) {

  instrument_tracing = TRUE;

}

void js_api_set_instrument_trace_unique(void) {

  instrument_unique = TRUE;

}

void js_api_set_stdout(char *file) {

  output_stdout = g_strdup(file);

}

void js_api_set_stderr(char *file) {

  output_stderr = g_strdup(file);

}

void js_api_set_stats_file(char *file) {

  stats_filename = g_strdup(file);

}

void js_api_set_stats_interval(uint64_t interval) {

  stats_interval = interval;

}

void js_api_set_stats_transitions() {

  stats_transitions = TRUE;

}

void js_api_set_persistent_hook(void *address) {

  persistent_hook = address;

}

void js_api_set_stalker_callback(const js_api_stalker_callback_t callback) {

  js_user_callback = callback;

}

