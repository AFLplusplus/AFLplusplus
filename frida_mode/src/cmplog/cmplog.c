#include "frida-gum.h"

#include "debug.h"

#include "util.h"

extern struct cmp_map *__afl_cmp_map;

static GArray *cmplog_ranges = NULL;

static gboolean cmplog_range(const GumRangeDetails *details,
                             gpointer               user_data) {

  UNUSED_PARAMETER(user_data);
  GumMemoryRange range = *details->range;
  g_array_append_val(cmplog_ranges, range);
  return TRUE;

}

static gint cmplog_sort(gconstpointer a, gconstpointer b) {

  return ((GumMemoryRange *)b)->base_address -
         ((GumMemoryRange *)a)->base_address;

}

void cmplog_init(void) {

  if (__afl_cmp_map != NULL) { OKF("CMPLOG mode enabled"); }

  cmplog_ranges = g_array_sized_new(false, false, sizeof(GumMemoryRange), 100);
  gum_process_enumerate_ranges(GUM_PAGE_READ, cmplog_range, NULL);
  g_array_sort(cmplog_ranges, cmplog_sort);

  for (guint i = 0; i < cmplog_ranges->len; i++) {

    GumMemoryRange *range = &g_array_index(cmplog_ranges, GumMemoryRange, i);
    OKF("CMPLOG Range - 0x%016" G_GINT64_MODIFIER "X - 0x%016" G_GINT64_MODIFIER
        "X",
        range->base_address, range->base_address + range->size);

  }

}

static gboolean cmplog_contains(GumAddress inner_base, GumAddress inner_limit,
                                GumAddress outer_base, GumAddress outer_limit) {

  return (inner_base >= outer_base && inner_limit <= outer_limit);

}

gboolean cmplog_is_readable(void *addr, size_t size) {

  if (cmplog_ranges == NULL) FATAL("CMPLOG not initialized");

  GumAddress inner_base = GUM_ADDRESS(addr);
  GumAddress inner_limit = inner_base + size;

  for (guint i = 0; i < cmplog_ranges->len; i++) {

    GumMemoryRange *range = &g_array_index(cmplog_ranges, GumMemoryRange, i);
    GumAddress      outer_base = range->base_address;
    GumAddress      outer_limit = outer_base + range->size;

    if (cmplog_contains(inner_base, inner_limit, outer_base, outer_limit))
      return true;

  }

  return false;

}

