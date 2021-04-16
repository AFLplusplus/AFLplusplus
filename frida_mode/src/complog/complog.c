#include "frida-gum.h"

#include "debug.h"
#include "cmplog.h"

extern struct cmp_map *__afl_cmp_map;

static GArray *complog_ranges = NULL;

static gboolean complog_range(const GumRangeDetails *details,
                              gpointer               user_data) {

  GumMemoryRange range = *details->range;
  g_array_append_val(complog_ranges, range);

}

gint complog_sort(gconstpointer a, gconstpointer b) {

  return ((GumMemoryRange *)b)->base_address -
         ((GumMemoryRange *)a)->base_address;

}

void complog_init() {

  if (__afl_cmp_map != NULL) { OKF("CompLog mode enabled"); }

  complog_ranges = g_array_sized_new(false, false, sizeof(GumMemoryRange), 100);
  gum_process_enumerate_ranges(GUM_PAGE_READ, complog_range, NULL);
  g_array_sort(complog_ranges, complog_sort);

  for (guint i = 0; i < complog_ranges->len; i++) {

    GumMemoryRange *range = &g_array_index(complog_ranges, GumMemoryRange, i);
    OKF("CompLog Range - 0x%016lX - 0x%016lX", range->base_address,
        range->base_address + range->size);

  }

}

static gboolean complog_overlaps(GumAddress base1, GumAddress limit1,
                                 GumAddress base2, GumAddress limit2) {

  if (base1 < base2) return false;
  if (limit1 > limit2) return false;
  return true;

}

gboolean complog_is_readable(void *addr, size_t size) {

  if (complog_ranges == NULL) FATAL("CompLog not initialized");

  GumAddress cmp_base = GUM_ADDRESS(addr);
  GumAddress cmp_limit = cmp_base + size;

  for (guint i = 0; i < complog_ranges->len; i++) {

    GumMemoryRange *range = &g_array_index(complog_ranges, GumMemoryRange, i);
    GumAddress      base = range->base_address;
    GumAddress      limit = base + range->size;

    if (complog_overlaps(cmp_base, cmp_limit, base, limit)) return true;

  }

  return false;

}

