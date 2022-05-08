#include "intercept.h"
#include "module.h"
#include "util.h"

#if defined(__linux__)
  #include <dlfcn.h>
  #include <link.h>
#endif

static guint    page_size = 0;
static gboolean handle_dlclose = FALSE;

void module_config(void) {

#if defined(__linux__)
  handle_dlclose = (getenv("AFL_FRIDA_NO_MODULE") == NULL);
#else
  FWARNF("AFL_FRIDA_MODULE not supported");
#endif

}

typedef struct {

  GumMemoryRange    range;
  GumPageProtection protection;
  GumFileMapping    file;

} gum_range_t;

gboolean found_range(const GumRangeDetails *details, gpointer user_data) {

  gum_range_t range = {0};
  GArray *    ranges = (GArray *)user_data;

  range.range = *details->range;
  range.protection = details->protection;
  if (details->file != NULL) { range.file = *details->file; }

  g_array_append_val(ranges, range);
  return FALSE;

}

#if defined(__linux__) && !defined(__ANDROID__)
static int on_dlclose(void *handle) {

  GArray *         ranges = NULL;
  struct link_map *lm = NULL;
  gum_range_t *    range = NULL;
  GumAddress       base;
  GumAddress       limit;
  gpointer         mem;

  if (dlinfo(handle, RTLD_DI_LINKMAP, &lm) < 0) {

    FFATAL("Failed to dlinfo: %s", dlerror());

  }

  FVERBOSE("on_dlclose: %s", lm->l_name);

  ranges = g_array_new(FALSE, TRUE, sizeof(gum_range_t));
  gum_module_enumerate_ranges(lm->l_name, GUM_PAGE_EXECUTE, found_range,
                              ranges);

  int ret = dlclose(handle);
  if (ret != 0) {

    FWARNF("dlclose returned: %d (%s)", ret, dlerror());
    return ret;

  }

  for (guint i = 0; i < ranges->len; i++) {

    range = &g_array_index(ranges, gum_range_t, i);
    base = range->range.base_address;
    limit = base + range->range.size;
    FVERBOSE("Reserving range: 0x%016lx, 0x%016lX", base, limit);
    mem = gum_memory_allocate(GSIZE_TO_POINTER(base), range->range.size,
                              page_size, GUM_PAGE_NO_ACCESS);
    if (mem == NULL) { FATAL("Failed to allocate %p (%d)", mem, errno); }

  }

  g_array_free(ranges, TRUE);
  return 0;

}

#endif

void module_init(void) {

  FOKF(cBLU "Module" cRST " - " cYEL " [%c]", handle_dlclose ? 'X' : ' ');

#if defined(__linux__) && !defined(__ANDROID__)
  if (!handle_dlclose) { return; }

  page_size = gum_query_page_size();
  intercept_hook(dlclose, on_dlclose, NULL);
#endif

}

