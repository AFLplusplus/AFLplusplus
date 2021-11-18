#include "frida-gumjs.h"

#include "asan.h"
#include "ranges.h"
#include "util.h"

static gboolean asan_enabled = FALSE;
gboolean        asan_initialized = FALSE;

void asan_config(void) {

  if (getenv("AFL_USE_FASAN") != NULL) {

    FOKF("Frida ASAN mode enabled");
    asan_enabled = TRUE;

  } else {

    FOKF("Frida ASAN mode disabled");

  }

}

void asan_init(void) {

  if (asan_enabled) {

    asan_arch_init();
    asan_initialized = TRUE;

  }

}

gboolean asan_exclude_range(const GumRangeDetails *details,
                            gpointer               user_data) {

  UNUSED_PARAMETER(user_data);

  FOKF("Exclude ASAN: 0x%016lx-0x%016lx", details->range->base_address,
       details->range->base_address + details->range->size);

  ranges_add_exclude((GumMemoryRange *)details->range);

}

static gboolean asan_exclude_module(const GumModuleDetails *details,
                                    gpointer                user_data) {

  gchar *    symbol_name = (gchar *)user_data;
  GumAddress address;

  address = gum_module_find_export_by_name(details->name, symbol_name);
  if (address == 0) { return TRUE; }

  gum_process_enumerate_ranges(GUM_PAGE_NO_ACCESS, asan_exclude_range, NULL);

}

void asan_exclude_module_by_symbol(gchar *symbol_name) {

  gum_process_enumerate_modules(asan_exclude_module, "__asan_loadN");

}

