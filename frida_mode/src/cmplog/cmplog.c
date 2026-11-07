#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "frida-gumjs.h"

#include "util.h"

#if defined(__APPLE__)
  #include <mach/mach.h>
  #include <mach/vm_map.h>
#endif

#define DEFAULT_MMAP_MIN_ADDR (32UL << 10)
#define MAX_MEMFD_SIZE (64UL << 10)

extern struct cmp_map *__afl_cmp_map;
static GArray         *cmplog_ranges = NULL;
static GHashTable     *hash_yes = NULL;
static GHashTable     *hash_no = NULL;

static long page_size = 0;
static long page_offset_mask = 0;
static long page_mask = 0;

static gboolean cmplog_range(const GumRangeDetails *details,
                             gpointer               user_data) {

  GArray        *cmplog_ranges = (GArray *)user_data;
  GumMemoryRange range = *details->range;
  g_array_append_val(cmplog_ranges, range);
  return TRUE;

}

static gint cmplog_sort(gconstpointer a, gconstpointer b) {

  GumMemoryRange *ra = (GumMemoryRange *)a;
  GumMemoryRange *rb = (GumMemoryRange *)b;

  if (ra->base_address < rb->base_address) {

    return -1;

  } else if (ra->base_address > rb->base_address) {

    return 1;

  } else {

    return 0;

  }

}

static void cmplog_get_ranges(void) {

  FVERBOSE("CMPLOG - Collecting ranges");

  cmplog_ranges = g_array_sized_new(false, false, sizeof(GumMemoryRange), 100);
  gum_process_enumerate_ranges(GUM_PAGE_READ, cmplog_range, cmplog_ranges);
  g_array_sort(cmplog_ranges, cmplog_sort);

}

void cmplog_config(void) {

}

void cmplog_init(void) {

  FOKF(cBLU "Instrumentation" cRST " - " cGRN "cmplog:" cYEL " [%c]",
       __afl_cmp_map == NULL ? ' ' : 'X');

  if (__afl_cmp_map == NULL) { return; }

  cmplog_get_ranges();

  FVERBOSE("Cmplog Ranges");

  for (guint i = 0; i < cmplog_ranges->len; i++) {

    GumMemoryRange *range = &g_array_index(cmplog_ranges, GumMemoryRange, i);
    FVERBOSE("\t%3u: 0x%016" G_GINT64_MODIFIER "X - 0x%016" G_GINT64_MODIFIER
             "X",
             i, range->base_address, range->base_address + range->size);

  }

  page_size = sysconf(_SC_PAGE_SIZE);
  page_offset_mask = page_size - 1;
  page_mask = ~(page_offset_mask);

  hash_yes = g_hash_table_new(g_direct_hash, g_direct_equal);
  if (hash_yes == NULL) {

    FFATAL("Failed to g_hash_table_new, errno: %d", errno);

  }

  hash_no = g_hash_table_new(g_direct_hash, g_direct_equal);
  if (hash_no == NULL) {

    FFATAL("Failed to g_hash_table_new, errno: %d", errno);

  }

}

static gboolean cmplog_contains(GumAddress inner_base, GumAddress inner_limit,
                                GumAddress outer_base, GumAddress outer_limit) {

  return (inner_base >= outer_base && inner_limit <= outer_limit);

}

gboolean cmplog_test_addr(guint64 addr, size_t size) {

  if (g_hash_table_contains(hash_yes, GSIZE_TO_POINTER(addr))) { return true; }
  if (g_hash_table_contains(hash_no, GSIZE_TO_POINTER(addr))) { return false; }

  void  *page_addr = GSIZE_TO_POINTER(addr & page_mask);
  size_t page_offset = addr & page_offset_mask;

  /* If it spans a page, then bail */
  if (page_size - page_offset < size) { return false; }

  /*
   * Our address map can change (e.g. stack growth), use msync as a fallback to
   * validate our address.
   */
  if (msync(page_addr, page_offset + size, MS_ASYNC) < 0) {

    if (!g_hash_table_add(hash_no, GSIZE_TO_POINTER(addr))) {

      FFATAL("Failed - g_hash_table_add");

    }

    return false;

  } else {

    if (!g_hash_table_add(hash_yes, GSIZE_TO_POINTER(addr))) {

      FFATAL("Failed - g_hash_table_add");

    }

    return true;

  }

}

#if defined(__APPLE__)
static gboolean cmplog_darwin_readable(guint64 addr, size_t size) {

  guint64 end = addr + size;
  guint64 cursor = addr;

  while (cursor < end) {

    /* The shared cache region is a submap whose top-level entry reports read
     * access for unmapped holes inside it; descend to the leaf mapping. */
    vm_address_t                    region;
    vm_size_t                       region_size;
    vm_region_submap_info_data_64_t info;
    natural_t                       depth = 0;
    kern_return_t                   kr;

    for (;;) {

      mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
      region = (vm_address_t)cursor;
      region_size = 0;
      kr = vm_region_recurse_64(mach_task_self(), &region, &region_size, &depth,
                                (vm_region_recurse_info_t)&info, &count);
      if (kr != KERN_SUCCESS || region > cursor || !info.is_submap) break;
      depth++;

    }

    /* vm_region_recurse_64 returns the next region when cursor is unmapped. */
    if (kr != KERN_SUCCESS || region > cursor ||
        (info.protection & VM_PROT_READ) == 0) {

      return false;

    }

    cursor = region + region_size;

  }

  return true;

}

#endif

gboolean cmplog_is_readable(guint64 addr, size_t size) {

  if (cmplog_ranges == NULL) FFATAL("CMPLOG not initialized");

  /*
   * The Linux kernel prevents mmap from allocating from the very bottom of the
   * address space to mitigate NULL pointer dereference attacks. The exact size
   * is set by sysctl by setting mmap_min_addr and 64k is suggested on most
   * platforms with 32k on ARM systems. We therefore fail fast if the address
   * is lower than this. This should avoid some overhead when functions are
   * called where one of the parameters is a size, or a some other small value.
   */
  if (addr < DEFAULT_MMAP_MIN_ADDR) { return false; }

  /* Check our address/length don't wrap around */
  if (SIZE_MAX - addr < size) { return false; }

#if defined(__APPLE__)
  /*
   * Darwin's msync() succeeds on mapped but unreadable pages (guard pages,
   * PROT_NONE reservations), and the start-up range list and per-address
   * caches go stale when the target maps and frees large buffers inside a
   * persistent loop.  Either way an integer argument that happens to fall in
   * such a page was dereferenced and killed the target with SIGBUS.  Ask the
   * kernel for the current protection of every page instead, uncached.
   */
  return cmplog_darwin_readable(addr, size);
#endif

  GumAddress inner_base = addr;
  GumAddress inner_limit = inner_base + size;

  for (guint i = 0; i < cmplog_ranges->len; i++) {

    GumMemoryRange *range = &g_array_index(cmplog_ranges, GumMemoryRange, i);

    GumAddress outer_base = range->base_address;
    GumAddress outer_limit = outer_base + range->size;

    if (cmplog_contains(inner_base, inner_limit, outer_base, outer_limit))
      return true;

  }

  if (cmplog_test_addr(addr, size)) { return true; }

  return false;

}

