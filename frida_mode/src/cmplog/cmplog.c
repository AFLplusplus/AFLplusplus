#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "frida-gum.h"

#include "debug.h"

#include "util.h"

#define DEFAULT_MMAP_MIN_ADDR (32UL << 10)
#define MAX_MEMFD_SIZE (64UL << 10)

extern struct cmp_map *__afl_cmp_map;
static GArray *        cmplog_ranges = NULL;
static GHashTable *    hash = NULL;

static int    tmpfd = -1;
static size_t tmpfd_size = 0;

static gboolean cmplog_range(const GumRangeDetails *details,
                             gpointer               user_data) {

  GArray *       cmplog_ranges = (GArray *)user_data;
  GumMemoryRange range = *details->range;
  g_array_append_val(cmplog_ranges, range);
  return TRUE;

}

static gint cmplog_sort(gconstpointer a, gconstpointer b) {

  return ((GumMemoryRange *)b)->base_address -
         ((GumMemoryRange *)a)->base_address;

}

static void cmplog_get_ranges(void) {

  OKF("CMPLOG - Collecting ranges");

  cmplog_ranges = g_array_sized_new(false, false, sizeof(GumMemoryRange), 100);
  gum_process_enumerate_ranges(GUM_PAGE_READ, cmplog_range, cmplog_ranges);
  g_array_sort(cmplog_ranges, cmplog_sort);

}

void cmplog_init(void) {

  gchar *name_used;

  if (__afl_cmp_map != NULL) { OKF("CMPLOG mode enabled"); }

  cmplog_get_ranges();

  for (guint i = 0; i < cmplog_ranges->len; i++) {

    GumMemoryRange *range = &g_array_index(cmplog_ranges, GumMemoryRange, i);
    OKF("CMPLOG Range - %3u: 0x%016" G_GINT64_MODIFIER
        "X - 0x%016" G_GINT64_MODIFIER "X",
        i, range->base_address, range->base_address + range->size);

  }

  tmpfd = g_file_open_tmp(".afl-frida-compcov-XXXXXX", &name_used, NULL);
  if (tmpfd < 0) { FATAL("Failed to create_tmpfd, errno: %d", errno); }

  unlink(name_used);
  g_free(name_used);

  hash = g_hash_table_new(g_direct_hash, g_direct_equal);
  if (hash == NULL) { FATAL("Failed to g_hash_table_new, errno: %d", errno); }

}

static gboolean cmplog_contains(GumAddress inner_base, GumAddress inner_limit,
                                GumAddress outer_base, GumAddress outer_limit) {

  return (inner_base >= outer_base && inner_limit <= outer_limit);

}

gboolean cmplog_test_addr(guint64 addr, size_t size) {

  if (g_hash_table_contains(hash, (gpointer)addr)) { return true; }

  if (tmpfd_size > MAX_MEMFD_SIZE) {

    if (lseek(tmpfd, 0, SEEK_SET) < 0) {

      FATAL("CMPLOG - Failed lseek, errno: %d", errno);

    }

  }

  /*
   * Our address map can change (e.g. stack growth), use write as a fallback to
   * validate our address.
   */
  ssize_t written = syscall(SYS_write, tmpfd, (void *)addr, size);
  if (written < 0 && errno != EFAULT && errno != 0) {

    FATAL("CMPLOG - Failed SYS_write, errno: %d", errno);

  }

  /*
   * If the write succeeds, then the buffer must be valid otherwise it would
   * return EFAULT
   */
  if (written > 0) { tmpfd_size += written; }

  if ((size_t)written == size) {

    if (!g_hash_table_add(hash, (gpointer)addr)) {

      FATAL("Failed - g_hash_table_add");

    }

    return true;

  }

  return false;

}

gboolean cmplog_is_readable(guint64 addr, size_t size) {

  if (cmplog_ranges == NULL) FATAL("CMPLOG not initialized");

  /*
   * The Linux kernel prevents mmap from allocating from the very bottom of the
   * address space to mitigate NULL pointer dereference attacks. The exact size
   * is set by sysctl by setting mmap_min_addr and 64k is suggested on most
   * platforms with 32k on ARM systems. We therefore fail fast if the address
   * is lower than this. This should avoid some overhead when functions are
   * called where one of the parameters is a size, or a some other small value.
   */
  if (addr < DEFAULT_MMAP_MIN_ADDR) { return false; }

  /* Check our addres/length don't wrap around */
  if (SIZE_MAX - addr < size) { return false; }

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

