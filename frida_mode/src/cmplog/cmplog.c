#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <syscall.h>

#include "frida-gum.h"

#include "debug.h"

#include "util.h"

#define DEFAULT_MMAP_MIN_ADDR (32UL << 10)
#define FD_TMP_MAX_SIZE 65536

extern struct cmp_map *__afl_cmp_map;

static GArray *cmplog_ranges = NULL;
static int     fd_tmp = -1;
static ssize_t fd_tmp_size = 0;

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

static int cmplog_create_temp(void) {

  const char *tmpdir = g_get_tmp_dir();
  OKF("CMPLOG Temporary directory: %s", tmpdir);
  gchar *fname = g_strdup_printf("%s/frida-cmplog-XXXXXX", tmpdir);
  OKF("CMPLOG Temporary file template: %s", fname);
  int fd = mkstemp(fname);
  OKF("CMPLOG Temporary file: %s", fname);

  if (fd < 0) {

    FATAL("Failed to create temp file: %s, errno: %d", fname, errno);

  }

  if (unlink(fname) < 0) {

    FATAL("Failed to unlink temp file: %s (%d), errno: %d", fname, fd, errno);

  }

  if (ftruncate(fd, 0) < 0) {

    FATAL("Failed to ftruncate temp file: %s (%d), errno: %d", fname, fd,
          errno);

  }

  g_free(fname);

  return fd;

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

  /*
   * We can't use /dev/null or /dev/zero for this since it appears that they
   * don't validate the input buffer. Persumably as an optimization because they
   * don't actually write any data. The file will be deleted on close.
   */
  fd_tmp = cmplog_create_temp();

}

static gboolean cmplog_contains(GumAddress inner_base, GumAddress inner_limit,
                                GumAddress outer_base, GumAddress outer_limit) {

  return (inner_base >= outer_base && inner_limit <= outer_limit);

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
    GumAddress      outer_base = range->base_address;
    GumAddress      outer_limit = outer_base + range->size;

    if (cmplog_contains(inner_base, inner_limit, outer_base, outer_limit))
      return true;

  }

  /*
   * Our address map can change (e.g. stack growth), use write as a fallback to
   * validate our address.
   */
  ssize_t written = syscall(__NR_write, fd_tmp, (void *)addr, size);

  /*
   * If the write succeeds, then the buffer must be valid otherwise it would
   * return EFAULT
   */
  if (written > 0) {

    fd_tmp_size += written;
    if (fd_tmp_size > FD_TMP_MAX_SIZE) {

      /*
       * Truncate the file, we don't want our temp file to continue growing!
       */
      if (ftruncate(fd_tmp, 0) < 0) {

        FATAL("Failed to truncate fd_tmp (%d), errno: %d", fd_tmp, errno);

      }

      fd_tmp_size = 0;

    }

    if ((size_t)written == size) { return true; }

  }

  return false;

}

