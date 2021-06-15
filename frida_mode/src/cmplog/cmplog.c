#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <syscall.h>
#include <sys/shm.h>
#include <sys/mman.h>

#include "frida-gum.h"

#include "debug.h"

#include "util.h"

#define DEFAULT_MMAP_MIN_ADDR (32UL << 10)
#define RANGE_DATA_SIZE (64UL << 10)
#define RANGE_DATA_MAX                                         \
  ((RANGE_DATA_SIZE - offsetof(cmplog_range_data_t, ranges)) / \
   sizeof(GumMemoryRange))
#define MICRO_TO_SEC 1000000
#define MINUTE_TO_SEC 60
#define RANGE_DATA_FREQ (5UL * MINUTE_TO_SEC * MICRO_TO_SEC)

extern struct cmp_map *__afl_cmp_map;

typedef struct {

  gint64         time;
  guint          count;
  GumMemoryRange ranges[0];

} cmplog_range_data_t;

cmplog_range_data_t *range_data = NULL;

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

  guint64 current_time = g_get_monotonic_time();
  if (range_data->time != 0) {

    if (current_time - range_data->time < RANGE_DATA_FREQ) { return; }

  }

  OKF("CMPLOG - Collecting ranges");

  GArray *cmplog_ranges =
      g_array_sized_new(false, false, sizeof(GumMemoryRange), 100);
  gum_process_enumerate_ranges(GUM_PAGE_READ, cmplog_range, cmplog_ranges);
  g_array_sort(cmplog_ranges, cmplog_sort);

  if (cmplog_ranges->len > RANGE_DATA_MAX) {

    FATAL("Too many ranges: %u > %lu", cmplog_ranges->len, RANGE_DATA_MAX);

  }

  range_data->time = current_time;
  range_data->count = cmplog_ranges->len;
  for (guint i = 0; i < cmplog_ranges->len; i++) {

    GumMemoryRange *range = &g_array_index(cmplog_ranges, GumMemoryRange, i);
    memcpy(&range_data->ranges[i], range, sizeof(GumMemoryRange));

  }

  g_array_free(cmplog_ranges, TRUE);

}

void cmplog_init(void) {

  if (__afl_cmp_map != NULL) { OKF("CMPLOG mode enabled"); }

  int shm_id =
      shmget(IPC_PRIVATE, RANGE_DATA_SIZE, IPC_CREAT | IPC_EXCL | 0600);
  if (shm_id < 0) { FATAL("shm_id < 0 - errno: %d\n", errno); }

  range_data = shmat(shm_id, NULL, 0);
  g_assert(range_data != MAP_FAILED);

  /*
   * Configure the shared memory region to be removed once the process dies.
   */
  if (shmctl(shm_id, IPC_RMID, NULL) < 0) {

    FATAL("shmctl (IPC_RMID) < 0 - errno: %d\n", errno);

  }

  /* Clear it, not sure it's necessary, just seems like good practice */
  memset(range_data, '\0', RANGE_DATA_SIZE);

  OKF("CMPLOG - RANGE_DATA_MAX: %lu", RANGE_DATA_MAX);

  cmplog_get_ranges();

  for (guint i = 0; i < range_data->count; i++) {

    GumMemoryRange *range = &range_data->ranges[i];
    OKF("CMPLOG Range - %3u: 0x%016" G_GINT64_MODIFIER
        "X - 0x%016" G_GINT64_MODIFIER "X",
        i, range->base_address, range->base_address + range->size);

  }

}

static gboolean cmplog_contains(GumAddress inner_base, GumAddress inner_limit,
                                GumAddress outer_base, GumAddress outer_limit) {

  return (inner_base >= outer_base && inner_limit <= outer_limit);

}

gboolean cmplog_is_readable(guint64 addr, size_t size) {

  if (range_data == NULL) FATAL("CMPLOG not initialized");

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

  for (guint i = 0; i < range_data->count; i++) {

    GumMemoryRange *range = &range_data->ranges[i];
    GumAddress      outer_base = range->base_address;
    GumAddress      outer_limit = outer_base + range->size;

    if (cmplog_contains(inner_base, inner_limit, outer_base, outer_limit))
      return true;

  }

  cmplog_get_ranges();

  return false;

}

