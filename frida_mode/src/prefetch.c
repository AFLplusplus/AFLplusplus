#include <errno.h>

#include "frida-gumjs.h"

#include "entry.h"
#include "intercept.h"
#include "prefetch.h"
#include "shm.h"
#include "stalker.h"
#include "util.h"

#define TRUST 0
#define PREFETCH_SIZE 65536
#define PREFETCH_ENTRIES ((PREFETCH_SIZE - sizeof(size_t)) / sizeof(void *))

#define BP_SIZE 524288

typedef struct {

  size_t count;
  void  *entry[PREFETCH_ENTRIES];

  guint8 backpatch_data[BP_SIZE];
  gsize  backpatch_size;

} prefetch_data_t;

gboolean prefetch_enable = TRUE;
gboolean prefetch_backpatch = TRUE;

static prefetch_data_t *prefetch_data = NULL;

static GHashTable *cant_prefetch = NULL;

static void gum_afl_stalker_backpatcher_notify(GumStalkerObserver *self,
                                               const GumBackpatch *backpatch,
                                               gsize               size) {

  UNUSED_PARAMETER(self);
  if (!entry_run) { return; }
  gsize remaining =
      sizeof(prefetch_data->backpatch_data) - prefetch_data->backpatch_size;

  gpointer from = gum_stalker_backpatch_get_from(backpatch);
  gpointer to = gum_stalker_backpatch_get_to(backpatch);

  /* Stop reporting patches which can't be prefetched */
  if (g_hash_table_contains(cant_prefetch, GSIZE_TO_POINTER(from)) ||
      g_hash_table_contains(cant_prefetch, GSIZE_TO_POINTER(to))) {

    return;

  }

  if (sizeof(gsize) + size > remaining) { return; }

  /* AFL may SIGKILL this child (timeout) at any instruction.
   * Publish the entry with one store to backpatch_size after its header and
   * data are written; growing the size before the data left a torn entry,
   * and the parent's prefetch_read_patches() then FFATALs before the next
   * fork, which kills the whole lane. */
  guint8 *dst = &prefetch_data->backpatch_data[prefetch_data->backpatch_size];
  memcpy(dst, &size, sizeof(gsize));
  memcpy(dst + sizeof(gsize), backpatch, size);
  __atomic_store_n(&prefetch_data->backpatch_size,
                   prefetch_data->backpatch_size + sizeof(gsize) + size,
                   __ATOMIC_RELEASE);

}

/*
 * We do this from the transformer since we need one anyway for coverage, this
 * saves the need to use an event sink.
 */
void prefetch_write(void *addr) {

#if defined(__aarch64__)
  if (!entry_compiled) { return; }
#else
  if (!entry_run) { return; }
#endif

  /* Bail if we aren't initialized */
  if (prefetch_data == NULL) return;

  /* Stop reporting blocks which can't be prefetched */
  if (g_hash_table_contains(cant_prefetch, GSIZE_TO_POINTER(addr))) { return; }

  /*
   * Our shared memory IPC is large enough for about 1000 entries, we can fine
   * tune this if we need to. But if we have more new blocks that this in a
   * single run then we ignore them and we'll pick them up next time.
   */
  if (prefetch_data->count >= PREFETCH_ENTRIES) return;

  /*
   * Write the block address to the SHM IPC and increment the number of entries.
   */

  prefetch_data->entry[prefetch_data->count] = addr;
  prefetch_data->count++;

}

/* the parent checks every block and backpatch address a child
 * reports.  Enumerating the process ranges for each address cost seconds per
 * fork on iOS, where target code sits in the shared cache behind thousands of
 * ranges.  Keep a sorted copy of the executable ranges across forks and search
 * it by bisection.  The fork server parent's map hardly changes once it is
 * running, so the copy is refreshed only when an address misses it, at most
 * once per prefetch_read(), which still catches mappings made since. */
static GArray  *prefetch_exec_ranges = NULL;
static gboolean prefetch_ranges_fresh = FALSE;

static gboolean prefetch_collect_range(const GumRangeDetails *details,
                                       gpointer               user_data) {

  UNUSED_PARAMETER(user_data);
  g_array_append_val(prefetch_exec_ranges, *details->range);
  return TRUE;

}

static gint prefetch_range_sort(gconstpointer a, gconstpointer b) {

  const GumMemoryRange *ra = (const GumMemoryRange *)a;
  const GumMemoryRange *rb = (const GumMemoryRange *)b;
  if (ra->base_address < rb->base_address) return -1;
  if (ra->base_address > rb->base_address) return 1;
  return 0;

}

static void prefetch_refresh_ranges(void) {

  if (prefetch_exec_ranges == NULL) {

    prefetch_exec_ranges = g_array_new(FALSE, FALSE, sizeof(GumMemoryRange));

  }

  g_array_set_size(prefetch_exec_ranges, 0);
  gum_process_enumerate_ranges(GUM_PAGE_EXECUTE, prefetch_collect_range, NULL);
  g_array_sort(prefetch_exec_ranges, prefetch_range_sort);
  prefetch_ranges_fresh = TRUE;

}

static gboolean prefetch_ranges_contain(GumAddress target) {

  gsize lo = 0;
  gsize hi = prefetch_exec_ranges->len;
  while (lo < hi) {

    gsize                 mid = lo + (hi - lo) / 2;
    const GumMemoryRange *range =
        &g_array_index(prefetch_exec_ranges, GumMemoryRange, mid);
    if (target < range->base_address) {

      hi = mid;

    } else if (target >= range->base_address + range->size) {

      lo = mid + 1;

    } else {

      return TRUE;

    }

  }

  return FALSE;

}

static gboolean prefetch_is_executable(void *address) {

  GumAddress target = GUM_ADDRESS(address);
  if (prefetch_exec_ranges == NULL) { prefetch_refresh_ranges(); }
  if (prefetch_ranges_contain(target)) { return TRUE; }
  if (prefetch_ranges_fresh) { return FALSE; }

  prefetch_refresh_ranges();
  return prefetch_ranges_contain(target);

}

static void prefetch_read_blocks(void) {

  GumStalker *stalker = stalker_get();
  if (prefetch_data == NULL) return;

  for (size_t i = 0; i < prefetch_data->count; i++) {

    void *addr = prefetch_data->entry[i];

    if (prefetch_is_executable(addr)) {

      gum_stalker_prefetch(stalker, addr, 1);

    } else {

      /*
       * If our child process creates a new executable mapping, e.g. by
       * dynamically loading a new DSO, then this won't appear in our parent
       * process' memory map and hence we can't prefetch it. Add it to a
       * hashtable which the child will inherit on the next fork to prevent the
       * child from keep reporting it and exhausting the shared memory buffers
       * used to pass new blocks from the child back to the parent.
       */
      g_hash_table_add(cant_prefetch, GSIZE_TO_POINTER(addr));

    }

  }

  /*
   * Reset the entry count to indicate we have finished with it and it can be
   * refilled by the child.
   */
  prefetch_data->count = 0;

}

static void prefetch_read_patches(void) {

  gsize         offset = 0;
  GumStalker   *stalker = stalker_get();
  GumBackpatch *backpatch = NULL;

  for (gsize remaining = prefetch_data->backpatch_size - offset;
       remaining > sizeof(gsize);
       remaining = prefetch_data->backpatch_size - offset) {

    gsize *src_backpatch_data = (gsize *)&prefetch_data->backpatch_data[offset];
    gsize  size = *src_backpatch_data;
    offset += sizeof(gsize);

    if (prefetch_data->backpatch_size - offset < size) {

      FFATAL("Incomplete backpatch entry");

    }

    backpatch = (GumBackpatch *)&prefetch_data->backpatch_data[offset];

    gpointer from = gum_stalker_backpatch_get_from(backpatch);
    gpointer to = gum_stalker_backpatch_get_to(backpatch);

    /*
     * If our child process creates a new executable mapping, e.g. by
     * dynamically loading a new DSO, then this won't appear in our parent
     * process' memory map and hence we can't prefetch it. Add it to a
     * hashtable which the child will inherit on the next fork to prevent the
     * child from keep reporting it and exhausting the shared memory buffers
     * used to pass new blocks from the child back to the parent.
     */
    if (!prefetch_is_executable(from)) {

      g_hash_table_add(cant_prefetch, GSIZE_TO_POINTER(from));

    }

    if (!prefetch_is_executable(to)) {

      g_hash_table_add(cant_prefetch, GSIZE_TO_POINTER(to));

    }

    if (prefetch_is_executable(from) && prefetch_is_executable(to)) {

      gum_stalker_prefetch_backpatch(stalker, backpatch);

    }

    offset += size;

  }

  prefetch_data->backpatch_size = 0;

}

/*
 * Read the IPC region one block at the time and prefetch it
 */
void prefetch_read(void) {

  prefetch_ranges_fresh = FALSE;

  /*
   * Only the fork server keeps the cached ranges: it no longer runs target
   * code, so its executable mappings are never removed. A process past the
   * entry point (a test case child, or a process the target forks itself)
   * reaches this through the fork hook with a copy it inherited, and may have
   * unmapped code since. List the ranges afresh there before trusting a hit.
   */
  if (entry_run && prefetch_data != NULL &&
      (prefetch_data->count != 0 || prefetch_data->backpatch_size != 0)) {

    prefetch_refresh_ranges();

  }

  prefetch_read_blocks();
  prefetch_read_patches();

}

void prefetch_config(void) {

  prefetch_enable = (getenv("AFL_FRIDA_INST_NO_PREFETCH") == NULL);

  if (prefetch_enable) {

    prefetch_backpatch =
        (getenv("AFL_FRIDA_INST_NO_PREFETCH_BACKPATCH") == NULL);

  } else {

    prefetch_backpatch = FALSE;

  }

}

static int prefetch_on_fork(void) {

  prefetch_read();
  return fork();

}

static void prefetch_hook_fork(void) {

  void *fork_addr =
      GSIZE_TO_POINTER(gum_module_find_global_export_by_name("fork"));
  intercept_hook(fork_addr, prefetch_on_fork, NULL);

}

void prefetch_init(void) {

  FOKF(cBLU "Instrumentation" cRST " - " cGRN "prefetch:" cYEL " [%c]",
       prefetch_enable ? 'X' : ' ');
  FOKF(cBLU "Instrumentation" cRST " - " cGRN "prefetch_backpatch:" cYEL
            " [%c]",
       prefetch_backpatch ? 'X' : ' ');

  if (!prefetch_enable) { return; }
  /*
   * Make our shared memory, we can attach before we fork, just like AFL does
   * with the coverage bitmap region and fork will take care of ensuring both
   * the parent and child see the same consistent memory region.
   */
  prefetch_data = shm_create(sizeof(prefetch_data_t));

  prefetch_hook_fork();

  cant_prefetch = g_hash_table_new(g_direct_hash, g_direct_equal);
  if (cant_prefetch == NULL) {

    FFATAL("Failed to g_hash_table_new, errno: %d", errno);

  }

  if (!prefetch_backpatch) { return; }

  GumStalkerObserver          *observer = stalker_get_observer();
  GumStalkerObserverInterface *iface = GUM_STALKER_OBSERVER_GET_IFACE(observer);
  iface->notify_backpatch = gum_afl_stalker_backpatcher_notify;

}

