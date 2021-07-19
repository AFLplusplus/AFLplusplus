#include <errno.h>
#include <sys/shm.h>
#include <sys/mman.h>

#include "frida-gumjs.h"

#include "debug.h"

#include "intercept.h"
#include "prefetch.h"
#include "stalker.h"

#define TRUST 0
#define PREFETCH_SIZE 65536
#define PREFETCH_ENTRIES ((PREFETCH_SIZE - sizeof(size_t)) / sizeof(void *))

typedef struct {

  size_t count;
  void * entry[PREFETCH_ENTRIES];

} prefetch_data_t;

gboolean prefetch_enable = TRUE;

static prefetch_data_t *prefetch_data = NULL;
static int              prefetch_shm_id = -1;

/*
 * We do this from the transformer since we need one anyway for coverage, this
 * saves the need to use an event sink.
 */
void prefetch_write(void *addr) {

  /* Bail if we aren't initialized */
  if (prefetch_data == NULL) return;

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

/*
 * Read the IPC region one block at the time and prefetch it
 */
void prefetch_read(void) {

  GumStalker *stalker = stalker_get();
  if (prefetch_data == NULL) return;

  for (size_t i = 0; i < prefetch_data->count; i++) {

    void *addr = prefetch_data->entry[i];
    gum_stalker_prefetch(stalker, addr, 1);

  }

  /*
   * Reset the entry count to indicate we have finished with it and it can be
   * refilled by the child.
   */
  prefetch_data->count = 0;

}

void prefetch_config(void) {

  prefetch_enable = (getenv("AFL_FRIDA_INST_NO_PREFETCH") == NULL);

}

static int prefetch_on_fork(void) {

  prefetch_read();
  return fork();

}

static void prefetch_hook_fork(void) {

  void *fork_addr =
      GSIZE_TO_POINTER(gum_module_find_export_by_name(NULL, "fork"));
  intercept_hook(fork_addr, prefetch_on_fork, NULL);

}

void prefetch_init(void) {

  g_assert_cmpint(sizeof(prefetch_data_t), ==, PREFETCH_SIZE);
  OKF("Instrumentation - prefetch [%c]", prefetch_enable ? 'X' : ' ');

  if (!prefetch_enable) { return; }
  /*
   * Make our shared memory, we can attach before we fork, just like AFL does
   * with the coverage bitmap region and fork will take care of ensuring both
   * the parent and child see the same consistent memory region.
   */
  prefetch_shm_id =
      shmget(IPC_PRIVATE, sizeof(prefetch_data_t), IPC_CREAT | IPC_EXCL | 0600);
  if (prefetch_shm_id < 0) {

    FATAL("prefetch_shm_id < 0 - errno: %d\n", errno);

  }

  prefetch_data = shmat(prefetch_shm_id, NULL, 0);
  g_assert(prefetch_data != MAP_FAILED);

  /*
   * Configure the shared memory region to be removed once the process dies.
   */
  if (shmctl(prefetch_shm_id, IPC_RMID, NULL) < 0) {

    FATAL("shmctl (IPC_RMID) < 0 - errno: %d\n", errno);

  }

  /* Clear it, not sure it's necessary, just seems like good practice */
  memset(prefetch_data, '\0', sizeof(prefetch_data_t));

  prefetch_hook_fork();

}

