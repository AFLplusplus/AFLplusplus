#include "shm.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/shm.h>

void *shm_create(size_t size) {

  int shm_id =
      shmget(IPC_PRIVATE, size, IPC_CREAT | IPC_EXCL | S_IRUSR | S_IWUSR);
  if (shm_id < 0) { FFATAL("shm_id < 0 - errno: %d\n", errno); }

  void *addr = shmat(shm_id, NULL, 0);
  if (addr == MAP_FAILED) { FFATAL("addr == MAP_FAILED - errno: %d\n", errno); }

  /*
   * Configure the shared memory region to be removed once the process
   * dies.
   */
  if (shmctl(shm_id, IPC_RMID, NULL) < 0) {

    FFATAL("shmctl (IPC_RMID) < 0 - errno: %d\n", errno);

  }

  /* Clear it, not sure it's necessary, just seems like good practice */
  memset(addr, '\0', size);

  return addr;

}

