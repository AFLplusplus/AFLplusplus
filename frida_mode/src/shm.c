#include "shm.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/shm.h>
#ifdef __ANDROID__
  #include <linux/ashmem.h>
  #include <sys/ioctl.h>
#endif

#ifdef __ANDROID__
  #define ASHMEM_DEVICE "/dev/ashmem"

void *shm_create(size_t size) {

  int               fd = -1;
  char              ourkey[11] = {0};
  void             *addr = MAP_FAILED;
  struct ashmem_pin pin = {0, size};

  fd = open(ASHMEM_DEVICE, O_RDWR);
  if (fd < 0) { FFATAL("Failed open /dev/ashmem: %d", errno); }

  if (snprintf(ourkey, sizeof(ourkey) - 1, "%d", IPC_PRIVATE) < 0) {

    FFATAL("Failed to generate key: %d", errno);

  }

  if (ioctl(fd, ASHMEM_SET_NAME, ourkey) < 0) {

    FFATAL("ioctl(ASHMEM_SET_NAME) errno: %d\n", errno);

  }

  if (ioctl(fd, ASHMEM_SET_SIZE, size) < 0) {

    FFATAL("ioctl(ASHMEM_SET_SIZE) errno: %d\n", errno);

  }

  addr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (addr == MAP_FAILED) { FFATAL("mmap failed: %d\n", errno); }

  /* Shared memory pinning has been deprecated. So if the ioctl fails, then
  just assume we are running on a version where it has been. Worst case, we
  will leak the shared memory region.*/
  ioctl(fd, ASHMEM_UNPIN, &pin);
  close(fd);

  return addr;

}

#else
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

#endif

