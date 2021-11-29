#if defined(__linux__) && !defined(__ANDROID__)

  #include <stdint.h>
  #include <stdio.h>
  #include <sys/syscall.h>
  #include <unistd.h>

  #include "seccomp.h"
  #include "util.h"

int seccomp_event_create(void) {

  #ifdef SYS_eventfd
  int fd = syscall(SYS_eventfd, 0, 0);
  #else
    #ifdef SYS_eventfd2
  int fd = syscall(SYS_eventfd2, 0, 0);
    #endif
  #endif
  if (fd < 0) { FFATAL("seccomp_event_create"); }
  return fd;

}

void seccomp_event_signal(int fd) {

  uint64_t val = 1;
  if (write(fd, &val, sizeof(uint64_t)) != sizeof(uint64_t)) {

    FFATAL("seccomp_event_signal");

  }

}

void seccomp_event_wait(int fd) {

  uint64_t val = 1;
  if (read(fd, &val, sizeof(uint64_t)) != sizeof(uint64_t)) {

    FFATAL("seccomp_event_wait");

  }

}

void seccomp_event_destroy(int fd) {

  if (close(fd) < 0) { FFATAL("seccomp_event_destroy"); }

}

#endif

