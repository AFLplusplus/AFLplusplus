#include <stdint.h>
#include <stdio.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include "debug.h"

#include "seccomp.h"

int seccomp_event_create(void) {

  int fd = eventfd(0, 0);
  if (fd < 0) { FATAL("seccomp_event_create"); }
  return fd;

}

void seccomp_event_signal(int fd) {

  uint64_t val = 1;
  if (write(fd, &val, sizeof(uint64_t)) != sizeof(uint64_t)) {

    FATAL("seccomp_event_signal");

  }

}

void seccomp_event_wait(int fd) {

  uint64_t val = 1;
  if (read(fd, &val, sizeof(uint64_t)) != sizeof(uint64_t)) {

    FATAL("seccomp_event_wait");

  }

}

void seccomp_event_destroy(int fd) {

  if (close(fd) < 0) { FATAL("seccomp_event_destroy"); }

}

