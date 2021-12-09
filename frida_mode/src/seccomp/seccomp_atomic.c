#if defined(__linux__) && !defined(__ANDROID__)

  #include <stdbool.h>
  #include <stdio.h>

  #include "util.h"

void seccomp_atomic_set(volatile bool *ptr, bool val) {

  if (!__sync_bool_compare_and_swap(ptr, !val, val)) {

    FFATAL("Failed to set event");

  }

}

bool seccomp_atomic_try_set(volatile bool *ptr, bool val) {

  return __sync_bool_compare_and_swap(ptr, !val, val);

}

void seccomp_atomic_wait(volatile bool *ptr, bool val) {

  while (!__sync_bool_compare_and_swap(ptr, val, !val))
    ;

}

#endif

