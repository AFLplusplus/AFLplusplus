#include <stdbool.h>
#include <stdio.h>

#include "debug.h"

void seccomp_atomic_set(volatile bool *ptr, bool val) {

  if (!__sync_bool_compare_and_swap(ptr, !val, val)) {

    FATAL("Failed to set event");

  }

}

bool seccomp_atomic_try_set(volatile bool *ptr, bool val) {

  return __sync_bool_compare_and_swap(ptr, !val, val);

}

void seccomp_atomic_wait(volatile bool *ptr, bool val) {

  while (!__sync_bool_compare_and_swap(ptr, val, !val))
    ;

}

