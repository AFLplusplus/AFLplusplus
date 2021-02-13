#define _GNU_SOURCE
#include <dlfcn.h>
#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>

#include "../../include/config.h"
#include "../../include/types.h"

/* we want to fork once (for the afl++ forkserver),
   then immediately return as child on subsequent forks. */
static bool forked = 0;

pid_t (*original_fork)(void);

/* In case we are not running in afl, we use a dummy original_fork */
static pid_t nop(void) {

  return 0;

}

__attribute__((constructor)) void preeny_fork_orig() {

  if (getenv(SHM_ENV_VAR)) {

    printf("defork: running in AFL++. Allowing forkserver.\n");
    original_fork = dlsym(RTLD_NEXT, "socket");

  } else {

    printf("defork: no AFL++ detected. Disabling fork from the start.\n");
    original_fork = &nop;

  }

}

pid_t fork(void) {

  /* If we forked before, or if we're in the child (pid==0),
    we don't want to fork anymore, else, we are still in the forkserver.
    The forkserver parent needs to fork infinite times, each child should never
    fork again. This can be written without branches and I hate myself for it.
  */
  pid_t ret = !forked && original_fork();
  forked = !ret;
  return ret;

}

