#include <stdio.h>
#include <errno.h>
#include <dlfcn.h>
#include <stdlib.h>

int main(int argc, char **argv) {

  if (!getenv("TEST_DLOPEN_TARGET")) {

    fprintf(stderr, "Error: TEST_DLOPEN_TARGET not set!\n");
    return 1;

  }

  void *lib = dlopen(getenv("TEST_DLOPEN_TARGET"), RTLD_LAZY);
  if (!lib) {

    perror(dlerror());
    return 2;

  }

  int (*func)(int, char **) = dlsym(lib, "main_exported");
  if (!func) {

    fprintf(stderr, "Error: main_exported not found!\n");
    return 3;

  }

  // must use deferred forkserver as otherwise AFL++ instrumentation aborts
  // because all dlopen() of instrumented libs must be before the forkserver
  __AFL_INIT();

  fprintf(stderr, "Running main_exported\n");
  return func(argc, argv);

}

