#include <stdio.h>
#include <errno.h>
#include <dlfcn.h>
#include <stdlib.h>

int main(int argc, char **argv) {

  if (!getenv("TEST_DLOPEN_TARGET")) return 1;
  void *lib = dlopen(getenv("TEST_DLOPEN_TARGET"), RTLD_LAZY);
  if (!lib) {

    perror(dlerror());
    return 2;

  }

  int (*func)(int, char **) = dlsym(lib, "main_exported");
  if (!func) return 3;

  return func(argc, argv);

}

