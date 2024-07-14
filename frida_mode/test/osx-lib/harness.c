#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

// typedef for our exported target function.
typedef void (*CRASHME)(const uint8_t *Data, size_t Size);

// globals
CRASHME fpn_crashme = NULL;

int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size) {

  fpn_crashme(data, size);
  return 0;

}

int main(int argc, const char *argv[]) {

  for (int i = 1; i < argc; i++) {

    fprintf(stderr, "Running: %s\n", argv[i]);
    FILE *f = fopen(argv[i], "r");
    assert(f);
    fseek(f, 0, SEEK_END);
    size_t len = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *buf = (unsigned char *)malloc(len);
    size_t         n_read = fread(buf, 1, len, f);
    fclose(f);
    assert(n_read == len);
    LLVMFuzzerTestOneInput(buf, len);
    free(buf);
    fprintf(stderr, "Done:    %s: (%zd bytes)\n", argv[i], n_read);

  }

  return 0;

}

__attribute__((constructor())) void constructor(void) {

  // handles to required libs
  void *dylib = NULL;

  dylib = dlopen("./libcrashme.dylib", RTLD_NOW);
  if (dylib == NULL) {

    printf("[-] Failed to load lib\n");
    printf("[-] Dlerror: %s\n", dlerror());
    exit(1);

  }

  printf("[+] Resolve function\n");

  fpn_crashme = (CRASHME)dlsym(dylib, "crashme");
  if (!fpn_crashme) {

    printf("[-] Failed to find function\n");
    exit(1);

  }

  printf("[+] Found function.\n");

}

