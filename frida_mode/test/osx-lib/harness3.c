#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

extern void crashme(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size) {

  crashme(data, size);
  return 0;

}

void run(int argc, const char *argv[]) {

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

}

int main(int argc, const char *argv[]) {

  run(argc, argv);

  return 0;

}

