/*
   american fuzzy lop++ - a trivial program to test the build
   --------------------------------------------------------
   Originally written by Michal Zalewski
   Copyright 2014 Google Inc. All rights reserved.
   Copyright 2019-2024 AFLplusplus Project. All rights reserved.
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:
     http://www.apache.org/licenses/LICENSE-2.0
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

#ifdef __APPLE__
  #define TESTINSTR_SECTION
#else
  #define TESTINSTR_SECTION __attribute__((section(".testinstr")))
#endif

void LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

  if (size < 1) return;

  struct timeval tv = {0};
  if (gettimeofday(&tv, NULL) < 0) return;

  if ((tv.tv_usec % 2) == 0) {

    printf("Hooray all even\n");

  } else {

    printf("Hmm that's odd\n");

  }

  // we support three input cases
  if (data[0] == '0')
    printf("Looks like a zero to me!\n");
  else if (data[0] == '1')
    printf("Pretty sure that is a one!\n");
  else
    printf("Neither one or zero? How quaint!\n");

}

void run_test(char *file) {

  fprintf(stderr, "Running: %s\n", file);
  FILE *f = fopen(file, "r");
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
  fprintf(stderr, "Done:    %s: (%zd bytes)\n", file, n_read);

}

int main(int argc, char **argv) {

  srand(1);
  fprintf(stderr, "StandaloneFuzzTargetMain: running %d inputs\n", argc - 1);
  for (int i = 1; i < argc; i++) {

    run_test(argv[i]);

  }

}

