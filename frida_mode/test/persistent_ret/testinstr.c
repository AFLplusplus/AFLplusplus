/*
   american fuzzy lop++ - a trivial program to test the build
   --------------------------------------------------------
   Originally written by Michal Zalewski
   Copyright 2014 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:
     http://www.apache.org/licenses/LICENSE-2.0
 */

#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#ifdef __APPLE__
  #define MAIN_SECTION
#else
  #define MAIN_SECTION __attribute__((section(".main")))
#endif

void LLVMFuzzerTestOneInput(char *buf, int len) {

  printf (">>> LLVMFuzzerTestOneInput >>>\n");
  if (len < 1) return;
  buf[len] = 0;

  // we support three input cases
  if (buf[0] == '0')
    printf("Looks like a zero to me!\n");
  else if (buf[0] == '1')
    printf("Pretty sure that is a one!\n");
  else
    printf("Neither one or zero? How quaint!\n");

}

void slow() {

  usleep(100000);

}

MAIN_SECTION int main(int argc, char **argv) {

  char * file;
  int    fd = -1;
  off_t  len;
  char * buf = NULL;
  size_t n_read;
  int    result = -1;

  if (argc != 2) { return 1; }

  do {

    file = argv[1];

    dprintf(STDERR_FILENO, "Running: %s\n", file);

    fd = open(file, O_RDONLY);
    if (fd < 0) {

      perror("open");
      break;

    }

    len = lseek(fd, 0, SEEK_END);
    if (len < 0) {

      perror("lseek (SEEK_END)");
      break;

    }

    if (lseek(fd, 0, SEEK_SET) != 0) {

      perror("lseek (SEEK_SET)");
      break;

    }

    buf = malloc(len);
    if (buf == NULL) {

      perror("malloc");
      break;

    }

    n_read = read(fd, buf, len);
    if (n_read != len) {

      perror("read");
      break;

    }

    dprintf(STDERR_FILENO, "Running:    %s: (%zd bytes)\n", file, n_read);

    LLVMFuzzerTestOneInput(buf, len);
    dprintf(STDERR_FILENO, "Done:    %s: (%zd bytes)\n", file, n_read);

    slow();

    result = 0;

  } while (false);

  if (buf != NULL) { free(buf); }

  if (fd != -1) { close(fd); }

  return result;

}

