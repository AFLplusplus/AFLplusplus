/*
   american fuzzy lop++ - a trivial program to test the build
   --------------------------------------------------------
   Originally written by Michal Zalewski
   Copyright 2014 Google Inc. All rights reserved.
   Copyright 2019-2022 AFLplusplus Project. All rights reserved.
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:
     http://www.apache.org/licenses/LICENSE-2.0
 */
#include <dlfcn.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

typedef void (*fntestinstrlib)(char *buf, int len);

void testinstr(char *buf, int len) {
  void *lib = dlopen("testinstrlib.so", RTLD_NOW);
  if (lib == NULL) {
    puts("Library not found");
    abort();
  }

  fntestinstrlib fn = (fntestinstrlib)(dlsym(lib, "testinstrlib"));
  if (fn == NULL) {
    puts("Function not found");
    abort();
  }

  fn(buf, len);
}

int main(int argc, char **argv) {
  char * file;
  int    fd = -1;
  off_t  len;
  char * buf = NULL;
  size_t n_read;
  int    result = -1;

  if (argc != 2) { return 1; }

  do {
    file = argv[1];
    printf("file: %s\n", file);

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

    printf("len: %ld\n", len);

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

    testinstr(buf, len);
    dprintf(STDERR_FILENO, "Done:    %s: (%zd bytes)\n", file, n_read);

    result = 0;

  } while (false);

  if (buf != NULL) { free(buf); }

  if (fd != -1) { close(fd); }

  return result;
}
