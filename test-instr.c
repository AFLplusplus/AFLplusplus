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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifdef TEST_SHARED_OBJECT
  #define main main_exported
#endif

int main(int argc, char **argv) {

  int   fd = 0, x = 1, y;
  char  buff[8];
  char *buf = buff;

  // we support command line parameter and stdin
  if (argc == 2) {

    buf = argv[1];
    printf("Input %s - ", buf);

  } else {

    if (argc >= 3 && strcmp(argv[1], "-f") == 0) {

      if ((fd = open(argv[2], O_RDONLY)) < 0) {

        fprintf(stderr, "Error: unable to open %s\n", argv[2]);
        exit(-1);

      }

    }

    if (read(fd, buf, sizeof(buf)) < 1) {

      printf("Hum?\n");
      return 1;

    }

  }

  // we support three input cases (plus a 4th if stdin is used but there is no
  // input)
  while (*buf) {

    if (*buf == '0') {

      char buff[64];
      strcpy(buff, "Looks like a zero to me: ");
      strcat(buff, buf);
      printf("%s\n", buff);

      for (y = 0; y < *buf; y++)
        x += (*buf + y - 1);

    } else if (*buf == '1') {

      char buff[64];
      strcpy(buff, "Pretty sure that is a one: ");
      strcat(buff, buf);
      printf("%s\n", buff);

      for (y = 0; y < *buf; y++)
        x += (*buf + y + 1);

    } else

      printf("Neither one or zero? How quaint!\n");

    buf++;

  }

  for (y = 0; buff[y] != 0; y++)
    x += buff[y] + y + 2;

  printf("Got %d\n", x);

  return 0;

}

