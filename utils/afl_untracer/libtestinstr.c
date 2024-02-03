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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

void testinstr(char *buf, int len) {

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

