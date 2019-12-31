/*
   american fuzzy lop++ - common routines header
   ---------------------------------------------

   Originally written by Michal Zalewski

   Now maintained by by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eißfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   Gather some functions common to multiple executables

   - detect_file_args

 */

#ifndef __AFLCOMMON_H
#define __AFLCOMMON_H
#include "types.h"

extern u8* target_path;                 /* Path to target binary            */

void detect_file_args(char** argv, u8* prog_in);

char** get_qemu_argv(u8* own_loc, char** argv, int argc);
char** get_wine_argv(u8* own_loc, char** argv, int argc);
#endif

