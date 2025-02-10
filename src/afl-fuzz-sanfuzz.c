/*
   american fuzzy lop++ - cmplog execution routines
   ------------------------------------------------

   Originally written by Michal Zalewski

   Forkserver design by Jann Horn <jannhorn@googlemail.com>

   Now maintained by by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eißfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2023 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   Shared code to handle the shared memory. This is used by the fuzzer
   as well the other components like afl-tmin, afl-showmap, etc...

 */

/* This file roughly follows afl-fuzz-asanfuzz */

#include <sys/select.h>

#include "afl-fuzz.h"

void sanfuzz_exec_child(afl_forkserver_t *fsrv, char **argv) {

  if (!fsrv->qemu_mode && !fsrv->frida_mode &&
      argv[0] != fsrv->asanfuzz_binary) {

    argv[0] = fsrv->asanfuzz_binary;

  }

  execv(fsrv->target_path, argv);

}

