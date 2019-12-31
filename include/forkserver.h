/*
   american fuzzy lop++ - forkserver header
   ----------------------------------------

   Originally written by Michal Zalewski

   Forkserver design by Jann Horn <jannhorn@googlemail.com>

   Now maintained by by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eißfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   Shared code that implements a forkserver. This is used by the fuzzer
   as well the other components like afl-tmin.

 */

#ifndef __AFL_FORKSERVER_H
#define __AFL_FORKSERVER_H

void handle_timeout(int sig);
void init_forkserver(char **argv);

#ifdef __APPLE__
#define MSG_FORK_ON_APPLE                                                    \
  "    - On MacOS X, the semantics of fork() syscalls are non-standard and " \
  "may\n"                                                                    \
  "      break afl-fuzz performance optimizations when running "             \
  "platform-specific\n"                                                      \
  "      targets. To fix this, set AFL_NO_FORKSRV=1 in the environment.\n\n"
#else
#define MSG_FORK_ON_APPLE ""
#endif

#ifdef RLIMIT_AS
#define MSG_ULIMIT_USAGE "      ( ulimit -Sv $[%llu << 10];"
#else
#define MSG_ULIMIT_USAGE "      ( ulimit -Sd $[%llu << 10];"
#endif                                                        /* ^RLIMIT_AS */

#endif

