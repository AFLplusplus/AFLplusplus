/*
   american fuzzy lop++ - cmplog execution routines
   ------------------------------------------------

   Originally written by Michal Zalewski

   Forkserver design by Jann Horn <jannhorn@googlemail.com>

   Now maintained by by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eißfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2022 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   Shared code to handle the shared memory. This is used by the fuzzer
   as well the other components like afl-tmin, afl-showmap, etc...

 */

#include <sys/select.h>

#include "afl-fuzz.h"
#include "cmplog.h"

void cmplog_exec_child(afl_forkserver_t *fsrv, char **argv) {

  setenv("___AFL_EINS_ZWEI_POLIZEI___", "1", 1);

  if (fsrv->qemu_mode) { setenv("AFL_DISABLE_LLVM_INSTRUMENTATION", "1", 0); }

  if (!fsrv->qemu_mode && !fsrv->frida_mode && argv[0] != fsrv->cmplog_binary) {

    argv[0] = fsrv->cmplog_binary;

  }

  execv(argv[0], argv);

}

u8 common_fuzz_cmplog_stuff(afl_state_t *afl, u8 *out_buf, u32 len) {

  u8 fault;

  write_to_testcase(afl, (void **)&out_buf, len, 0);

  fault = fuzz_run_target(afl, &afl->cmplog_fsrv, afl->fsrv.exec_tmout);

  if (afl->stop_soon) { return 1; }

  if (fault == FSRV_RUN_TMOUT) {

    if (afl->subseq_tmouts++ > TMOUT_LIMIT) {

      ++afl->cur_skipped_items;
      return 1;

    }

  } else {

    afl->subseq_tmouts = 0;

  }

  /* Users can hit us with SIGUSR1 to request the current input
     to be abandoned. */

  if (afl->skip_requested) {

    afl->skip_requested = 0;
    ++afl->cur_skipped_items;
    return 1;

  }

  return 0;

}

