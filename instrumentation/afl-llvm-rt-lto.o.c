/*
   american fuzzy lop++ - LLVM instrumentation bootstrap
   -----------------------------------------------------

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

*/

#include <stdio.h>
#include <stdlib.h>

// to prevent the function from being removed
unsigned char __afl_lto_mode = 0;

/* Proper initialization routine. */

__attribute__((constructor(0))) void __afl_auto_init_globals(void) {

  if (getenv("AFL_DEBUG")) fprintf(stderr, "[__afl_auto_init_globals]\n");
  __afl_lto_mode = 1;

}

