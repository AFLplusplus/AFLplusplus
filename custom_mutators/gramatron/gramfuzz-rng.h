
#ifndef AFLPLUSPLUS_GRAMFUZZ_RNG_H
#define AFLPLUSPLUS_GRAMFUZZ_RNG_H

#include "afl-fuzz.h"

// for test.c as standalone mode instead of AFL mode
struct afl_state;
u32 gf_rand_below(struct afl_state *afl, u32 limit);

#endif  // AFLPLUSPLUS_GRAMFUZZ_RNG_H
