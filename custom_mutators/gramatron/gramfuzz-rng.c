
#include "gramfuzz-rng.h"
#include <stdlib.h>

extern afl_state_t *global_afl;
extern int gf_standalone_mode;

u32 gf_rand_below(afl_state_t *afl, u32 limit) {

  if (limit <= 1) return 0;

  /* Standalone mode (test_pda) */
  if (gf_standalone_mode || !afl) {
    return (u32)(rand() % limit);
  }

  /* AFL mode */
  return rand_below(afl, limit);
}
