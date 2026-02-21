/* include/storfuzz.h */
#ifndef _AFL_FUZZ_STORFUZZ_H
#define _AFL_FUZZ_STORFUZZ_H

#include "types.h"
#include "config.h"

#ifdef __cplusplus
extern "C" {

#endif

/* StorFuzz paper default: 2^17 bytes = 131072 bytes */
#define STORFUZZ_MAP_SIZE_POW2 17U
#define STORFUZZ_MAP_SIZE (1U << STORFUZZ_MAP_SIZE_POW2)

/* Enable flag (runtime) */
#define AFL_STORFUZZ_ENABLE_ENV "AFL_STORFUZZ"

/* SHM env var passed to target runtime */
#ifndef SHM_STOR_ENV_VAR
  #define SHM_STOR_ENV_VAR "__AFL_STOR_SHM_ID"
#endif

struct afl_state;

void storfuzz_init(struct afl_state *afl);
void storfuzz_deinit(struct afl_state *afl);
void storfuzz_clear_map(struct afl_state *afl);

/* returns 0 if no new bits, 2 if any new bits (AFL-style “interesting”) */
u8 storfuzz_has_new_bits(struct afl_state *afl);

#ifdef __cplusplus

}

#endif

#endif                                              /* _AFL_FUZZ_STORFUZZ_H */

