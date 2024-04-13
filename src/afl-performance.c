#include <stdint.h>
#include "afl-fuzz.h"
#include "types.h"

#ifdef _HAVE_AVX2
  #define T1HA0_AESNI_AVAILABLE 1
  #define T1HA_USE_FAST_ONESHOT_READ 1
  #define T1HA_USE_INDIRECT_FUNCTIONS 1
  #define T1HA_IA32AES_NAME XXH3_64bits
  #include "t1ha0_ia32aes_b.h"
#else
  #define XXH_INLINE_ALL
  #include "xxhash.h"
  #undef XXH_INLINE_ALL
#endif

void rand_set_seed(afl_state_t *afl, s64 init_seed) {

  afl->init_seed = init_seed;
  afl->rand_seed[0] =
      hash64((u8 *)&afl->init_seed, sizeof(afl->init_seed), HASH_CONST);
  afl->rand_seed[1] = afl->rand_seed[0] ^ 0x1234567890abcdef;
  afl->rand_seed[2] = (afl->rand_seed[0] & 0x1234567890abcdef) ^
                      (afl->rand_seed[1] | 0xfedcba9876543210);

}

#define ROTL(d, lrot) ((d << (lrot)) | (d >> (8 * sizeof(d) - (lrot))))

#ifdef WORD_SIZE_64
// romuDuoJr
inline AFL_RAND_RETURN rand_next(afl_state_t *afl) {

  AFL_RAND_RETURN xp = afl->rand_seed[0];
  afl->rand_seed[0] = 15241094284759029579u * afl->rand_seed[1];
  afl->rand_seed[1] = afl->rand_seed[1] - xp;
  afl->rand_seed[1] = ROTL(afl->rand_seed[1], 27);
  return xp;

}

#else
// RomuTrio32
inline AFL_RAND_RETURN rand_next(afl_state_t *afl) {

  AFL_RAND_RETURN xp = afl->rand_seed[0], yp = afl->rand_seed[1],
                  zp = afl->rand_seed[2];
  afl->rand_seed[0] = 3323815723u * zp;
  afl->rand_seed[1] = yp - xp;
  afl->rand_seed[1] = ROTL(afl->rand_seed[1], 6);
  afl->rand_seed[2] = zp - yp;
  afl->rand_seed[2] = ROTL(afl->rand_seed[2], 22);
  return xp;

}

#endif

#undef ROTL

/* returns a double between 0.000000000 and 1.000000000 */

inline double rand_next_percent(afl_state_t *afl) {

  return (double)(((double)rand_next(afl)) / (double)0xffffffffffffffff);

}

/* we switch from afl's murmur implementation to xxh3 as it is 30% faster -
   and get 64 bit hashes instead of just 32 bit. Less collisions! :-) */

#ifdef _DEBUG
u32 hash32(u8 *key, u32 len, u32 seed) {

#else
inline u32 hash32(u8 *key, u32 len, u32 seed) {

#endif

  (void)seed;
  return (u32)XXH3_64bits(key, len);

}

#ifdef _DEBUG
u64 hash64(u8 *key, u32 len, u64 seed) {

#else
inline u64 hash64(u8 *key, u32 len, u64 seed) {

#endif

  (void)seed;
  return XXH3_64bits(key, len);

}

