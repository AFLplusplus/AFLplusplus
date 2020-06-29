/*
   Written in 2019 by David Blackman and Sebastiano Vigna (vigna@acm.org)

   To the extent possible under law, the author has dedicated all copyright
   and related and neighboring rights to this software to the public domain
   worldwide. This software is distributed without any warranty.

   See <http://creativecommons.org/publicdomain/zero/1.0/>.

   This is xoshiro256++ 1.0, one of our all-purpose, rock-solid generators.
   It has excellent (sub-ns) speed, a state (256 bits) that is large
   enough for any parallel application, and it passes all tests we are
   aware of.

   For generating just floating-point numbers, xoshiro256+ is even faster.

   The state must be seeded so that it is not everywhere zero. If you have
   a 64-bit seed, we suggest to seed a splitmix64 generator and use its
   output to fill s[].
*/

#include <stdint.h>
#include "afl-fuzz.h"
#include "types.h"
#include "xxh3.h"

/* we use xoshiro256** instead of rand/random because it is 10x faster and has
   better randomness properties. */

static inline uint64_t rotl(const uint64_t x, int k) {

  return (x << k) | (x >> (64 - k));

}

void rand_set_seed(afl_state_t *afl, s64 init_seed) {

  afl->init_seed = init_seed;
  afl->rand_seed[0] =
      hash64((u8 *)&afl->init_seed, sizeof(afl->init_seed), HASH_CONST);
  afl->rand_seed[1] = afl->rand_seed[0] ^ 0x1234567890abcdef;
  afl->rand_seed[2] = afl->rand_seed[0] & 0x0123456789abcdef;
  afl->rand_seed[3] = afl->rand_seed[0] | 0x01abcde43f567908;

}

uint64_t rand_next(afl_state_t *afl) {

  const uint64_t result =
      rotl(afl->rand_seed[0] + afl->rand_seed[3], 23) + afl->rand_seed[0];

  const uint64_t t = afl->rand_seed[1] << 17;

  afl->rand_seed[2] ^= afl->rand_seed[0];
  afl->rand_seed[3] ^= afl->rand_seed[1];
  afl->rand_seed[1] ^= afl->rand_seed[2];
  afl->rand_seed[0] ^= afl->rand_seed[3];

  afl->rand_seed[2] ^= t;

  afl->rand_seed[3] = rotl(afl->rand_seed[3], 45);

  return result;

}

/* This is the jump function for the generator. It is equivalent
   to 2^128 calls to rand_next(); it can be used to generate 2^128
   non-overlapping subsequences for parallel computations. */

void jump(afl_state_t *afl) {

  static const uint64_t JUMP[] = {0x180ec6d33cfd0aba, 0xd5a61266f0c9392c,
                                  0xa9582618e03fc9aa, 0x39abdc4529b1661c};
  int                   i, b;
  uint64_t              s0 = 0;
  uint64_t              s1 = 0;
  uint64_t              s2 = 0;
  uint64_t              s3 = 0;
  for (i = 0; i < sizeof JUMP / sizeof *JUMP; i++)
    for (b = 0; b < 64; b++) {

      if (JUMP[i] & UINT64_C(1) << b) {

        s0 ^= afl->rand_seed[0];
        s1 ^= afl->rand_seed[1];
        s2 ^= afl->rand_seed[2];
        s3 ^= afl->rand_seed[3];

      }

      rand_next(afl);

    }

  afl->rand_seed[0] = s0;
  afl->rand_seed[1] = s1;
  afl->rand_seed[2] = s2;
  afl->rand_seed[3] = s3;

}

/* This is the long-jump function for the generator. It is equivalent to
   2^192 calls to rand_next(); it can be used to generate 2^64 starting points,
   from each of which jump() will generate 2^64 non-overlapping
   subsequences for parallel distributed computations. */

void long_jump(afl_state_t *afl) {

  static const uint64_t LONG_JUMP[] = {0x76e15d3efefdcbbf, 0xc5004e441c522fb3,
                                       0x77710069854ee241, 0x39109bb02acbe635};

  int      i, b;
  uint64_t s0 = 0;
  uint64_t s1 = 0;
  uint64_t s2 = 0;
  uint64_t s3 = 0;
  for (i = 0; i < sizeof LONG_JUMP / sizeof *LONG_JUMP; i++)
    for (b = 0; b < 64; b++) {

      if (LONG_JUMP[i] & UINT64_C(1) << b) {

        s0 ^= afl->rand_seed[0];
        s1 ^= afl->rand_seed[1];
        s2 ^= afl->rand_seed[2];
        s3 ^= afl->rand_seed[3];

      }

      rand_next(afl);

    }

  afl->rand_seed[0] = s0;
  afl->rand_seed[1] = s1;
  afl->rand_seed[2] = s2;
  afl->rand_seed[3] = s3;

}

/* we switch from afl's murmur implementation to xxh3 as it is 30% faster -
   and get 64 bit hashes instead of just 32 bit. Less collisions! :-) */

#ifdef _DEBUG
u32 hash32(u8 *key, u32 len, u32 seed) {

#else
u32 inline hash32(u8 *key, u32 len, u32 seed) {

#endif

  return (u32)XXH64(key, len, seed);

}

#ifdef _DEBUG
u64 hash64(u8 *key, u32 len, u64 seed) {

#else
u64 inline hash64(u8 *key, u32 len, u64 seed) {

#endif

  return XXH64(key, len, seed);

}

