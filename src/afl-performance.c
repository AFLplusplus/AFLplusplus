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

/* Hash a file */

u64 get_binary_hash(u8 *fn) {

  if (!fn) { return 0; }
  int fd = open(fn, O_RDONLY);
  if (fd < 0) { PFATAL("Unable to open '%s'", fn); }
  struct stat st;
  if (fstat(fd, &st) < 0) { PFATAL("Unable to fstat '%s'", fn); }
  u32 f_len = st.st_size;
  if (!f_len) { return 0; }
  u8 *f_data = mmap(0, f_len, PROT_READ, MAP_PRIVATE, fd, 0);
  if (f_data == MAP_FAILED) { PFATAL("Unable to mmap file '%s'", fn); }
  close(fd);
  u64 hash = hash64(f_data, f_len, 0);
  if (munmap(f_data, f_len)) { PFATAL("unmap() failed"); }
  return hash;

}

// Public domain SHA1 implementation copied from:
// https://github.com/x42/liboauth/blob/7001b8256cd654952ec2515b055d2c5b243be600/src/sha1.c

/* This code is public-domain - it is based on libcrypt
 * placed in the public domain by Wei Dai and other contributors.
 */
// gcc -Wall -DSHA1TEST -o sha1test sha1.c && ./sha1test

#include <stdint.h>
#include <string.h>

#ifdef __BIG_ENDIAN__
  #define SHA_BIG_ENDIAN
#elif defined __LITTLE_ENDIAN__
/* override */
#elif defined __BYTE_ORDER
  #if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    #define SHA_BIG_ENDIAN
  #endif
#else                  // ! defined __LITTLE_ENDIAN__
  #include <endian.h>  // machine/endian.h
  #if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    #define SHA_BIG_ENDIAN
  #endif
#endif

/* header */

#define HASH_LENGTH 20
#define BLOCK_LENGTH 64

typedef struct sha1nfo {

  uint32_t buffer[BLOCK_LENGTH / 4];
  uint32_t state[HASH_LENGTH / 4];
  uint32_t byteCount;
  uint8_t  bufferOffset;
  uint8_t  keyBuffer[BLOCK_LENGTH];
  uint8_t  innerHash[HASH_LENGTH];

} sha1nfo;

/* public API - prototypes - TODO: doxygen*/

/**
 */
void sha1_init(sha1nfo *s);
/**
 */
void sha1_writebyte(sha1nfo *s, uint8_t data);
/**
 */
void sha1_write(sha1nfo *s, const char *data, size_t len);
/**
 */
uint8_t *sha1_result(sha1nfo *s);
/**
 */
void sha1_initHmac(sha1nfo *s, const uint8_t *key, int keyLength);
/**
 */
uint8_t *sha1_resultHmac(sha1nfo *s);

/* code */
#define SHA1_K0 0x5a827999
#define SHA1_K20 0x6ed9eba1
#define SHA1_K40 0x8f1bbcdc
#define SHA1_K60 0xca62c1d6

void sha1_init(sha1nfo *s) {

  s->state[0] = 0x67452301;
  s->state[1] = 0xefcdab89;
  s->state[2] = 0x98badcfe;
  s->state[3] = 0x10325476;
  s->state[4] = 0xc3d2e1f0;
  s->byteCount = 0;
  s->bufferOffset = 0;

}

uint32_t sha1_rol32(uint32_t number, uint8_t bits) {

  return ((number << bits) | (number >> (32 - bits)));

}

void sha1_hashBlock(sha1nfo *s) {

  uint8_t  i;
  uint32_t a, b, c, d, e, t;

  a = s->state[0];
  b = s->state[1];
  c = s->state[2];
  d = s->state[3];
  e = s->state[4];
  for (i = 0; i < 80; i++) {

    if (i >= 16) {

      t = s->buffer[(i + 13) & 15] ^ s->buffer[(i + 8) & 15] ^
          s->buffer[(i + 2) & 15] ^ s->buffer[i & 15];
      s->buffer[i & 15] = sha1_rol32(t, 1);

    }

    if (i < 20) {

      t = (d ^ (b & (c ^ d))) + SHA1_K0;

    } else if (i < 40) {

      t = (b ^ c ^ d) + SHA1_K20;

    } else if (i < 60) {

      t = ((b & c) | (d & (b | c))) + SHA1_K40;

    } else {

      t = (b ^ c ^ d) + SHA1_K60;

    }

    t += sha1_rol32(a, 5) + e + s->buffer[i & 15];
    e = d;
    d = c;
    c = sha1_rol32(b, 30);
    b = a;
    a = t;

  }

  s->state[0] += a;
  s->state[1] += b;
  s->state[2] += c;
  s->state[3] += d;
  s->state[4] += e;

}

void sha1_addUncounted(sha1nfo *s, uint8_t data) {

  uint8_t *const b = (uint8_t *)s->buffer;
#ifdef SHA_BIG_ENDIAN
  b[s->bufferOffset] = data;
#else
  b[s->bufferOffset ^ 3] = data;
#endif
  s->bufferOffset++;
  if (s->bufferOffset == BLOCK_LENGTH) {

    sha1_hashBlock(s);
    s->bufferOffset = 0;

  }

}

void sha1_writebyte(sha1nfo *s, uint8_t data) {

  ++s->byteCount;
  sha1_addUncounted(s, data);

}

void sha1_write(sha1nfo *s, const char *data, size_t len) {

  for (; len--;)
    sha1_writebyte(s, (uint8_t)*data++);

}

void sha1_pad(sha1nfo *s) {

  // Implement SHA-1 padding (fips180-2 §5.1.1)

  // Pad with 0x80 followed by 0x00 until the end of the block
  sha1_addUncounted(s, 0x80);
  while (s->bufferOffset != 56)
    sha1_addUncounted(s, 0x00);

  // Append length in the last 8 bytes
  sha1_addUncounted(s, 0);  // We're only using 32 bit lengths
  sha1_addUncounted(s, 0);  // But SHA-1 supports 64 bit lengths
  sha1_addUncounted(s, 0);  // So zero pad the top bits
  sha1_addUncounted(s, s->byteCount >> 29);  // Shifting to multiply by 8
  sha1_addUncounted(
      s, s->byteCount >> 21);  // as SHA-1 supports bitstreams as well as
  sha1_addUncounted(s, s->byteCount >> 13);  // byte.
  sha1_addUncounted(s, s->byteCount >> 5);
  sha1_addUncounted(s, s->byteCount << 3);

}

uint8_t *sha1_result(sha1nfo *s) {

  // Pad to complete the last block
  sha1_pad(s);

#ifndef SHA_BIG_ENDIAN
  // Swap byte order back
  int i;
  for (i = 0; i < 5; i++) {

    s->state[i] = (((s->state[i]) << 24) & 0xff000000) |
                  (((s->state[i]) << 8) & 0x00ff0000) |
                  (((s->state[i]) >> 8) & 0x0000ff00) |
                  (((s->state[i]) >> 24) & 0x000000ff);

  }

#endif

  // Return pointer to hash (20 characters)
  return (uint8_t *)s->state;

}

#define HMAC_IPAD 0x36
#define HMAC_OPAD 0x5c

void sha1_initHmac(sha1nfo *s, const uint8_t *key, int keyLength) {

  uint8_t i;
  memset(s->keyBuffer, 0, BLOCK_LENGTH);
  if (keyLength > BLOCK_LENGTH) {

    // Hash long keys
    sha1_init(s);
    for (; keyLength--;)
      sha1_writebyte(s, *key++);
    memcpy(s->keyBuffer, sha1_result(s), HASH_LENGTH);

  } else {

    // Block length keys are used as is
    memcpy(s->keyBuffer, key, keyLength);

  }

  // Start inner hash
  sha1_init(s);
  for (i = 0; i < BLOCK_LENGTH; i++) {

    sha1_writebyte(s, s->keyBuffer[i] ^ HMAC_IPAD);

  }

}

uint8_t *sha1_resultHmac(sha1nfo *s) {

  uint8_t i;
  // Complete inner hash
  memcpy(s->innerHash, sha1_result(s), HASH_LENGTH);
  // Calculate outer hash
  sha1_init(s);
  for (i = 0; i < BLOCK_LENGTH; i++)
    sha1_writebyte(s, s->keyBuffer[i] ^ HMAC_OPAD);
  for (i = 0; i < HASH_LENGTH; i++)
    sha1_writebyte(s, s->innerHash[i]);
  return sha1_result(s);

}

// End public domain SHA1 implementation

void sha1(const u8 *data, size_t len, u8 *out) {

  sha1nfo s;
  sha1_init(&s);
  sha1_write(&s, (const char *)data, len);
  memcpy(out, sha1_result(&s), HASH_LENGTH);

}

char *sha1_hex(const u8 *data, size_t len) {

  u8 digest[HASH_LENGTH];
  sha1(data, len, digest);
  u8 *hex = ck_alloc(HASH_LENGTH * 2 + 1);
  for (size_t i = 0; i < HASH_LENGTH; ++i) {

    sprintf((char *)(hex + i * 2), "%02x", digest[i]);

  }

  return hex;

}

char *sha1_hex_for_file(const char *fname, u32 len) {

  int fd = open(fname, O_RDONLY);
  if (fd < 0) { PFATAL("Unable to open '%s'", fname); }

  u32 read_len = MIN(len, (u32)MAX_FILE);
  u8 *tmp = ck_alloc(read_len);
  ck_read(fd, tmp, read_len, fname);

  close(fd);

  char *hex = sha1_hex(tmp, read_len);
  ck_free(tmp);
  return hex;

}

