/* Correct counterpart for the round-trip oracle: save and load are exact
   inverses, and the loader refuses the type values the saver never emits.
   Exits 0. */

#include <stdio.h>
#include <string.h>
#include "../afl-oracles.h"

typedef struct {

  unsigned char type;
  unsigned char len;
  unsigned char data[8];

} record_t;

static long save(const record_t *obj, unsigned char *out, size_t cap) {

  volatile unsigned char len = obj->len;

  if (len > sizeof(obj->data)) { return -1; }
  if (cap < (size_t)len + 2u) { return -1; }

  out[0] = obj->type;
  out[1] = (unsigned char)len;
  memcpy(out + 2, obj->data, len);

  return (long)len + 2;

}

static int load(const unsigned char *in, size_t len, record_t *out) {

  if (len < 2) { return 1; }
  if (in[0] < 1 || in[0] > 3) { return 1; }
  if (in[1] > sizeof(out->data)) { return 1; }
  if (len != (size_t)in[1] + 2u) { return 1; }

  memset(out, 0, sizeof(*out));
  out->type = in[0];
  out->len = in[1];
  memcpy(out->data, in + 2, in[1]);

  return 0;

}

int main(void) {

  record_t obj, tmp;

  memset(&obj, 0, sizeof(obj));
  obj.type = 2;
  obj.len = 6;
  memcpy(obj.data, "abcdef", 6);

  AFL_ORACLE_ROUNDTRIP(save, load, &obj, &tmp, AFL_ORACLE_MANGLE_FLIP);

  printf("roundtrip_good: clean\n");

  return 0;

}
