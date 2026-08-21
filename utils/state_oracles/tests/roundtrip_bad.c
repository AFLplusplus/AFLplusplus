/* Deliberately broken example for the round-trip oracle. The loader has a
   length limit the saver does not, so save -> load -> save loses bytes, and
   it accepts type values the saver would never write. The oracle must abort
   (SIGABRT, exit 134 under a shell). */

#include <stdio.h>
#include <string.h>
#include "../afl-oracles.h"

#define LOADER_LIMIT 4

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

/* The defect: a limit the saver does not share, routed through volatile so
   no optimisation level can fold it away. */

static int load(const unsigned char *in, size_t len, record_t *out) {

  volatile unsigned char limit = LOADER_LIMIT;

  if (len < 2) { return 1; }

  memset(out, 0, sizeof(*out));
  out->type = in[0];
  out->len = in[1] > limit ? limit : in[1];
  memcpy(out->data, in + 2, out->len);

  return 0;

}

int main(void) {

  record_t obj, tmp;

  memset(&obj, 0, sizeof(obj));
  obj.type = 2;
  obj.len = 6;
  memcpy(obj.data, "abcdef", 6);

  AFL_ORACLE_ROUNDTRIP(save, load, &obj, &tmp, AFL_ORACLE_MANGLE_FLIP);

  printf("roundtrip_bad: NOT DETECTED\n");

  return 0;

}
