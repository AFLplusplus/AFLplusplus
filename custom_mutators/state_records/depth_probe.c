/*
   state_records - depth probe
   ---------------------------

   Reports how far into the example harness's state machine one input reaches,
   for the equal-work depth comparison of SNAPSHOT-PLAN.md Task 3 step 8.

   Depth is the popcount of a fixed 24 bit situation vector, recorded over the
   whole replay rather than at the end: an end-of-run digest of the open slots
   caps at 8 and cannot separate an input that only opened slots from one that
   reached the two bug preconditions. Bit assignments are listed at
   SITUATION_BITS below and never change, so numbers from different runs are
   comparable.

   The replay follows example_harness.c operation for operation, with two
   deliberate departures so that the probe itself has no undefined behaviour:
   a closed slot keeps its buffer instead of freeing it, and the commit
   terminator is written into a buffer with room for it. Both bugs are
   therefore recorded as situations reached rather than performed, and the
   state the rest of the program sees is the same one the harness sees.

   Built uninstrumented with plain cc, and forks once per input, so that a
   crashing or looping input costs one input rather than the whole sample.

   usage: depth_probe file [file ...]
   output: one line per file - <path> ops=<n> depth=<popcount> bits=<hex>
 */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "state_records.h"

#define DP_MAX_INPUT (1024 * 1024)
#define DP_MAX_RECS 4096
#define DP_COMMIT_MAX 64
#define DP_SLOT_MAX 4096
#define DP_TIMEOUT 5

/* SITUATION_BITS

     0-7    slot i was opened at least once
     8-15   slot i was closed while open at least once
     16     an append write succeeded
     17     a replace write succeeded
     18     dup read a slot that close had already released
     19     a read digested at least one byte
     20     a commit landed
     21     three or more commits landed
     22     the open slots held 32 bytes or more at some point
     23     the open slots held exactly the commit limit, so the terminator
            went one past the end
 */

#define DP_BIT_OPEN(i) (1u << (i))
#define DP_BIT_CLOSED(i) (1u << (8 + (i)))
#define DP_BIT_APPEND (1u << 16)
#define DP_BIT_REPLACE (1u << 17)
#define DP_BIT_UAF (1u << 18)
#define DP_BIT_READ (1u << 19)
#define DP_BIT_COMMIT (1u << 20)
#define DP_BIT_COMMIT3 (1u << 21)
#define DP_BIT_BYTES32 (1u << 22)
#define DP_BIT_OVERFLOW (1u << 23)

typedef struct dp_slot {

  unsigned char *data;
  size_t         len;
  int            open;

} dp_slot_t;

static dp_slot_t     slots[STATE_REC_SLOTS];
static unsigned long digest;
static unsigned      commits;
static unsigned      situations;

static void dp_release(dp_slot_t *slot) {

  slot->open = 0;

}

static void dp_reset(void) {

  unsigned i;

  for (i = 0; i < STATE_REC_SLOTS; ++i) {

    free(slots[i].data);
    slots[i].data = NULL;
    slots[i].len = 0;
    slots[i].open = 0;

  }

  digest = 0;
  commits = 0;

}

static void dp_set(dp_slot_t *slot, const unsigned char *src, size_t len) {

  unsigned char *fresh;

  if (len > DP_SLOT_MAX) { len = DP_SLOT_MAX; }

  fresh = (unsigned char *)malloc(len ? len : 1);
  if (!fresh) { return; }

  if (len && src) { memcpy(fresh, src, len); }

  free(slot->data);
  slot->data = fresh;
  slot->len = len;
  slot->open = 1;

}

static void dp_note_bytes(void) {

  size_t   total = 0;
  unsigned i, open = 0;

  for (i = 0; i < STATE_REC_SLOTS; ++i) {

    if (slots[i].open) {

      total += slots[i].len;
      ++open;

    }

  }

  if (!open) { return; }
  if (total >= 32) { situations |= DP_BIT_BYTES32; }

}

static void dp_open(const state_rec_t *rec) {

  unsigned   idx = STATE_REC_SLOT(rec->dst);
  dp_slot_t *dst = &slots[idx];

  dp_set(dst, rec->payload, rec->len);
  situations |= DP_BIT_OPEN(idx);

  if ((rec->flags & 1) && dst->data) { memset(dst->data, 0, dst->len); }

}

static void dp_write(const state_rec_t *rec) {

  dp_slot_t *dst = &slots[STATE_REC_SLOT(rec->dst)];
  dp_slot_t *src = &slots[STATE_REC_SLOT(rec->src)];
  size_t     total;

  if (!dst->open || !src->open) { return; }

  if (!(rec->flags & 2)) {

    dp_set(dst, src->data, src->len);
    situations |= DP_BIT_REPLACE;
    return;

  }

  total = dst->len + src->len;
  if (total > DP_SLOT_MAX) { return; }

  {

    size_t         head = dst->len;
    size_t         tail = src->len;
    unsigned char *grown;

    grown = (unsigned char *)realloc(dst->data, total ? total : 1);
    if (!grown) { return; }

    if (dst == src) {

      memcpy(grown + head, grown, tail);

    } else {

      memcpy(grown + head, src->data, tail);

    }

    dst->data = grown;
    dst->len = total;
    situations |= DP_BIT_APPEND;

  }

}

static void dp_read(const state_rec_t *rec) {

  dp_slot_t *src = &slots[STATE_REC_SLOT(rec->src)];
  size_t     i;

  if (!src->open) { return; }
  if (src->len) { situations |= DP_BIT_READ; }

  for (i = 0; i < src->len; ++i) {

    digest = digest * 31u + src->data[i];

  }

}

static void dp_dup(const state_rec_t *rec) {

  unsigned   sidx = STATE_REC_SLOT(rec->src);
  dp_slot_t *dst = &slots[STATE_REC_SLOT(rec->dst)];
  dp_slot_t *src = &slots[sidx];

  if (!src->data) { return; }

  if (!src->open) { situations |= DP_BIT_UAF; }

  dp_set(dst, src->data, src->len);
  situations |= DP_BIT_OPEN(STATE_REC_SLOT(rec->dst));

}

static void dp_close(const state_rec_t *rec) {

  unsigned   idx = STATE_REC_SLOT(rec->dst);
  dp_slot_t *dst = &slots[idx];

  if (!dst->open) { return; }

  dp_release(dst);
  situations |= DP_BIT_CLOSED(idx);

}

static void dp_commit(void) {

  unsigned char buf[DP_COMMIT_MAX + 1];
  size_t        total = 0;
  unsigned      i, open = 0;

  for (i = 0; i < STATE_REC_SLOTS; ++i) {

    if (slots[i].open) {

      total += slots[i].len;
      ++open;

    }

  }

  if (!open || total > DP_COMMIT_MAX) { return; }

  if (total == DP_COMMIT_MAX) { situations |= DP_BIT_OVERFLOW; }

  total = 0;

  for (i = 0; i < STATE_REC_SLOTS; ++i) {

    if (slots[i].open && slots[i].len) {

      memcpy(buf + total, slots[i].data, slots[i].len);
      total += slots[i].len;

    }

  }

  buf[total] = 0;

  for (i = 0; i < total; ++i) {

    digest = digest * 131u + buf[i];

  }

  ++commits;
  situations |= DP_BIT_COMMIT;
  if (commits >= 3) { situations |= DP_BIT_COMMIT3; }

}

static size_t dp_run(const unsigned char *buf, size_t len) {

  static state_rec_t recs[DP_MAX_RECS];
  size_t             n, i;

  dp_reset();
  situations = 0;

  n = state_rec_decode(buf, len, recs, DP_MAX_RECS);

  for (i = 0; i < n; ++i) {

    switch (recs[i].opcode) {

      case STATE_OP_OPEN:
        dp_open(&recs[i]);
        break;
      case STATE_OP_WRITE:
        dp_write(&recs[i]);
        break;
      case STATE_OP_READ:
        dp_read(&recs[i]);
        break;
      case STATE_OP_DUP:
        dp_dup(&recs[i]);
        break;
      case STATE_OP_CLOSE:
        dp_close(&recs[i]);
        break;
      case STATE_OP_COMMIT:
        dp_commit();
        break;
      case STATE_OP_RESET:
        dp_reset();
        break;
      default:
        break;

    }

    dp_note_bytes();

  }

  dp_reset();

  return n;

}

static unsigned dp_popcount(unsigned v) {

  unsigned c = 0;

  while (v) {

    v &= v - 1;
    ++c;

  }

  return c;

}

static int dp_one(const char *path) {

  static unsigned char buf[DP_MAX_INPUT];
  FILE                *f = fopen(path, "rb");
  size_t               len, n;

  if (!f) { return 1; }
  len = fread(buf, 1, sizeof(buf), f);
  fclose(f);

  alarm(DP_TIMEOUT);
  n = dp_run(buf, len);
  alarm(0);

  printf("%s ops=%zu depth=%u bits=%06x\n", path, n, dp_popcount(situations),
         situations);

  return 0;

}

int main(int argc, char **argv) {

  int i;

  if (argc < 2) {

    fprintf(stderr, "usage: %s file [file ...]\n", argv[0]);
    return 1;

  }

  if (argc == 2) { return dp_one(argv[1]); }

  for (i = 1; i < argc; ++i) {

    pid_t pid = fork();

    if (pid < 0) { return 1; }

    if (!pid) {

      int rc = dp_one(argv[i]);

      fflush(stdout);
      _exit(rc);

    }

    {

      int st;

      if (waitpid(pid, &st, 0) < 0) { return 1; }

      if (!WIFEXITED(st) || WEXITSTATUS(st)) {

        printf("%s ops=? depth=? bits=?\n", argv[i]);
        fflush(stdout);

      }

    }

  }

  return 0;

}

