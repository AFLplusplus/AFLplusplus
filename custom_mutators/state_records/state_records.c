/*
   state_records - AFL++ custom mutator for the record format in
   state_records.h
   ---------------------------------------------------------------------

   The mutator works on decoded records, never on the encoded bytes: an
   input is decoded into a program, one to eight record level operators are
   stacked on it, and the result is encoded again. Because the format
   resynchronises, the plain byte mutators keep working on the same inputs at
   the same time, which is why AFL_CUSTOM_MUTATOR_ONLY is not recommended.

   Build:

     make -C custom_mutators/state_records

   Use:

     AFL_CUSTOM_MUTATOR_LIBRARY=custom_mutators/state_records/state_records.so \
       afl-fuzz -i in -o out -- ./target @@
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "afl-fuzz.h"
#include "state_records.h"

/* Upper bounds. A program longer than this is truncated to it, which keeps
   every buffer in this file a fixed size and makes the mutator allocation
   free on the hot path. */

#define STATE_MAX_RECS 1024
#define STATE_STACK_MAX 8
#define STATE_GEN_MAX 4
#define STATE_GEN_PAYLOAD 64
#define STATE_SPLICE_TRIES 64
#define STATE_ARENA_MAX (16 * 1024 * 1024)
#define STATE_NO_OFF 0xffffffffU

/* A record while it is being mutated. The payload lives in an arena and is
   named by an offset, not a pointer, so that growing the arena never
   invalidates a record. */

typedef struct mut_rec {

  u8  opcode;
  u8  dst;
  u8  src;
  u8  flags;
  u32 off;
  u32 len;

} mut_rec_t;

typedef struct state_arena {

  u8 *buf;
  u32 len;

} state_arena_t;

typedef struct state_mutator {

  afl_state_t *afl;
  u64          rnd[2];

  state_arena_t work;
  mut_rec_t     prog[STATE_MAX_RECS];
  mut_rec_t     part[STATE_MAX_RECS];
  u32           prog_n;
  state_rec_t   scratch[STATE_MAX_RECS];
  u8           *out_buf;

  state_arena_t trim_arena;
  mut_rec_t     trim_prog[STATE_MAX_RECS];
  mut_rec_t     trim_cand[STATE_MAX_RECS];
  u32           trim_n;
  u32           trim_idx;
  u32           trim_steps;
  u32           trim_max;
  u8            trim_noop;
  u8           *trim_buf;

  const char *last_op;
  char        describe[32];

} state_mutator_t;

/* ---- random ---------------------------------------------------------- */

static inline u64 state_rand64(state_mutator_t *data) {

  u64 x = data->rnd[0];
  u64 y = data->rnd[1];

  data->rnd[0] = y;
  x ^= x << 23;
  data->rnd[1] = x ^ y ^ (x >> 17) ^ (y >> 26);

  return data->rnd[1] + y;

}

static inline u32 state_rand_below(state_mutator_t *data, u32 limit) {

  if (limit <= 1) { return 0; }
  return (u32)(state_rand64(data) % limit);

}

/* ---- payload arena --------------------------------------------------- */

static u32 state_arena_add(state_arena_t *arena, const u8 *src, u32 len) {

  u32 off = arena->len;

  if (!len) { return off; }
  if (len > STATE_ARENA_MAX || arena->len > STATE_ARENA_MAX - len) {

    return STATE_NO_OFF;

  }

  if (!afl_realloc((void **)&arena->buf, (size_t)arena->len + len)) {

    arena->len = 0;
    return STATE_NO_OFF;

  }

  if (src) {

    memcpy(arena->buf + off, src, len);

  } else {

    memset(arena->buf + off, 0, len);

  }

  arena->len += len;

  return off;

}

/* ---- decode and encode ----------------------------------------------- */

/* Decode buf into prog, copying every payload into arena. Returns the number
   of records loaded. */

static u32 state_load(state_mutator_t *data, state_arena_t *arena,
                      const u8 *buf, size_t len, mut_rec_t *prog) {

  u32 n, i;

  n = (u32)state_rec_decode(buf, len, data->scratch, STATE_MAX_RECS);

  for (i = 0; i < n; ++i) {

    u32 off =
        state_arena_add(arena, data->scratch[i].payload, data->scratch[i].len);

    if (off == STATE_NO_OFF) { return 0; }

    prog[i].opcode = data->scratch[i].opcode;
    prog[i].dst = data->scratch[i].dst;
    prog[i].src = data->scratch[i].src;
    prog[i].flags = data->scratch[i].flags;
    prog[i].off = off;
    prog[i].len = data->scratch[i].len;

  }

  return n;

}

/* Encode prog into *out, which is grown with afl_realloc(). Records are
   emitted whole, so a program that does not fit in max_size is cut at a
   record boundary. Returns the encoded length. */

static size_t state_store(state_mutator_t *data, state_arena_t *arena,
                          const mut_rec_t *prog, u32 n, u8 **out,
                          size_t max_size) {

  u32    i;
  size_t need = 0, cap;

  if (n > STATE_MAX_RECS) { n = STATE_MAX_RECS; }

  for (i = 0; i < n; ++i) {

    u32 len = prog[i].len;

    if (len > STATE_REC_MAX_PAYLOAD) { len = STATE_REC_MAX_PAYLOAD; }
    if (!arena->buf) { len = 0; }

    data->scratch[i].opcode = prog[i].opcode;
    data->scratch[i].dst = prog[i].dst;
    data->scratch[i].src = prog[i].src;
    data->scratch[i].flags = prog[i].flags;
    data->scratch[i].len = (uint16_t)len;
    data->scratch[i].payload = len ? arena->buf + prog[i].off : NULL;

    need += STATE_REC_HDR + len;

  }

  cap = need < max_size ? need : max_size;
  if (cap < STATE_REC_HDR) { return 0; }

  if (!afl_realloc((void **)out, cap)) { return 0; }

  return state_rec_encode(data->scratch, n, *out, cap);

}

/* ---- record level operators ------------------------------------------ */

static u8 state_gen_opcode(state_mutator_t *data) {

  if (state_rand_below(data, 16)) {

    return (u8)state_rand_below(data, STATE_OP_COUNT);

  }

  return (u8)state_rand_below(data, 256);

}

/* Pick a slot that one of the first upto records writes, so that a record
   reading it finds something there. Falls back to any slot. */

static u8 state_pick_written(state_mutator_t *data, u32 upto) {

  u32 i, cnt = 0, pick;
  u8  mask = 0;

  if (upto > data->prog_n) { upto = data->prog_n; }

  for (i = 0; i < upto; ++i) {

    if (state_op_writes_dst(data->prog[i].opcode)) {

      mask |= (u8)(1 << STATE_REC_SLOT(data->prog[i].dst));

    }

  }

  if (!mask) { return (u8)state_rand_below(data, STATE_REC_SLOTS); }

  for (i = 0; i < STATE_REC_SLOTS; ++i) {

    if (mask & (1 << i)) { ++cnt; }

  }

  pick = state_rand_below(data, cnt);

  for (i = 0; i < STATE_REC_SLOTS; ++i) {

    if (mask & (1 << i)) {

      if (!pick) { return (u8)i; }
      --pick;

    }

  }

  return 0;

}

static u8 state_gen_rec(state_mutator_t *data, mut_rec_t *rec, u32 upto) {

  u32 plen, i, off;

  plen = state_rand_below(data, STATE_GEN_PAYLOAD + 1);
  off = state_arena_add(&data->work, NULL, plen);
  if (off == STATE_NO_OFF) { return 0; }

  for (i = 0; i < plen; ++i) {

    data->work.buf[off + i] = (u8)state_rand_below(data, 256);

  }

  rec->opcode = state_gen_opcode(data);
  rec->dst = (u8)state_rand_below(data, STATE_REC_SLOTS);
  rec->src = state_pick_written(data, upto);
  rec->flags = (u8)state_rand_below(data, 256);
  rec->off = off;
  rec->len = plen;

  return 1;

}

static const char *state_op_insert(state_mutator_t *data) {

  mut_rec_t rec;
  u32       at;

  if (data->prog_n >= STATE_MAX_RECS) { return NULL; }

  at = state_rand_below(data, data->prog_n + 1);
  if (!state_gen_rec(data, &rec, at)) { return NULL; }

  memmove(&data->prog[at + 1], &data->prog[at],
          (data->prog_n - at) * sizeof(mut_rec_t));
  data->prog[at] = rec;
  ++data->prog_n;

  return "insert";

}

static const char *state_op_delete(state_mutator_t *data) {

  u32 at;

  if (!data->prog_n) { return NULL; }

  at = state_rand_below(data, data->prog_n);
  memmove(&data->prog[at], &data->prog[at + 1],
          (data->prog_n - at - 1) * sizeof(mut_rec_t));
  --data->prog_n;

  return "delete";

}

static const char *state_op_duplicate(state_mutator_t *data) {

  mut_rec_t rec;
  u32       at;

  if (!data->prog_n || data->prog_n >= STATE_MAX_RECS) { return NULL; }

  at = state_rand_below(data, data->prog_n);
  rec = data->prog[at];

  if (rec.len) {

    /* The source lives in the arena that is about to grow, so reserve first
       and copy afterwards - afl_realloc() may move and free the old block. */

    u32 off = state_arena_add(&data->work, NULL, rec.len);

    if (off == STATE_NO_OFF) { return NULL; }
    memcpy(data->work.buf + off, data->work.buf + rec.off, rec.len);
    rec.off = off;

  }

  memmove(&data->prog[at + 2], &data->prog[at + 1],
          (data->prog_n - at - 1) * sizeof(mut_rec_t));
  data->prog[at + 1] = rec;
  ++data->prog_n;

  return "duplicate";

}

static const char *state_op_swap(state_mutator_t *data) {

  mut_rec_t tmp;
  u32       a, b;

  if (data->prog_n < 2) { return NULL; }

  a = state_rand_below(data, data->prog_n);
  b = state_rand_below(data, data->prog_n);
  if (a == b) { b = (b + 1) % data->prog_n; }

  tmp = data->prog[a];
  data->prog[a] = data->prog[b];
  data->prog[b] = tmp;

  return "swap";

}

static const char *state_op_move(state_mutator_t *data) {

  mut_rec_t rec;
  u32       from, to;

  if (data->prog_n < 2) { return NULL; }

  from = state_rand_below(data, data->prog_n);
  to = state_rand_below(data, data->prog_n);
  if (from == to) { return NULL; }

  rec = data->prog[from];
  memmove(&data->prog[from], &data->prog[from + 1],
          (data->prog_n - from - 1) * sizeof(mut_rec_t));
  memmove(&data->prog[to + 1], &data->prog[to],
          (data->prog_n - to - 1) * sizeof(mut_rec_t));
  data->prog[to] = rec;

  return "move";

}

static const char *state_op_opcode(state_mutator_t *data) {

  u32 at;

  if (!data->prog_n) { return NULL; }

  at = state_rand_below(data, data->prog_n);

  if (state_rand_below(data, 4)) {

    data->prog[at].opcode = state_gen_opcode(data);
    return "opcode";

  }

  data->prog[at].flags = (u8)state_rand_below(data, 256);

  return "flags";

}

static const char *state_op_rewire(state_mutator_t *data) {

  u32 at;

  if (!data->prog_n) { return NULL; }

  at = state_rand_below(data, data->prog_n);

  if (state_rand_below(data, 4)) {

    data->prog[at].src = state_pick_written(data, at);

  } else {

    data->prog[at].dst = (u8)state_rand_below(data, STATE_REC_SLOTS);

  }

  return "rewire";

}

static const char *state_op_payload(state_mutator_t *data) {

  u32 at, hits, i, tries;

  if (!data->prog_n) { return NULL; }

  at = data->prog_n;
  for (tries = 0; tries < 8; ++tries) {

    u32 cand = state_rand_below(data, data->prog_n);

    if (data->prog[cand].len) {

      at = cand;
      break;

    }

  }

  if (at == data->prog_n) { return NULL; }

  hits = 1 + state_rand_below(data, 4);

  for (i = 0; i < hits; ++i) {

    u32 pos = state_rand_below(data, data->prog[at].len);
    u8 *byte = data->work.buf + data->prog[at].off + pos;

    switch (state_rand_below(data, 4)) {

      case 0:
        *byte ^= (u8)(1 << state_rand_below(data, 8));
        break;
      case 1:
        *byte = (u8)state_rand_below(data, 256);
        break;
      case 2:
        *byte += (u8)(1 + state_rand_below(data, 16));
        break;
      default:
        *byte -= (u8)(1 + state_rand_below(data, 16));
        break;

    }

  }

  return "payload";

}

static const char *state_op_grow(state_mutator_t *data) {

  u32 at, extra, want, off, i;

  if (!data->prog_n) { return NULL; }

  at = state_rand_below(data, data->prog_n);
  extra = 1 + state_rand_below(data, 32);
  want = data->prog[at].len + extra;
  if (want > STATE_REC_MAX_PAYLOAD) { return NULL; }

  off = state_arena_add(&data->work, NULL, want);
  if (off == STATE_NO_OFF) { return NULL; }

  if (data->prog[at].len) {

    memcpy(data->work.buf + off, data->work.buf + data->prog[at].off,
           data->prog[at].len);

  }

  for (i = data->prog[at].len; i < want; ++i) {

    data->work.buf[off + i] = (u8)state_rand_below(data, 256);

  }

  data->prog[at].off = off;
  data->prog[at].len = want;

  return "grow";

}

static const char *state_op_shrink(state_mutator_t *data) {

  u32 at, cut;

  if (!data->prog_n) { return NULL; }

  at = state_rand_below(data, data->prog_n);
  if (!data->prog[at].len) { return NULL; }

  cut = 1 + state_rand_below(data, data->prog[at].len);
  data->prog[at].len -= cut;

  return "shrink";

}

static const char *state_apply_one(state_mutator_t *data) {

  switch (state_rand_below(data, 10)) {

    case 0:
      return state_op_insert(data);
    case 1:
      return state_op_delete(data);
    case 2:
      return state_op_duplicate(data);
    case 3:
      return state_op_swap(data);
    case 4:
      return state_op_move(data);
    case 5:
      return state_op_opcode(data);
    case 6:
      return state_op_rewire(data);
    case 7:
      return state_op_payload(data);
    case 8:
      return state_op_grow(data);
    default:
      return state_op_shrink(data);

  }

}

/* ---- splicing at record boundaries ----------------------------------- */

static u8 state_slot_mask(const mut_rec_t *rec) {

  u8 mask = 0;

  if (state_op_writes_dst(rec->opcode)) {

    mask |= (u8)(1 << STATE_REC_SLOT(rec->dst));

  }

  if (state_op_reads_src(rec->opcode)) {

    mask |= (u8)(1 << STATE_REC_SLOT(rec->src));

  }

  return mask;

}

/* Keep the first cut_a records of our program and append the records from
   cut_b on of the splice partner. The cut is always between records, and a
   cut where the two sides touch the same slot is preferred so that the data
   flow of the spliced program still means something. */

static const char *state_splice(state_mutator_t *data, u8 *add_buf,
                                size_t add_len) {

  u32 part_n, cut_a, cut_b, tail, i;

  part_n = state_load(data, &data->work, add_buf, add_len, data->part);
  if (!part_n || !data->prog_n) { return NULL; }

  cut_a = 1 + state_rand_below(data, data->prog_n);
  cut_b = state_rand_below(data, part_n);

  for (i = 0; i < STATE_SPLICE_TRIES; ++i) {

    u32 a = 1 + state_rand_below(data, data->prog_n);
    u32 b = state_rand_below(data, part_n);

    if (state_slot_mask(&data->prog[a - 1]) & state_slot_mask(&data->part[b])) {

      cut_a = a;
      cut_b = b;
      break;

    }

  }

  tail = part_n - cut_b;
  if (cut_a + tail > STATE_MAX_RECS) { tail = STATE_MAX_RECS - cut_a; }

  memcpy(&data->prog[cut_a], &data->part[cut_b], tail * sizeof(mut_rec_t));
  data->prog_n = cut_a + tail;

  return "splice";

}

/* ---- AFL++ custom mutator API ---------------------------------------- */

state_mutator_t *afl_custom_init(afl_state_t *afl, unsigned int seed) {

  state_mutator_t *data = (state_mutator_t *)calloc(1, sizeof(state_mutator_t));

  if (!data) {

    perror("afl_custom_init calloc");
    return NULL;

  }

  data->afl = afl;
  data->rnd[0] = 0x9e3779b97f4a7c15ULL ^ (u64)seed;
  data->rnd[1] = 0xbf58476d1ce4e5b9ULL + ((u64)seed << 32);
  data->last_op = "none";

  return data;

}

size_t afl_custom_fuzz(state_mutator_t *data, u8 *buf, size_t buf_size,
                       u8 **out_buf, u8 *add_buf, size_t add_buf_size,
                       size_t max_size) {

  u32    i, stack;
  u8     spliced = 0;
  size_t out_len;

  *out_buf = NULL;
  data->last_op = "none";
  data->work.len = 0;
  data->prog_n = state_load(data, &data->work, buf, buf_size, data->prog);

  if (data->prog_n && add_buf && add_buf_size >= STATE_REC_HDR &&
      !state_rand_below(data, 2)) {

    if (state_splice(data, add_buf, add_buf_size)) {

      data->last_op = "splice";
      spliced = 1;

    }

  }

  if (!spliced) {

    if (!data->prog_n) {

      u32 want = 1 + state_rand_below(data, STATE_GEN_MAX);

      for (i = 0; i < want; ++i) {

        if (!state_gen_rec(data, &data->prog[data->prog_n], data->prog_n)) {

          break;

        }

        ++data->prog_n;

      }

      data->last_op = "generate";

    }

    stack = 1 + state_rand_below(data, STATE_STACK_MAX);

    for (i = 0; i < stack; ++i) {

      const char *name = state_apply_one(data);

      if (name) { data->last_op = name; }

    }

  }

  out_len = state_store(data, &data->work, data->prog, data->prog_n,
                        &data->out_buf, max_size);

  if (!out_len) { return 0; }

  *out_buf = data->out_buf;

  return out_len;

}

const char *afl_custom_describe(state_mutator_t *data,
                                size_t           max_description_len) {

  snprintf(data->describe, sizeof(data->describe), "rec_%s", data->last_op);

  if (max_description_len && strlen(data->describe) > max_description_len) {

    data->describe[max_description_len] = '\0';

  }

  return data->describe;

}

/* Trimming removes whole operations. Byte level trimming inside a record only
   corrupts the record, so this replaces it entirely for this format. */

s32 afl_custom_init_trim(state_mutator_t *data, u8 *buf, size_t buf_size) {

  data->trim_arena.len = 0;
  data->trim_n =
      state_load(data, &data->trim_arena, buf, buf_size, data->trim_prog);
  data->trim_idx = 0;
  data->trim_steps = 0;
  data->trim_noop = 0;
  data->trim_max = data->trim_n > 1 ? data->trim_n : 0;

  return (s32)data->trim_max;

}

size_t afl_custom_trim(state_mutator_t *data, u8 **out_buf) {

  u32    n;
  size_t len;

  if (data->trim_n > 1 && data->trim_idx < data->trim_n) {

    data->trim_noop = 0;
    memcpy(data->trim_cand, data->trim_prog,
           data->trim_idx * sizeof(mut_rec_t));
    memcpy(&data->trim_cand[data->trim_idx],
           &data->trim_prog[data->trim_idx + 1],
           (data->trim_n - data->trim_idx - 1) * sizeof(mut_rec_t));
    n = data->trim_n - 1;

  } else {

    data->trim_noop = 1;
    memcpy(data->trim_cand, data->trim_prog, data->trim_n * sizeof(mut_rec_t));
    n = data->trim_n;

  }

  *out_buf = NULL;

  len = state_store(data, &data->trim_arena, data->trim_cand, n,
                    &data->trim_buf, (size_t)-1);

  if (!len) { return 0; }

  *out_buf = data->trim_buf;

  return len;

}

s32 afl_custom_post_trim(state_mutator_t *data, u8 success) {

  if (!data->trim_noop) {

    if (success) {

      memmove(&data->trim_prog[data->trim_idx],
              &data->trim_prog[data->trim_idx + 1],
              (data->trim_n - data->trim_idx - 1) * sizeof(mut_rec_t));
      --data->trim_n;

    } else {

      ++data->trim_idx;

    }

  }

  ++data->trim_steps;
  if (data->trim_steps > data->trim_max) { data->trim_steps = data->trim_max; }

  return (s32)data->trim_steps;

}

/* --- what state does this input reach? ---

   The fuzzer can only schedule on a state signal that names a *class of
   situations*. This walks the program the way the target does and reports a
   digest of the live object store at the end of it - which slots are open, and
   at the coarser levels nothing else. A digest that carried the order of the
   operations would name a path, not a state, and then every input reaches a
   new state and the queue fills with everything.

   STATE_RECORDS_DIGEST selects how much is folded in, so the trade can be
   measured rather than argued:

     0  say nothing
     1  which slots are open                          (up to 256 classes)
     2  open slots, whether a commit landed, log2 of the bytes held
     3  hash of the whole opcode sequence             (a path, not a state) */

#define STATE_DIGEST_SLOTS 1
#define STATE_DIGEST_STORE 2
#define STATE_DIGEST_PATH 3

static unsigned state_digest_level(void) {

  static int cached = -1;

  if (unlikely(cached < 0)) {

    const char *e = getenv("STATE_RECORDS_DIGEST");

    cached = e ? atoi(e) : STATE_DIGEST_SLOTS;
    if (cached < 0 || cached > STATE_DIGEST_PATH) { cached = STATE_DIGEST_SLOTS; }

  }

  return (unsigned)cached;

}

static unsigned state_ilog2_u32(uint32_t v) {

  unsigned r = 0;

  while (v >>= 1) { ++r; }
  return r;

}

u8 afl_custom_describe_state(state_mutator_t *data, const u8 *buf,
                             size_t buf_size, u32 *ops, u32 *state_id) {

  unsigned level = state_digest_level();
  size_t   n, i;
  uint32_t open_mask = 0, held = 0, path = 0;
  unsigned commits = 0;

  if (!level || !buf || !buf_size) { return 0; }

  n = state_rec_decode(buf, buf_size, data->scratch, STATE_MAX_RECS);
  *ops = (u32)n;

  if (!n) {

    *state_id = 0;
    return 1;

  }

  /* The same walk the harness does, kept to what survives into the store. */

  for (i = 0; i < n; ++i) {

    uint8_t op = data->scratch[i].opcode % STATE_OP_COUNT;
    uint8_t dst = STATE_REC_SLOT(data->scratch[i].dst);

    switch (op) {

      case STATE_OP_OPEN:
      case STATE_OP_WRITE:
      case STATE_OP_DUP:
        open_mask |= 1u << dst;
        held += data->scratch[i].len;
        break;
      case STATE_OP_CLOSE:
        open_mask &= ~(1u << dst);
        break;
      case STATE_OP_RESET:
        open_mask = 0;
        held = 0;
        break;
      case STATE_OP_COMMIT:
        ++commits;
        break;
      default:
        break;

    }

    if (level >= STATE_DIGEST_PATH) {

      path = path * 31u + op;

    }

  }

  switch (level) {

    case STATE_DIGEST_SLOTS:
      *state_id = open_mask + 1u;
      break;

    case STATE_DIGEST_STORE:
      *state_id = 1u + open_mask + ((commits ? 1u : 0u) << 8) +
                  (state_ilog2_u32(held + 1) << 9);
      break;

    default:
      *state_id = path | 1u;
      break;

  }

  return 1;

}

void afl_custom_deinit(state_mutator_t *data) {

  if (!data) { return; }

  afl_free(data->work.buf);
  afl_free(data->trim_arena.buf);
  afl_free(data->out_buf);
  afl_free(data->trim_buf);
  free(data);

}

