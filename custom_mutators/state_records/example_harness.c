/*
   state_records - example target
   ------------------------------

   A slot machine. The input is a record program, every record is one
   operation on a fixed store of eight slots, and operations reach each other
   through dst and src. It exists to demonstrate the format end to end, so it
   contains two deliberate bugs that only a particular sequence of operations
   reaches:

     * DUP checks that the source slot still holds a pointer instead of
       checking that it is open, so OPEN s / CLOSE s / DUP d,s reads freed
       memory.
     * COMMIT writes a terminator one past the end of its buffer when the
       open slots hold exactly STATE_COMMIT_MAX bytes together.

   Both are memory errors, so build with AFL_USE_ASAN=1 to see them:

     AFL_USE_ASAN=1 afl-clang-fast -O0 -g -o example_harness example_harness.c

   Without an instrumenting compiler this builds with any C compiler and
   reads one input from argv[1] or stdin.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "state_records.h"

#define STATE_MAX_INPUT (1024 * 1024)
#define STATE_MAX_RECS 4096
#define STATE_COMMIT_MAX 64
#define STATE_SLOT_MAX 4096

#ifdef __AFL_HAVE_MANUAL_CONTROL
__AFL_FUZZ_INIT();
#endif

typedef struct slot {

  unsigned char *data;
  size_t         len;
  int            open;

} slot_t;

static slot_t                 slots[STATE_REC_SLOTS];
static volatile unsigned long digest;
static volatile unsigned      commits;

/* The buffer is released but the slot keeps the pointer and the length, so
   that reopening the slot knows how big it used to be. Everything that reads
   a slot is supposed to check the open flag first. */

static void slot_release(slot_t *slot) {

  free(slot->data);
  slot->open = 0;

}

static void store_reset(void) {

  unsigned i;

  for (i = 0; i < STATE_REC_SLOTS; ++i) {

    if (slots[i].open) { slot_release(&slots[i]); }
    slots[i].data = NULL;
    slots[i].len = 0;
    slots[i].open = 0;

  }

  digest = 0;
  commits = 0;

}

static void slot_set(slot_t *slot, const unsigned char *src, size_t len) {

  unsigned char *fresh;

  if (len > STATE_SLOT_MAX) { len = STATE_SLOT_MAX; }

  fresh = (unsigned char *)malloc(len ? len : 1);
  if (!fresh) { return; }

  if (len && src) { memcpy(fresh, src, len); }

  if (slot->open) { free(slot->data); }
  slot->data = fresh;
  slot->len = len;
  slot->open = 1;

}

static void do_open(const state_rec_t *rec) {

  slot_t *dst = &slots[STATE_REC_SLOT(rec->dst)];

  slot_set(dst, rec->payload, rec->len);

  /* flag bit 0 zeroes the slot instead of taking the payload */
  if ((rec->flags & 1) && dst->data) { memset(dst->data, 0, dst->len); }

}

static void do_write(const state_rec_t *rec) {

  slot_t *dst = &slots[STATE_REC_SLOT(rec->dst)];
  slot_t *src = &slots[STATE_REC_SLOT(rec->src)];
  size_t  total;

  if (!dst->open || !src->open) { return; }

  /* flag bit 1 appends the source, otherwise the source replaces the
     destination */
  if (!(rec->flags & 2)) {

    slot_set(dst, src->data, src->len);
    return;

  }

  total = dst->len + src->len;
  if (total > STATE_SLOT_MAX) { return; }

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

  }

}

static void do_read(const state_rec_t *rec) {

  slot_t *src = &slots[STATE_REC_SLOT(rec->src)];
  size_t  i;

  if (!src->open) { return; }

  for (i = 0; i < src->len; ++i) {

    digest = digest * 31u + src->data[i];

  }

}

/* The pointer is checked instead of the open flag, so a slot that CLOSE
   already freed is read here. */

static void do_dup(const state_rec_t *rec) {

  slot_t *dst = &slots[STATE_REC_SLOT(rec->dst)];
  slot_t *src = &slots[STATE_REC_SLOT(rec->src)];

  if (!src->data) { return; }

  slot_set(dst, src->data, src->len);

}

static void do_close(const state_rec_t *rec) {

  slot_t *dst = &slots[STATE_REC_SLOT(rec->dst)];

  if (!dst->open) { return; }

  slot_release(dst);

}

/* The only operation whose behaviour depends on the state reached rather
   than on its own fields. */

static void do_commit(void) {

  unsigned char buf[STATE_COMMIT_MAX];
  size_t        total = 0;
  unsigned      i, open = 0;

  for (i = 0; i < STATE_REC_SLOTS; ++i) {

    if (slots[i].open) {

      total += slots[i].len;
      ++open;

    }

  }

  if (!open || total > STATE_COMMIT_MAX) { return; }

  total = 0;

  for (i = 0; i < STATE_REC_SLOTS; ++i) {

    if (slots[i].open && slots[i].len) {

      memcpy(buf + total, slots[i].data, slots[i].len);
      total += slots[i].len;

    }

  }

  /* one past the end when the open slots hold exactly STATE_COMMIT_MAX
     bytes */
  buf[total] = 0;

  for (i = 0; i < total; ++i) {

    digest = digest * 131u + buf[i];

  }

  ++commits;
  if (commits >= 3) { digest ^= (unsigned long)total << 8; }

}

/* AFL_POOL_FORK_PROBE=<k> replays k operations, then times fork plus reap
   against the dirty footprint that k operations built. The reap is inside the
   timed loop because that is what a pool hit actually pays. */

static unsigned long pool_probe_rss_kb(void) {

  FILE         *f = fopen("/proc/self/statm", "r");
  unsigned long total = 0, resident = 0;

  if (!f) { return 0; }

  if (fscanf(f, "%lu %lu", &total, &resident) != 2) { resident = 0; }

  fclose(f);
  return resident * (unsigned long)(sysconf(_SC_PAGESIZE) / 1024);

}

static unsigned long pool_probe_now_us(void) {

  struct timespec ts;

  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (unsigned long)ts.tv_sec * 1000000UL +
         (unsigned long)(ts.tv_nsec / 1000);

}

static void pool_probe_fork_cost(unsigned park_ops) {

  const unsigned runs = 200;
  unsigned long  start, stop;
  unsigned       i;

  start = pool_probe_now_us();

  for (i = 0; i < runs; ++i) {

    pid_t p = fork();

    if (p < 0) { break; }

    if (!p) { _exit(0); }

    while (waitpid(p, NULL, 0) < 0) {}

  }

  stop = pool_probe_now_us();

  printf("park_ops=%u us_per_fork=%.2f rss_kb=%lu runs=%u\n", park_ops,
         (double)(stop - start) / (double)(i ? i : 1), pool_probe_rss_kb(), i);
  fflush(stdout);

}

static void run(const unsigned char *buf, size_t len) {

  static state_rec_t recs[STATE_MAX_RECS];
  size_t             n, i;
  const char        *probe = getenv("AFL_POOL_FORK_PROBE");
  size_t park = probe ? (size_t)strtoul(probe, NULL, 10) : (size_t)-1;

  store_reset();

  n = state_rec_decode(buf, len, recs, STATE_MAX_RECS);

  for (i = 0; i < n; ++i) {

    if (probe && i == park) {

      pool_probe_fork_cost((unsigned)i);
      store_reset();
      return;

    }

    switch (recs[i].opcode) {

      case STATE_OP_OPEN:
        do_open(&recs[i]);
        break;
      case STATE_OP_WRITE:
        do_write(&recs[i]);
        break;
      case STATE_OP_READ:
        do_read(&recs[i]);
        break;
      case STATE_OP_DUP:
        do_dup(&recs[i]);
        break;
      case STATE_OP_CLOSE:
        do_close(&recs[i]);
        break;
      case STATE_OP_COMMIT:
        do_commit();
        break;
      case STATE_OP_RESET:
        store_reset();
        break;
      default:
        break;

    }

  }

  if (probe && park >= n) { pool_probe_fork_cost((unsigned)n); }

  store_reset();

}

int main(int argc, char **argv) {

#ifdef __AFL_HAVE_MANUAL_CONTROL

  (void)argc;
  (void)argv;

  __AFL_INIT();

  {

    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(10000)) {

      run(buf, (size_t)__AFL_FUZZ_TESTCASE_LEN);

    }

  }

#else

  static unsigned char buf[STATE_MAX_INPUT];
  size_t               len = 0;

  if (argc > 1) {

    FILE *f = fopen(argv[1], "rb");

    if (!f) { return 1; }
    len = fread(buf, 1, sizeof(buf), f);
    fclose(f);

  } else {

    ssize_t got;

    while ((got = read(0, buf + len, sizeof(buf) - len)) > 0) {

      len += (size_t)got;
      if (len == sizeof(buf)) { break; }

    }

  }

  run(buf, len);

#endif

  return 0;

}

