/*
   End-to-end target for state fuzzing mode (afl-fuzz -J).

   A small protocol that only makes sense as a sequence: nothing works before
   HELLO, nothing works before AUTH, and the bug is reachable only from READY
   after a particular order of operations. Compare with a picture viewer, which
   forgets everything after each file.

   States:

     INIT --HELLO--> HELLO_DONE --AUTH(good)--> READY --WRITE/READ--> READY
                                --AUTH(bad)---> ERROR --HELLO------> HELLO_DONE
                                                READY --BYE--------> DONE

   Build for fuzzing:
     AFL_LLVM_IJON=1 afl-clang-fast -o test-state-machine test-state-machine.c

   Build without AFL (the annotations compile out):
     cc -O0 -o test-state-machine test-state-machine.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#if defined(__has_include)
  #if __has_include("afl-ijon-min.h")
    #include "afl-ijon-min.h"
  #endif
#endif

#ifndef IJON_STATE
  #define IJON_STATE(x) ((void)(x))
#endif
#ifndef AFL_STATE_ACTION
  #define AFL_STATE_ACTION(x) ((void)(x))
#endif
#ifndef AFL_HOT_REGION
  #define AFL_HOT_REGION(o, l) \
    do {                       \
                               \
      (void)(o);               \
      (void)(l);               \
                               \
    } while (0)

#endif

#ifdef __AFL_FUZZ_TESTCASE_LEN
__AFL_FUZZ_INIT();
#endif

#define ST_INIT 0
#define ST_HELLO 1
#define ST_READY 2
#define ST_ERROR 3
#define ST_DONE 4

#define CMD_HELLO 0x10
#define CMD_AUTH 0x20
#define CMD_WRITE 0x30
#define CMD_READ 0x40
#define CMD_RESET 0x50
#define CMD_BYE 0x60

#define SLOTS 4
#define SLOT_CAP 32

/* The command stream starts here. Everything before is a fixed preamble, so
   the interesting bytes are a small part of a large input - which is the
   situation AFL_HOT_REGION exists for. */
#define PREAMBLE 64

static unsigned long long ops_total;

struct session {

  int      state;
  int      writes;
  int      resets;
  unsigned state_log;
  char    *slot[SLOTS];
  size_t   slot_len[SLOTS];

};

static void session_init(struct session *s) {

  memset(s, 0, sizeof(*s));
  s->state = ST_INIT;

}

static void session_free(struct session *s) {

  for (int i = 0; i < SLOTS; i++) {

    free(s->slot[i]);
    s->slot[i] = NULL;
    s->slot_len[i] = 0;

  }

}

/* Returns 0 to keep going, 1 when the session is over. */
static int step(struct session *s, uint8_t cmd, uint8_t arg, const uint8_t *pay,
                size_t pay_len) {

  ++ops_total;
  AFL_STATE_ACTION(cmd);

  switch (cmd) {

    case CMD_HELLO:
      if (s->state == ST_INIT || s->state == ST_ERROR) { s->state = ST_HELLO; }
      break;

    case CMD_AUTH:
      if (s->state != ST_HELLO) { break; }
      /* The wall: one specific byte gets you in. Everything past this point
         is unreachable by byte mutation alone until it is solved. */
      if (arg == 0xa7) {

        s->state = ST_READY;

      } else {

        s->state = ST_ERROR;

      }

      break;

    case CMD_WRITE: {

      if (s->state != ST_READY) { break; }
      int    slot = arg % SLOTS;
      size_t n = pay_len > SLOT_CAP ? SLOT_CAP : pay_len;
      free(s->slot[slot]);
      s->slot[slot] = malloc(SLOT_CAP);
      if (!s->slot[slot]) { return 1; }
      memcpy(s->slot[slot], pay, n);
      s->slot_len[slot] = n;
      ++s->writes;
      break;

    }

    case CMD_READ: {

      if (s->state != ST_READY) { break; }
      int slot = arg % SLOTS;
      if (!s->slot[slot]) { break; }

      /* The bug. Reachable only from READY, only after the session has been
         reset at least twice and written to at least three times, i.e. only
         from a genuine sequence - a single mutated buffer cannot get here. */
      size_t n = s->slot_len[slot];
      if (s->resets >= 2 && s->writes >= 3) { n = s->slot_len[slot] + 8; }

      volatile char sink = 0;
      for (size_t i = 0; i < n; i++) {

        sink = (char)(sink ^ s->slot[slot][i]);

      }

      (void)sink;
      break;

    }

    case CMD_RESET:
      if (s->state == ST_READY) {

        session_free(s);
        s->state = ST_HELLO;
        ++s->resets;

      }

      break;

    case CMD_BYE:
      if (s->state == ST_READY) {

        s->state = ST_DONE;
        return 1;

      }

      break;

    default:
      break;

  }

  /* Two steps of protocol history, which is what the fuzzer keys its state
     map on. */
  s->state_log = (s->state_log << 4) + (unsigned)s->state;
  IJON_STATE(s->state_log);

  return 0;

}

static void run(const uint8_t *buf, size_t len) {

  struct session s;

  session_init(&s);

  if (len <= PREAMBLE) {

    session_free(&s);
    return;

  }

  if (memcmp(buf, "SESS", 4) != 0) {

    session_free(&s);
    return;

  }

  AFL_HOT_REGION(PREAMBLE, len - PREAMBLE);

  size_t p = PREAMBLE;
  while (p + 3 <= len) {

    uint8_t cmd = buf[p];
    uint8_t arg = buf[p + 1];
    uint8_t plen = buf[p + 2];
    p += 3;

    size_t avail = len - p;
    size_t take = plen < avail ? plen : avail;

    if (step(&s, cmd, arg, buf + p, take)) { break; }

    p += take;

  }

  session_free(&s);

}

static void write_ops_counter(void) {

  const char *path = getenv("AFL_OPS_COUNTER_FILE");

  if (!path) { return; }

  FILE *f = fopen(path, "w");
  if (!f) { return; }
  fprintf(f, "%llu\n", ops_total);
  fclose(f);

}

int main(int argc, char **argv) {

#ifdef __AFL_HAVE_MANUAL_CONTROL
  __AFL_INIT();
#endif

#ifdef __AFL_FUZZ_TESTCASE_LEN

  unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

  while (__AFL_LOOP(10000)) {

    int len = __AFL_FUZZ_TESTCASE_LEN;
    run(buf, (size_t)len);

  }

#else

  static uint8_t data[1 << 20];
  size_t         len = 0;

  if (argc > 1) {

    FILE *f = fopen(argv[1], "rb");
    if (!f) { return 1; }
    len = fread(data, 1, sizeof(data), f);
    fclose(f);

  } else {

    len = fread(data, 1, sizeof(data), stdin);

  }

  run(data, len);

#endif

  write_ops_counter();

  return 0;

}

