/* target for test/test-cmin.sh - distinct coverage per leading byte, plus a
   crashing and a hanging input, and it records the input length it received
   in $CMIN_OBSERVED. Compiled twice, with -DPERSIST for the persistent
   (shared memory test case) variant. */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#ifdef PERSIST
__AFL_FUZZ_INIT();
#endif

static void classify(unsigned char *buf, int len) {

  const char *obs = getenv("CMIN_OBSERVED");

  if (obs) {

    FILE *f = fopen(obs, "a");
    if (f) {

      fprintf(f, "%d\n", len);
      fclose(f);

    }

  }

  if (len < 1) {

    puts("empty");
    return;

  }

  switch (buf[0]) {

    case '0':
      puts("zero");
      break;
    case '1':
      puts("one");
      break;
    case '2':
      puts("two");
      break;
    case 'C':
      abort();
      break;
    case 'T':
      while (1) {}
      break;
    default:
      puts("other");
      break;

  }

}

int main(int argc, char **argv) {

#ifdef PERSIST

  (void)argc;
  (void)argv;

  __AFL_INIT();
  unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

  while (__AFL_LOOP(1000)) {

    classify(buf, __AFL_FUZZ_TESTCASE_LEN);

  }

#else

  static unsigned char buf[4 * 1024 * 1024];
  int                  len = 0;

  if (argc > 1) {

    FILE *f = fopen(argv[1], "rb");
    if (!f) return 1;
    len = (int)fread(buf, 1, sizeof(buf), f);
    fclose(f);

  } else {

    int r;
    while ((r = read(0, buf + len, sizeof(buf) - (size_t)len)) > 0)
      len += r;

  }

  classify(buf, len);

#endif

  return 0;

}

