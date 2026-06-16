/* Tiny target for test-crash-traces.sh: triggers a heap-buffer-overflow under
   ASAN when the first input byte differs from the seed byte 'B'. Reads from
   argv[1] if given, otherwise from stdin. Crashing on "any byte != 'B'" makes
   the crash trivial for AFL to discover from a 'B' seed (one byte-0 mutation),
   keeping the test fast and reliable.

   The out-of-bounds index is derived from the runtime input length and the
   result escapes through a volatile sink, so the access survives -O3 (which
   afl-cc forces) instead of being optimized away. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

volatile unsigned char g_sink;

int main(int argc, char **argv) {

  unsigned char buf[16];
  int           n;

  if (argc > 1) {

    FILE *f = fopen(argv[1], "rb");
    if (!f) return 0;
    n = (int)fread(buf, 1, sizeof(buf), f);
    fclose(f);

  } else {

    n = (int)read(0, buf, sizeof(buf));

  }

  if (n <= 0) return 0;

  /* Print to stderr on EVERY run so the test can verify the captured trace
     holds only the crashing run's output, not output accumulated from previous
     runs. */
  fprintf(stderr, "run-marker: processing %d bytes\n", n);

  if (buf[0] != 'B') {

    unsigned char *p = (unsigned char *)malloc(8);
    if (!p) return 0;
    size_t idx = 8 + ((size_t)n & 7);              /* 8..15: past the alloc */
    p[idx] = buf[0];                               /* OOB write -> ASAN     */
    g_sink = p[idx];                               /* escapes; keeps access */
    free(p);

  }

  return 0;

}

