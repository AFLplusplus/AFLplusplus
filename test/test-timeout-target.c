/* test/test-timeout-target.c — target for test-timeout.sh: fast paths, a slow
   path and a hanging path behind magic bytes. The slow path shares its exit
   code with a fast path so the -t <msec>+ ratchet can be exercised in normal
   and in -C mode. The 'Q' path returns a different exit code on every second
   run without branching on it, so a 'Q' input reaches new coverage once and
   then fails the calibration that follows. */

#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {

  unsigned char buf[64];

  if (argc < 2) { return 1; }

  memset(buf, 0, sizeof(buf));

  FILE *f = fopen(argv[1], "rb");
  if (!f) { return 1; }
  size_t n = fread(buf, 1, sizeof(buf) - 1, f);
  fclose(f);

  if (n < 1) { return 0; }

  if (buf[0] == 'H' && buf[1] == 'H') {

    volatile int spin = 1;
    while (spin) {}

  }

  if (buf[0] == 'Q') { return (int)(getpid() & 1) * 9; }

  if (buf[0] == 'S') {

    usleep(200000);
    if (buf[1] == 'X') { return 3; }
    return 2;

  }

  if (buf[0] == 'F') { return 2; }

  if (buf[0] == 'a') { return 4; }
  if (buf[0] == 'b') { return 5; }
  if (buf[0] == 'c') { return 6; }

  return 0;

}

