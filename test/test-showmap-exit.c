/*
   Test target for afl-showmap exit code testing.
   - Normal exit on most inputs
   - Timeout on input starting with "HANG"
   - Crash on input starting with "BOOM"
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {

  char buf[16];
  int  len;

  if (argc >= 2) {

    FILE *f = fopen(argv[1], "rb");
    if (!f) return 1;
    len = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);

  } else {

    len = read(0, buf, sizeof(buf) - 1);

  }

  if (len < 1) return 0;
  buf[len] = 0;

  if (len >= 4 && memcmp(buf, "HANG", 4) == 0) {

    while (1)
      sleep(1);

  }

  if (len >= 4 && memcmp(buf, "BOOM", 4) == 0) { abort(); }

  return 0;

}

