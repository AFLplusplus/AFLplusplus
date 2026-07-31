#include <string.h>

int main(int argc, char **argv) {

  volatile int x = argc + (argv && argv[0] ? 1 : 0);

  if (x == 3) { x += 7; }

  switch (x) {

    case 1:
      x += 11;
      break;

    case 2:
      x += 13;
      break;

    default:
      x += 17;
      break;

  }

  return memcmp("AA", "BB", 2) ? 0 : x;

}

