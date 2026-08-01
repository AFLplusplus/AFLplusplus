#include <stdint.h>

int main_exported(int argc, char **argv) {

  (void)argv;

  volatile unsigned int key = (unsigned int)argc * 17U;
  volatile uint8_t      byte_key = (uint8_t)argc;
  if (byte_key == 0xa5U) { return 6; }
  if (argc == 1234) { return 1; }

  switch (key) {

    case 34:
      return 2;
    case 51:
      return 3;
    case 68:
      return 4;
    case 85:
      return 5;
    default:
      return 0;

  }

}

