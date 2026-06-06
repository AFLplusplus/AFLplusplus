#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#define BUF_SIZE 1024

int main(void) {

  unsigned char buf[BUF_SIZE];
  size_t        len = fread(buf, 1, sizeof(buf), stdin);

  uint32_t count_x = 0;
  uint32_t count_y = 0;
  uint32_t count_z = 0;
  uint32_t count_a = 0;

  for (size_t i = 0; i < len; ++i) {

    switch (buf[i]) {

      case 'X':
        count_x++;
        break;

      case 'Y':
        count_y++;
        break;

      case 'Z':
        count_z++;
        break;

      case 'A':
        count_a++;
        break;

      default:
        break;

    }

  }

  IJON_MAX_UNTIL(count_x, 512);
  IJON_MAX_UNTIL(count_y, 128);
  IJON_MAX_UNTIL(count_z, 128);
  IJON_MAX(count_a);

  /*
   * Trigger crash when count_x reaches 512
   * during iterative processing.
   */
  if (count_x >= 512) {

    fprintf(stderr, "Crash triggered: count_x = %u\n", count_x);

    volatile int *p = NULL;
    *p = 0x1337;

  }

  printf("X = %u\n", count_x);
  printf("Y = %u\n", count_y);
  printf("Z = %u\n", count_z);
  printf("A = %u\n", count_a);

  return 0;

}

