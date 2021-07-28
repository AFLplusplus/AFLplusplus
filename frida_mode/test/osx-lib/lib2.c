#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>


void __attribute__((noinline)) crashme(const uint8_t *Data, size_t Size) {

  if (Size < 1) return;

  char *buf = malloc(10);

  if (buf == NULL) return;

  switch (Data[0]) {

    /* Underflow */
    case 'U':
      printf("Underflow\n");
      buf[-1] = '\0';
      free(buf);
      break;
    /* Overflow */
    case 'O':
      printf("Overflow\n");
      buf[10] = '\0';
      free(buf);
      break;
    /* Double free */
    case 'D':
      printf("Double free\n");
      free(buf);
      free(buf);
      break;
    /* Use after free */
    case 'A':
      printf("Use after free\n");
      free(buf);
      buf[0] = '\0';
      break;
    /* Test Limits (OK) */
    case 'T':
      printf("Test-Limits - No Error\n");
      buf[0] = 'A';
      buf[9] = 'I';
      free(buf);
      break;
    case 'M':
      printf("Memset too many\n");
      memset(buf, '\0', 11);
      free(buf);
      break;
    default:
      printf("Nop - No Error\n");
      break;

  }


}

