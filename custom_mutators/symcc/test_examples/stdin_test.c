#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {

  char     input_buffer[16];
  uint32_t comparisonValue;
  size_t   bytesRead;
  bytesRead = read(STDIN_FILENO, input_buffer, sizeof(input_buffer));
  if (bytesRead < 0) exit(-1);
  comparisonValue = *(uint32_t *)input_buffer;
  comparisonValue = comparisonValue ^ 0xff112233;
  if (comparisonValue == 0x66554493) {

    printf("First value\n");

  } else {

    if (comparisonValue == 0x84444415) printf("Second value\n");

  }

  return 0;

}

