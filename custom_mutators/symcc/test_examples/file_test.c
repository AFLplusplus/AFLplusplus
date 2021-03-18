#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

int main(int argc, char **argv) {

  if (argc < 2) {

    printf("Need a file argument\n");
    return 1;

  }

  int fd = open(argv[1], O_RDONLY);
  if (fd < 0) {

    printf("Couldn't open file\n");
    return 1;

  }

  uint32_t value = 0;

  read(fd, &value, sizeof(value));
  close(fd);

  value = value ^ 0xffffffff;
  if (value == 0x11223344) printf("Value one\n");
  if (value == 0x44332211) printf("Value two\n");
  if (value != 0x0) printf("Not zero\n");
  return 0;

}

