#include <stdio.h>

int target_func(unsigned char *buf, int size) {

  printf("buffer:%p, size:%d\n", buf, size);
  switch (buf[0]) {

    case 1:
      if (buf[1] == '\x44') { puts("a"); }
      break;
    case 0xff:
      if (buf[2] == '\xff') {

        if (buf[1] == '\x44') { puts("b"); }

      }

      break;
    default:
      break;

  }

  return 1;

}

char data[1024];

int main() {

  target_func(data, 1024);

}

