#include <unistd.h>

static volatile int sink;

int main(void) {

  unsigned char buf[8];
  int           first_run = 1;

  while (__AFL_LOOP(100000)) {

    ssize_t len;

    if (first_run) {

      first_run = 0;
      usleep(220000);

    }

    len = read(0, buf, sizeof(buf));

    if (len > 0 && buf[0] == 'A') { sink++; }
    if (len > 1 && buf[1] == 'B') { sink++; }

  }

  return 0;

}
