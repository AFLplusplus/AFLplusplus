#include <unistd.h>
#include <stdlib.h>

void exit(int status) {
  _exit(status);
}
