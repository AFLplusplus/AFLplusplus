#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char** argv) {
  char buf[1024];
  int len = read(0, buf, 1024);
  if (len < 0) return 1;
  buf[len] = 0;
  if (strstr(buf, "test_custom_mutator") != NULL) {
    abort();
  }
  return 0;
}
