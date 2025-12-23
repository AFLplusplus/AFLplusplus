#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void funcA(char* buf) {
    buf[1] = 'A';
}
void funcB(char* buf) {
    buf[2] = 'B';
}

int main(int argc, char** argv) {
  char buf[1024];
  int len = read(0, buf, 1024);
  if (len < 0) return 1;
  buf[len] = 0;
  
  if (buf[0] == 'A') {
    for (int i = 0; i < 1000; i++) buf[i % 1024] ^= 1;
  } else if (buf[0] == 'B') {
    abort();
  } else if (buf[0] == 'C') {
    for (int i = 0; i < 500; i++) buf[i % 1024] ^= 2;
  }
  
  if (strstr(buf, "test_custom_mutator") != NULL) {
    abort();
  }
  return 0;
}
