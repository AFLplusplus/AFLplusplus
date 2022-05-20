#include <stdio.h>
#include "test.h"

int main() {
  printf("hello world\n");
  int a = foo();
  printf("%d\n", a);
  return 0;
}
