#include <stdio.h>
#include <stdlib.h>

void barY() {
  printf("barY\n");
}
void barZ() {
  printf("barZ\n");
}
void bar0() {
  printf("bar0\n");
}
void bar1() {
  printf("bar1\n");
}
void bar2() {
  printf("bar2\n");
}
void bard() {
  printf("bar3\n");
}

int foo(int a, int b, int c) {

  switch(a) {
    case 0: bar0(); break;
    case 1: bar1(); break;
    case 2: bar2(); break;
    default: bard(); break;
  }

  switch(b) {
    case 0: bar0(); break;
    case 1: bar1(); break;
    case 2: bar2(); break;
    default: bard(); break;
  }

  switch(c) {
    case 1: barY(); break;
    case 2: barZ(); break;
    default: barZ(); break;
  }

  return 0;  
}

int main(int argc, char **argv) {

  int a = 1, b = 2, c;

  if (argc == 1) c = 3; else if (argc == 2) c = atoi(argv[1]);
  // else: uninitialized

  return foo(a, b, c);

}
