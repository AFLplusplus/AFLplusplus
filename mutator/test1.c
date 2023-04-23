#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

int main(){
  unsigned char buf[1024];
  unsigned      i;

  i = read(0, (char *)buf, sizeof(buf) - 1);
  if(buf[0] < 'g'){
    return 0;
  }

  abort();
  return 1;
}