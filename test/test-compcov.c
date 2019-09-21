#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char** argv) {

  char *buf;

  if (argc > 1) {
  
    if (strcmp(argv[1], "LIBTOKENCAP") == 0)
      printf("your string was libtokencap\n");
    else if (strcmp(argv[1], "BUGMENOT") == 0)
      printf("your string was bugmenot\n");
    else if (strcmp(argv[1], "BUFFEROVERFLOW") == 0) {
      buf = malloc(16);
      strcpy(buf, "TEST");
      strcat(buf, argv[1]);
      printf("This will only crash with libdislocator: %s\n", buf);
      return 0;
    } else
      printf("I do not know your string\n");
  
  }

  return 0;

}
