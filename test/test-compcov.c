#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char **argv) {
  char *input = argv[1], *buf, buffer[20];

  if (argc < 2) {
    ssize_t ret = read(0, buffer, sizeof(buffer) - 1);
    buffer[ret] = 0;
    input = buffer;
  }
  
  if (strcmp(input, "LIBTOKENCAP") == 0)
    printf("your string was libtokencap\n");
  else if (strcmp(input, "BUGMENOT") == 0)
    printf("your string was bugmenot\n");
  else if (strcmp(input, "BUFFEROVERFLOW") == 0) {
    buf = malloc(16);
    strcpy(buf, "TEST");
    strcat(buf, input);
    printf("This will only crash with libdislocator: %s\n", buf);
    return 0;
  } else if (*(unsigned int*)input == 0xabadcafe)
    printf("GG you eat cmp tokens for breakfast!\n");
  else
    printf("I do not know your string\n");

  return 0;

}
