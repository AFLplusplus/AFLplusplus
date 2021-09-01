#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

char global_cmpval[] = "GLOBALVARIABLE";

int main(int argc, char **argv) {

  char *input = argv[1], *buf, buffer[20];
  char  cmpval[] = "LOCALVARIABLE";
  char  shortval[4] = "abc";

  if (argc < 2) {

    ssize_t ret = read(0, buffer, sizeof(buffer) - 1);
    buffer[ret] = 0;
    input = buffer;

  }

  if (strcmp(input, "LIBTOKENCAP") == 0)
    printf("your string was LIBTOKENCAP\n");
  else if (strcmp(input, "BUGMENOT") == 0)
    printf("your string was BUGMENOT\n");
  else if (strncmp(input, "BANANA", 3) == 0)
    printf("your string started with BAN\n");
  else if (strcmp(input, "APRI\0COT") == 0)
    printf("your string was APRI\n");
  else if (strcasecmp(input, "Kiwi") == 0)
    printf("your string was Kiwi\n");
  else if (strncasecmp(input, "avocado", 9) == 0)
    printf("your string was avocado\n");
  else if (strncasecmp(input, "Grapes", argc > 2 ? atoi(argv[2]) : 3) == 0)
    printf("your string was a prefix of Grapes\n");
  else if (strstr(input, "tsala") != NULL)
    printf("your string is a fruit salad\n");
  else if (strcmp(input, "BUFFEROVERFLOW") == 0) {

    buf = (char *)malloc(16);
    strcpy(buf, "TEST");
    strcat(buf, input);
    printf("This will only crash with libdislocator: %s\n", buf);

  } else if (*(unsigned int *)input == 0xabadcafe)

    printf("GG you eat cmp tokens for breakfast!\n");
  else if (memcmp(cmpval, input, 8) == 0)
    printf("local var memcmp works!\n");
  else if (memcmp(shortval, input, 4) == 0)
    printf("short local var memcmp works!\n");
  else if (memcmp(global_cmpval, input, sizeof(global_cmpval)) == 0)
    printf("global var memcmp works!\n");
  else if (strncasecmp("-h", input, 2) == 0)
    printf("this is not the help you are looking for\n");
  else
    printf("I do not know your string\n");

  return 0;

}

