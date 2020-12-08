#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/types.h>

/* This is an example target for defork.c - fuzz using
```
mkdir in; echo a > ./in/a
AFL_PRELOAD=./defork64.so ../../afl-fuzz -i in -o out -- ./forking_target @@
```
*/

int main(int argc, char **argv) {

  if (argc < 2) {

    printf("Example tool to test defork.\nUsage ./forking_target <input>\n");
    return -1;

  }

  pid_t pid = fork();
  if (pid == 0) {

    printf("We're in the child.\n");
    FILE *f = fopen(argv[1], "r");
    char  buf[4096];
    fread(buf, 1, 4096, f);
    fclose(f);
    uint32_t offset = buf[100] + (buf[101] << 8);
    char     test_val = buf[offset];
    return test_val < 100;

  } else if (pid < 0) {

    perror("fork");
    return -1;

  } else {

    printf("We are in the parent - defork didn't work! :( (pid=%d)\n",
           (int)pid);

  }

  return 0;

}

