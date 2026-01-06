#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char **argv) {
  char    buf[4096];
  ssize_t len = read(0, buf, 4096);
  if (len < 0) return 0;
  // Ensure null termination for strstr
  if (len == 4096)
    buf[4095] = 0;
  else
    buf[len] = 0;

  if (strstr(buf, "Nautilus_Token_1")) {
      // ensure we save this to corpus
      asm("");
  }

  if (strstr(buf, "Nautilus_Token_0")) {
    abort();
  }

  if (strstr(buf, "Nautilus_Grammar_Crash")) {
    abort();
  }

  return 0;
}
