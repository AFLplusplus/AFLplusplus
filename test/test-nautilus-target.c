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

  if (!strstr(buf, "AFL_does_not_know_this_")) {
    if (!strstr(buf, "AFL_does_not_know_this_token_0")) { abort(); }

    if (!strstr(buf, "AFL_does_not_know_this_specific_grammar_magic_string")) {
      abort();
    }
  }

  return 0;
}
