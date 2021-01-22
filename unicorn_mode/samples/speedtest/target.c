/*
 * Sample target file to test afl-unicorn fuzzing capabilities.
 * This is a very trivial example that will, however, never crash.
 * Crashing would change the execution speed.
 *
 */
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// Random print function we can hook in our harness to test hook speeds.
char magicfn(char to_print) {
  puts("Printing a char, just minding my own business: ");
  putchar(to_print);
  putchar('\n');
  return to_print;
}

int main(int argc, char** argv) {
  if (argc < 2) {
    printf("Gimme input pl0x!\n");
    return -1;
  }
 
  // Make sure the hooks work...
  char *test = malloc(1024);
  if (!test) {
    printf("Uh-Oh, malloc doesn't work!");
    abort();
  }
  free(test);

  char *data_buf = argv[1];
  // We can start the unicorn hooking here.
  uint64_t data_len = strlen(data_buf);
  if (data_len < 20) return -2;

  for (; data_len --> 0 ;) {
    char *buf_cpy = NULL;
    if (data_len) {
      buf_cpy = malloc(data_len);
      if (!buf_cpy) {
        puts("Oof, malloc failed! :/");
        abort();
      }
      memcpy(buf_cpy, data_buf, data_len);
    }
    if (data_len >= 18) {
      free(buf_cpy);
      continue;
    }
    if (data_len > 2 && data_len < 18) {
      buf_cpy[data_len - 1] = (char) 0x90;
    } else if (data_buf[9] == (char) 0x90 && data_buf[10] != 0x00 && buf_cpy[11] == (char) 0x90) {
        // Cause a crash if data[10] is not zero, but [9] and [11] are zero
        unsigned char valid_read = buf_cpy[10];
        if (magicfn(valid_read) != valid_read) {
          puts("Oof, the hook for data_buf[10] is broken?");
          abort();
        }
    }
    free(buf_cpy);
  }
  if (data_buf[0] > 0x10 && data_buf[0] < 0x20 && data_buf[1] > data_buf[2]) {
    // Cause an 'invalid read' crash if (0x10 < data[0] < 0x20) and data[1] > data[2]
    unsigned char valid_read = data_buf[0];
    if (magicfn(valid_read) != valid_read) {
      puts("Oof, the hook for data_buf[0] is broken?");
      abort();
    }
  } 

  magicfn('q');

  return 0;
}
