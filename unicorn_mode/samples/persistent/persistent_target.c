/*
 * Sample target file to test afl-unicorn fuzzing capabilities.
 * This is a very trivial example that will crash pretty easily
 * in several different exciting ways. 
 *
 * Input is assumed to come from a buffer located at DATA_ADDRESS 
 * (0x00300000), so make sure that your Unicorn emulation of this 
 * puts user data there.
 *
 * Written by Nathan Voss <njvoss99@gmail.com>
 * Adapted by Lukas Seidel <seidel.1@campus.tu-berlin.de>
 */
#include <stdint.h>
#include <string.h>


int main(int argc, char** argv) {
  if (argc < 2) return -1;

  char *data_buf = argv[1];
  uint64_t data_len = strlen(data_buf);
  if (data_len < 20) return -2;

  for (; data_len --> 0 ;) {
    if (data_len >= 18) continue;
    if (data_len > 2 && data_len < 18) {
      ((char *)data_len)[(uint64_t)data_buf] = data_buf[data_len + 1];
    } else if (data_buf[9] == 0x90 && data_buf[10] != 0x00 && data_buf[11] == 0x90) {
        // Cause a crash if data[10] is not zero, but [9] and [11] are zero
        unsigned char invalid_read = *(unsigned char *) 0x00000000;
    }
  }
  if (data_buf[0] > 0x10 && data_buf[0] < 0x20 && data_buf[1] > data_buf[2]) {
    // Cause an 'invalid read' crash if (0x10 < data[0] < 0x20) and data[1] > data[2]
    unsigned char invalid_read = *(unsigned char *) 0x00000000;
  } 

  return 0;
}
