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
#include <string.h>

int main(int argc, char** argv) {
  if(argc < 2){
     return -1;
  }

  char *data_buf = argv[1];

  if (strlen(data_buf) >= 21 && data_buf[20] != 0) {
    printf("Not crashing");
  } else if (strlen(data_buf) > 1
             && data_buf[0] > 0x10 && data_buf[0] < 0x20 && data_buf[1] > data_buf[2]) {
    printf("Also not crashing with databuf[0] == %c", data_buf[0])
  }
#if 0
  // not possible with argv (zero terminated strings) (hexcoder-)
  // do not try to access data_buf[10] and beyond
  else if (data_buf[9] == 0x00 && data_buf[10] != 0x00 && data_buf[11] == 0x00) {
    // Cause a crash if data[10] is not zero, but [9] and [11] are zero
    unsigned char invalid_read = *(unsigned char *) 0x00000000;
  }
#endif
  return 0;
}
