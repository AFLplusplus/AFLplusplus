/*
 * Sample target file to test afl-unicorn fuzzing capabilities.
 * This is a very trivial example that will crash pretty easily
 * in several different exciting ways. 
 *
 * Input is assumed to come from a buffer located at DATA_ADDRESS 
 * (0x00300000), so make sure that your Unicorn emulation of this 
 * puts user data there.
 *
 * Written by Andrea Fioraldi
 */

// Magic address where mutated data will be placed
#define DATA_ADDRESS 	0x00300000

int main(void) {
  unsigned int *data_buf = (unsigned int *) DATA_ADDRESS;

  if (((unsigned short*)data_buf)[0] == 0x0100) {
    unsigned char invalid_read = *(unsigned char *) 0x00000000;
  } else if (data_buf[1] == data_buf[2] + 0xfffe) {
    unsigned char invalid_read = *(unsigned char *) 0x00000000;
  }

  return 0;
}
