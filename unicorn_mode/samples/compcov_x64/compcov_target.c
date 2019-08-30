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

  if (data_buf[0] == 0xabadcafe) {
    // Cause an 'invalid read' crash if data[0..3] == '\x01\x02\x03\x04'
    unsigned char invalid_read = *(unsigned char *) 0x00000000;
  } else if (data_buf[1] == data_buf[2] + 0x4141) {
    // Cause an 'invalid read' crash if (0x10 < data[0] < 0x20) and data[1] > data[2]
    unsigned char invalid_read = *(unsigned char *) 0x00000000;
  }

  return 0;
}
