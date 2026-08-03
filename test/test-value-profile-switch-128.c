#include <stdint.h>

#ifdef __SIZEOF_INT128__

__attribute__((noinline)) static int run_switch(unsigned __int128 value) {

  switch (value) {

    case (((unsigned __int128)1) << 96) + 0x1234u:
      return 1;
    case (((unsigned __int128)1) << 96) + 0x5678u:
      return 2;
    case (((unsigned __int128)1) << 100) + 0x9abcu:
      return 3;
    default:
      return 0;

  }

}

int main(void) {

  volatile unsigned __int128 value = (((unsigned __int128)1) << 96) + 0x1111u;
  return run_switch(value);

}

#else

int main(void) {

  return 0;

}

#endif

