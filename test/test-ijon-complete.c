#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

// Simple program that uses IJON macros to create context-aware coverage
// Tests all major IJON macros when compiled with AFL++:
//   - IJON_STATE: State-aware coverage (changes global state affecting all
//   coverage)
//   - IJON_MAX:   Maximum value tracking (variadic macro)
//   - IJON_MIN:   Minimum value tracking (variadic macro)
//   - IJON_SET:   Set specific values for tracking (single parameter)
//   - IJON_INC:   Increment coverage counters (single parameter)
int main(int argc, char **argv) {

  char input[256];
  int  state = 0;

  printf("IJON Test Program - reading from stdin\n");

  // Read input
  if (read(STDIN_FILENO, input, sizeof(input) - 1) <= 0) {

    input[0] = 'A';  // Default input
    input[1] = '\0';

  }

  printf("Input: %c (0x%02x)\n", input[0], (unsigned char)input[0]);

  // Test different execution paths with IJON state tracking
  if (input[0] >= 'A' && input[0] <= 'Z') {

    state = 1;
#ifdef _USE_IJON
    IJON_STATE(
        state);  // State-aware coverage - makes each path context-dependent
#endif
    printf("Path 1: Uppercase letter (state=%d)\n", state);

    if (input[0] == 'A') {

      state = 11;
#ifdef _USE_IJON
      IJON_STATE(state);
      IJON_MAX(state);  // Track maximum state value seen
      IJON_SET(65);     // Set specific value for letter A (ASCII 65)
#endif
      printf("Path 1A: Letter A (state=%d)\n", state);

    } else if (input[0] == 'Z') {

      state = 12;
#ifdef _USE_IJON
      IJON_STATE(state);
      IJON_MAX(state);  // Track maximum state value seen
      IJON_MIN(state);  // Track minimum state value seen
      IJON_SET(90);     // Set specific value for letter Z (ASCII 90)
#endif
      printf("Path 1Z: Letter Z (state=%d)\n", state);

    }

  } else if (input[0] >= 'a' && input[0] <= 'z') {

    state = 2;
#ifdef _USE_IJON
    IJON_STATE(state);
#endif
    printf("Path 2: Lowercase letter (state=%d)\n", state);

    if (input[0] == 'x') {

      state = 21;
#ifdef _USE_IJON
      IJON_STATE(state);
      IJON_INC(state);  // Increment coverage for this specific path
      IJON_SET(120);    // Set specific value for letter x (ASCII 120)
      IJON_MIN(state);  // Track minimum for this path
#endif
      printf("Path 2X: Letter x (state=%d)\n", state);

    }

  } else if (input[0] >= '0' && input[0] <= '9') {

    state = 3;
#ifdef _USE_IJON
    IJON_STATE(state);
#endif
    printf("Path 3: Digit (state=%d)\n", state);

    if (input[0] == '5') {

      state = 31;
#ifdef _USE_IJON
      IJON_STATE(state);
      IJON_MAX(state * 10);  // Track some derived value
      IJON_SET(53);          // Set specific value for digit 5 (ASCII 53)
      IJON_MIN(state / 2);   // Track minimum of derived value
#endif
      printf("Path 3-5: Digit 5 (state=%d)\n", state);

    }

  } else {

    state = 4;
#ifdef _USE_IJON
    IJON_STATE(state);
    IJON_INC(1);                        // Simple increment for this path
    IJON_SET((unsigned char)input[0]);  // Set the actual ASCII value
    IJON_MAX(state * 100);              // Track large derived value
    IJON_MIN(1);                        // Track minimum baseline
#endif
    printf("Path 4: Other character (state=%d)\n", state);

  }

  printf("Final state: %d\n", state);
  return 0;

}

