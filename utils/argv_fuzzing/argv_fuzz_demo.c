#include <stdio.h>
#include <string.h>
#include "argv-fuzz-inl.h"

int main(int argc, char **argv) {

  // Initialize the argv array for use with the AFL (American Fuzzy Lop) tool
  AFL_INIT_ARGV();

  /* Check the number of command line arguments and
    compare the values of the first two arguments to specific strings.
    If the number of arguments is not correct or the values do not match,
    an error message is printed. If the values do match, the program
    calls the abort() function. */
  if (argc > 1 && strcmp(argv[1], "XYZ") == 0) {

    if (strcmp(argv[2], "TEST2") == 0) { abort(); }

  } else {

    printf("Bad number of arguments!\n");

  }

  return 0;

}

