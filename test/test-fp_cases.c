/* test cases for floating point comparison transformations
 * compile with -DFLOAT_TYPE=float
 *          or  -DFLOAT_TYPE=double
 *          or  -DFLOAT_TYPE="long double"
 */

#include <assert.h>

int main() {

  volatile FLOAT_TYPE a, b;
  /* different values */
  a = -2.1;
  b = -2;                             /* signs equal, exp equal, mantissa > */
  assert((a < b));
  assert((a <= b));
  assert(!(a > b));
  assert(!(a >= b));
  assert((a != b));
  assert(!(a == b));

  a = 1.8;
  b = 2.1;                           /* signs equal, exp differ, mantissa > */
  assert((a < b));
  assert((a <= b));
  assert(!(a > b));
  assert(!(a >= b));
  assert((a != b));
  assert(!(a == b));

  a = 2;
  b = 2.1;                            /* signs equal, exp equal, mantissa < */
  assert((a < b));
  assert((a <= b));
  assert(!(a > b));
  assert(!(a >= b));
  assert((a != b));
  assert(!(a == b));

  a = -2;
  b = -1.8;                          /* signs equal, exp differ, mantissa < */
  assert((a < b));
  assert((a <= b));
  assert(!(a > b));
  assert(!(a >= b));
  assert((a != b));
  assert(!(a == b));

  a = -1;
  b = 1;                         /* signs differ, exp equal, mantissa equal */
  assert((a < b));
  assert((a <= b));
  assert(!(a > b));
  assert(!(a >= b));
  assert((a != b));
  assert(!(a == b));

  a = -1;
  b = 0;                        /* signs differ, exp differ, mantissa equal */
  assert((a < b));
  assert((a <= b));
  assert(!(a > b));
  assert(!(a >= b));
  assert((a != b));
  assert(!(a == b));

  a = -2;
  b = 2.8;                           /* signs differ, exp equal, mantissa < */
  assert((a < b));
  assert((a <= b));
  assert(!(a > b));
  assert(!(a >= b));
  assert((a != b));
  assert(!(a == b));

  a = -2;
  b = 1.8;                          /* signs differ, exp differ, mantissa < */
  assert((a < b));
  assert((a <= b));
  assert(!(a > b));
  assert(!(a >= b));
  assert((a != b));
  assert(!(a == b));

  a = -2;
  b = -2.1;                           /* signs equal, exp equal, mantissa > */
  assert((a > b));
  assert((a >= b));
  assert(!(a < b));
  assert(!(a <= b));
  assert((a != b));
  assert(!(a == b));

  a = 2.1;
  b = 1.8;                           /* signs equal, exp differ, mantissa > */
  assert((a > b));
  assert((a >= b));
  assert(!(a < b));
  assert(!(a <= b));
  assert((a != b));
  assert(!(a == b));

  a = 2.1;
  b = 2;                              /* signs equal, exp equal, mantissa < */
  assert((a > b));
  assert((a >= b));
  assert(!(a < b));
  assert(!(a <= b));
  assert((a != b));
  assert(!(a == b));

  a = -1.8;
  b = -2;                            /* signs equal, exp differ, mantissa < */
  assert((a > b));
  assert((a >= b));
  assert(!(a < b));
  assert(!(a <= b));
  assert((a != b));
  assert(!(a == b));

  a = 1;
  b = -1;                        /* signs differ, exp equal, mantissa equal */
  assert((a > b));
  assert((a >= b));
  assert(!(a < b));
  assert(!(a <= b));
  assert((a != b));
  assert(!(a == b));

  a = 0;
  b = -1;                       /* signs differ, exp differ, mantissa equal */
  assert((a > b));
  assert((a >= b));
  assert(!(a < b));
  assert(!(a <= b));
  assert((a != b));
  assert(!(a == b));

  a = 2.8;
  b = -2;                            /* signs differ, exp equal, mantissa < */
  assert((a > b));
  assert((a >= b));
  assert(!(a < b));
  assert(!(a <= b));
  assert((a != b));
  assert(!(a == b));

  a = 1.8;
  b = -2;                           /* signs differ, exp differ, mantissa < */
  assert((a > b));
  assert((a >= b));
  assert(!(a < b));
  assert(!(a <= b));
  assert((a != b));
  assert(!(a == b));

  /* equal values */
  a = 0;
  b = 0;
  assert(!(a < b));
  assert((a <= b));
  assert(!(a > b));
  assert((a >= b));
  assert(!(a != b));
  assert((a == b));

  a = -0;
  b = 0;
  assert(!(a < b));
  assert((a <= b));
  assert(!(a > b));
  assert((a >= b));
  assert(!(a != b));
  assert((a == b));

  a = 1;
  b = 1;
  assert(!(a < b));
  assert((a <= b));
  assert(!(a > b));
  assert((a >= b));
  assert(!(a != b));
  assert((a == b));

  a = 0.5;
  b = 0.5;
  assert(!(a < b));
  assert((a <= b));
  assert(!(a > b));
  assert((a >= b));
  assert(!(a != b));
  assert((a == b));

  a = -1;
  b = -1;
  assert(!(a < b));
  assert((a <= b));
  assert(!(a > b));
  assert((a >= b));
  assert(!(a != b));
  assert((a == b));

  a = -0.5;
  b = -0.5;
  assert(!(a < b));
  assert((a <= b));
  assert(!(a > b));
  assert((a >= b));
  assert(!(a != b));
  assert((a == b));

}

