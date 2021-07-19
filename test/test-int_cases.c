/* test cases for integer comparison transformations
 * compile with -DINT_TYPE="signed char"
 *          or  -DINT_TYPE="short"
 *          or  -DINT_TYPE="int"
 *          or  -DINT_TYPE="long"
 *          or  -DINT_TYPE="long long"
 */

#include <assert.h>

int main() {

  volatile INT_TYPE a, b;
  /* different values */
  a = -21;
  b = -2;                                                    /* signs equal */
  assert((a < b));
  assert((a <= b));
  assert(!(a > b));
  assert(!(a >= b));
  assert((a != b));
  assert(!(a == b));

  a = 1;
  b = 8;                                                     /* signs equal */
  assert((a < b));
  assert((a <= b));
  assert(!(a > b));
  assert(!(a >= b));
  assert((a != b));
  assert(!(a == b));

  if ((unsigned)(INT_TYPE)(~0) > 255) {                  /* short or bigger */
    volatile short a, b;
    a = 2;
    b = 256 + 1;                                             /* signs equal */
    assert((a < b));
    assert((a <= b));
    assert(!(a > b));
    assert(!(a >= b));
    assert((a != b));
    assert(!(a == b));

    a = -1 - 256;
    b = -8;                                                  /* signs equal */
    assert((a < b));
    assert((a <= b));
    assert(!(a > b));
    assert(!(a >= b));
    assert((a != b));
    assert(!(a == b));

    if ((unsigned)(INT_TYPE)(~0) > 65535) {                /* int or bigger */
      volatile int a, b;
      a = 2;
      b = 65536 + 1;                                         /* signs equal */
      assert((a < b));
      assert((a <= b));
      assert(!(a > b));
      assert(!(a >= b));
      assert((a != b));
      assert(!(a == b));

      a = -1 - 65536;
      b = -8;                                                /* signs equal */
      assert((a < b));
      assert((a <= b));
      assert(!(a > b));
      assert(!(a >= b));
      assert((a != b));
      assert(!(a == b));

      if ((unsigned)(INT_TYPE)(~0) > 4294967295) {        /* long or bigger */
        volatile long a, b;
        a = 2;
        b = 4294967296 + 1;                                  /* signs equal */
        assert((a < b));
        assert((a <= b));
        assert(!(a > b));
        assert(!(a >= b));
        assert((a != b));
        assert(!(a == b));

        a = -1 - 4294967296;
        b = -8;                                              /* signs equal */
        assert((a < b));
        assert((a <= b));
        assert(!(a > b));
        assert(!(a >= b));
        assert((a != b));
        assert(!(a == b));

      }

    }

  }

  a = -1;
  b = 1;                                                    /* signs differ */
  assert((a < b));
  assert((a <= b));
  assert(!(a > b));
  assert(!(a >= b));
  assert((a != b));
  assert(!(a == b));

  a = -1;
  b = 0;                                                    /* signs differ */
  assert((a < b));
  assert((a <= b));
  assert(!(a > b));
  assert(!(a >= b));
  assert((a != b));
  assert(!(a == b));

  a = -2;
  b = 8;                                                    /* signs differ */
  assert((a < b));
  assert((a <= b));
  assert(!(a > b));
  assert(!(a >= b));
  assert((a != b));
  assert(!(a == b));

  a = -1;
  b = -2;                                                    /* signs equal */
  assert((a > b));
  assert((a >= b));
  assert(!(a < b));
  assert(!(a <= b));
  assert((a != b));
  assert(!(a == b));

  a = 8;
  b = 1;                                                     /* signs equal */
  assert((a > b));
  assert((a >= b));
  assert(!(a < b));
  assert(!(a <= b));
  assert((a != b));
  assert(!(a == b));

  if ((unsigned)(INT_TYPE)(~0) > 255) {

    volatile short a, b;
    a = 1 + 256;
    b = 3;                                                   /* signs equal */
    assert((a > b));
    assert((a >= b));
    assert(!(a < b));
    assert(!(a <= b));
    assert((a != b));
    assert(!(a == b));

    a = -1;
    b = -256;                                                /* signs equal */
    assert((a > b));
    assert((a >= b));
    assert(!(a < b));
    assert(!(a <= b));
    assert((a != b));
    assert(!(a == b));

    if ((unsigned)(INT_TYPE)(~0) > 65535) {

      volatile int a, b;
      a = 1 + 65536;
      b = 3;                                                 /* signs equal */
      assert((a > b));
      assert((a >= b));
      assert(!(a < b));
      assert(!(a <= b));
      assert((a != b));
      assert(!(a == b));

      a = -1;
      b = -65536;                                            /* signs equal */
      assert((a > b));
      assert((a >= b));
      assert(!(a < b));
      assert(!(a <= b));
      assert((a != b));
      assert(!(a == b));

      if ((unsigned)(INT_TYPE)(~0) > 4294967295) {

        volatile long a, b;
        a = 1 + 4294967296;
        b = 3;                                               /* signs equal */
        assert((a > b));
        assert((a >= b));
        assert(!(a < b));
        assert(!(a <= b));
        assert((a != b));
        assert(!(a == b));

        a = -1;
        b = -4294967296;                                     /* signs equal */
        assert((a > b));
        assert((a >= b));
        assert(!(a < b));
        assert(!(a <= b));
        assert((a != b));
        assert(!(a == b));

      }

    }

  }

  a = 1;
  b = -1;                                                   /* signs differ */
  assert((a > b));
  assert((a >= b));
  assert(!(a < b));
  assert(!(a <= b));
  assert((a != b));
  assert(!(a == b));

  a = 0;
  b = -1;                                                   /* signs differ */
  assert((a > b));
  assert((a >= b));
  assert(!(a < b));
  assert(!(a <= b));
  assert((a != b));
  assert(!(a == b));

  a = 8;
  b = -2;                                                   /* signs differ */
  assert((a > b));
  assert((a >= b));
  assert(!(a < b));
  assert(!(a <= b));
  assert((a != b));
  assert(!(a == b));

  a = 1;
  b = -2;                                                   /* signs differ */
  assert((a > b));
  assert((a >= b));
  assert(!(a < b));
  assert(!(a <= b));
  assert((a != b));
  assert(!(a == b));

  if ((unsigned)(INT_TYPE)(~0) > 255) {

    volatile short a, b;
    a = 1 + 256;
    b = -2;                                                 /* signs differ */
    assert((a > b));
    assert((a >= b));
    assert(!(a < b));
    assert(!(a <= b));
    assert((a != b));
    assert(!(a == b));

    a = -1;
    b = -2 - 256;                                           /* signs differ */
    assert((a > b));
    assert((a >= b));
    assert(!(a < b));
    assert(!(a <= b));
    assert((a != b));
    assert(!(a == b));

    if ((unsigned)(INT_TYPE)(~0) > 65535) {

      volatile int a, b;
      a = 1 + 65536;
      b = -2;                                               /* signs differ */
      assert((a > b));
      assert((a >= b));
      assert(!(a < b));
      assert(!(a <= b));
      assert((a != b));
      assert(!(a == b));

      a = -1;
      b = -2 - 65536;                                       /* signs differ */
      assert((a > b));
      assert((a >= b));
      assert(!(a < b));
      assert(!(a <= b));
      assert((a != b));
      assert(!(a == b));

      if ((unsigned)(INT_TYPE)(~0) > 4294967295) {

        volatile long a, b;
        a = 1 + 4294967296;
        b = -2;                                             /* signs differ */
        assert((a > b));
        assert((a >= b));
        assert(!(a < b));
        assert(!(a <= b));
        assert((a != b));
        assert(!(a == b));

        a = -1;
        b = -2 - 4294967296;                                /* signs differ */
        assert((a > b));
        assert((a >= b));
        assert(!(a < b));
        assert(!(a <= b));
        assert((a != b));
        assert(!(a == b));

      }

    }

  }

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

  a = 5;
  b = 5;
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

  a = -5;
  b = -5;
  assert(!(a < b));
  assert((a <= b));
  assert(!(a > b));
  assert((a >= b));
  assert(!(a != b));
  assert((a == b));

  if ((unsigned)(INT_TYPE)(~0) > 255) {

    volatile short a, b;
    a = 1 + 256;
    b = 1 + 256;
    assert(!(a < b));
    assert((a <= b));
    assert(!(a > b));
    assert((a >= b));
    assert(!(a != b));
    assert((a == b));

    a = -2 - 256;
    b = -2 - 256;
    assert(!(a < b));
    assert((a <= b));
    assert(!(a > b));
    assert((a >= b));
    assert(!(a != b));
    assert((a == b));

    if ((unsigned)(INT_TYPE)(~0) > 65535) {

      volatile int a, b;
      a = 1 + 65536;
      b = 1 + 65536;
      assert(!(a < b));
      assert((a <= b));
      assert(!(a > b));
      assert((a >= b));
      assert(!(a != b));
      assert((a == b));

      a = -2 - 65536;
      b = -2 - 65536;
      assert(!(a < b));
      assert((a <= b));
      assert(!(a > b));
      assert((a >= b));
      assert(!(a != b));
      assert((a == b));

      if ((unsigned)(INT_TYPE)(~0) > 4294967295) {

        volatile long a, b;
        a = 1 + 4294967296;
        b = 1 + 4294967296;
        assert(!(a < b));
        assert((a <= b));
        assert(!(a > b));
        assert((a >= b));
        assert(!(a != b));
        assert((a == b));

        a = -2 - 4294967296;
        b = -2 - 4294967296;
        assert(!(a < b));
        assert((a <= b));
        assert(!(a > b));
        assert((a >= b));
        assert(!(a != b));
        assert((a == b));

      }

    }

  }

}

