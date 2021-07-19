/*
 * compile with -DINT_TYPE="char"
 *          or  -DINT_TYPE="short"
 *          or  -DINT_TYPE="int"
 *          or  -DINT_TYPE="long"
 *          or  -DINT_TYPE="long long"
 */

#include <assert.h>

int main() {

  volatile unsigned INT_TYPE a, b;

  a = 1;
  b = 8;
  assert((a < b));
  assert((a <= b));
  assert(!(a > b));
  assert(!(a >= b));
  assert((a != b));
  assert(!(a == b));

  if ((INT_TYPE)(~0) > 255) {

    volatile unsigned short a, b;
    a = 256 + 2;
    b = 256 + 21;
    assert((a < b));
    assert((a <= b));
    assert(!(a > b));
    assert(!(a >= b));
    assert((a != b));
    assert(!(a == b));

    a = 21;
    b = 256 + 1;
    assert((a < b));
    assert((a <= b));
    assert(!(a > b));
    assert(!(a >= b));
    assert((a != b));
    assert(!(a == b));

    if ((INT_TYPE)(~0) > 65535) {

      volatile unsigned int a, b;
      a = 65536 + 2;
      b = 65536 + 21;
      assert((a < b));
      assert((a <= b));
      assert(!(a > b));
      assert(!(a >= b));
      assert((a != b));
      assert(!(a == b));

      a = 21;
      b = 65536 + 1;
      assert((a < b));
      assert((a <= b));
      assert(!(a > b));
      assert(!(a >= b));
      assert((a != b));
      assert(!(a == b));

    }

    if ((INT_TYPE)(~0) > 4294967295) {

      volatile unsigned long a, b;
      a = 4294967296 + 2;
      b = 4294967296 + 21;
      assert((a < b));
      assert((a <= b));
      assert(!(a > b));
      assert(!(a >= b));
      assert((a != b));
      assert(!(a == b));

      a = 21;
      b = 4294967296 + 1;
      assert((a < b));
      assert((a <= b));
      assert(!(a > b));
      assert(!(a >= b));
      assert((a != b));
      assert(!(a == b));

    }

  }

  a = 8;
  b = 1;
  assert((a > b));
  assert((a >= b));
  assert(!(a < b));
  assert(!(a <= b));
  assert((a != b));
  assert(!(a == b));

  if ((INT_TYPE)(~0) > 255) {

    volatile unsigned short a, b;
    a = 256 + 2;
    b = 256 + 1;
    assert((a > b));
    assert((a >= b));
    assert(!(a < b));
    assert(!(a <= b));
    assert((a != b));
    assert(!(a == b));

    a = 256 + 2;
    b = 6;
    assert((a > b));
    assert((a >= b));
    assert(!(a < b));
    assert(!(a <= b));
    assert((a != b));
    assert(!(a == b));

    if ((INT_TYPE)(~0) > 65535) {

      volatile unsigned int a, b;
      a = 65536 + 2;
      b = 65536 + 1;
      assert((a > b));
      assert((a >= b));
      assert(!(a < b));
      assert(!(a <= b));
      assert((a != b));
      assert(!(a == b));

      a = 65536 + 2;
      b = 6;
      assert((a > b));
      assert((a >= b));
      assert(!(a < b));
      assert(!(a <= b));
      assert((a != b));
      assert(!(a == b));

      if ((INT_TYPE)(~0) > 4294967295) {

        volatile unsigned long a, b;
        a = 4294967296 + 2;
        b = 4294967296 + 1;
        assert((a > b));
        assert((a >= b));
        assert(!(a < b));
        assert(!(a <= b));
        assert((a != b));
        assert(!(a == b));

        a = 4294967296 + 2;
        b = 6;
        assert((a > b));
        assert((a >= b));
        assert(!(a < b));
        assert(!(a <= b));
        assert((a != b));
        assert(!(a == b));

      }

    }

  }

  a = 0;
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

  if ((INT_TYPE)(~0) > 255) {

    volatile unsigned short a, b;
    a = 256 + 5;
    b = 256 + 5;
    assert(!(a < b));
    assert((a <= b));
    assert(!(a > b));
    assert((a >= b));
    assert(!(a != b));
    assert((a == b));

    if ((INT_TYPE)(~0) > 65535) {

      volatile unsigned int a, b;
      a = 65536 + 5;
      b = 65536 + 5;
      assert(!(a < b));
      assert((a <= b));
      assert(!(a > b));
      assert((a >= b));
      assert(!(a != b));
      assert((a == b));

      if ((INT_TYPE)(~0) > 4294967295) {

        volatile unsigned long a, b;
        a = 4294967296 + 5;
        b = 4294967296 + 5;
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

