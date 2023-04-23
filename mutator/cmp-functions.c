#include "cmp-functions.h"

#include <math.h>

// CMP attribute enum
enum {

  IS_EQUAL = 1,    // arithemtic equal comparison
  IS_GREATER = 2,  // arithmetic greater comparison
  IS_LESSER = 4,   // arithmetic lesser comparison
  IS_FP = 8,       // is a floating point, not an integer
};

s64 aminusb(u64 a, u64 b) { return a - b; }

s64 bminusa(u64 a, u64 b) { return b - a; }

s64 abs_aminusb(u64 a, u64 b) { return abs(a - b); }

s64 neg_abs_aminusb(u64 a, u64 b) { return -abs(a - b); }


u8 ltez(s64 n){
  return n <= 0;
}

u8 ltz(s64 n){
  return n < 0;
}

u8 ez(s64 n){
  return n == 0;
}

kale_function_info_t kale_get_function_from_type(unsigned attributes) {
  // a <= b
  if (attributes & IS_LESSER && attributes & IS_EQUAL) {
    // f = a - b    f <= 0
    return (kale_function_info_t) {aminusb, ltez};
  }
  // a >= b
  else if (attributes & IS_GREATER && attributes & IS_EQUAL) {
    // f = b - a     f <= 0
    return (kale_function_info_t) {bminusa, ltez};
  }
  // a < b
  else if (attributes & IS_LESSER) {
    // f = a - b     f < 0
    return (kale_function_info_t) {aminusb, ltz};
  }
  // a > b
  else if (attributes & IS_GREATER) {
    // f = b - a     f < 0
    return (kale_function_info_t) {bminusa, ltz};
  }
  // a == b
  else if (attributes & IS_EQUAL) {
    // f = abs(a - b)  f == 0
    return (kale_function_info_t) {abs_aminusb, ez};
  }
  // a != b
  else {
    // f = -abs(a - b) f < 0
    return (kale_function_info_t) {neg_abs_aminusb, ltz};
  }
}