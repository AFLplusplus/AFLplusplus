#include <stdint.h>
#include <stddef.h>

static unsigned char afl_area_dummy[8];
unsigned char       *__afl_area_ptr = afl_area_dummy;

void __sanitizer_cov_trace_pc_guard(uint32_t *guard) {

  (void)guard;

}

void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop) {

  (void)start;
  (void)stop;

}

void __valueprofile_hook1(uint8_t arg1, uint8_t arg2, uint8_t attr,
                          uint64_t site_token) {

  (void)arg1;
  (void)arg2;
  (void)attr;
  (void)site_token;

}

void __valueprofile_hook2(uint16_t arg1, uint16_t arg2, uint8_t attr,
                          uint64_t site_token) {

  (void)arg1;
  (void)arg2;
  (void)attr;
  (void)site_token;

}

void __valueprofile_hook4(uint32_t arg1, uint32_t arg2, uint8_t attr,
                          uint64_t site_token) {

  (void)arg1;
  (void)arg2;
  (void)attr;
  (void)site_token;

}

void __valueprofile_hook8(uint64_t arg1, uint64_t arg2, uint8_t attr,
                          uint64_t site_token) {

  (void)arg1;
  (void)arg2;
  (void)attr;
  (void)site_token;

}

#ifdef __SIZEOF_INT128__
void __valueprofile_hook16(__uint128_t arg1, __uint128_t arg2, uint8_t attr,
                           uint64_t site_token) {

  (void)arg1;
  (void)arg2;
  (void)attr;
  (void)site_token;

}

void __valueprofile_hookN(__uint128_t arg1, __uint128_t arg2, uint8_t attr,
                          uint8_t bits_minus_1, uint64_t site_token) {

  (void)arg1;
  (void)arg2;
  (void)attr;
  (void)bits_minus_1;
  (void)site_token;

}

#endif

void __valueprofile_switch(uint64_t val, uint64_t *cases, uint64_t site_token) {

  (void)val;
  (void)cases;
  (void)site_token;

}

void __valueprofile_rtn_hook_n(uint8_t *ptr1, uint8_t *ptr2, uint64_t len,
                               uint64_t site_token) {

  (void)ptr1;
  (void)ptr2;
  (void)len;
  (void)site_token;

}

void __valueprofile_rtn_hook_strn(uint8_t *ptr1, uint8_t *ptr2, uint64_t len,
                                  uint64_t site_token) {

  (void)ptr1;
  (void)ptr2;
  (void)len;
  (void)site_token;

}

void __valueprofile_rtn_hook_str(uint8_t *ptr1, uint8_t *ptr2,
                                 uint64_t site_token) {

  (void)ptr1;
  (void)ptr2;
  (void)site_token;

}

void __valueprofile_rtn_hook(uint8_t *ptr1, uint8_t *ptr2,
                             uint64_t site_token) {

  (void)ptr1;
  (void)ptr2;
  (void)site_token;

}

