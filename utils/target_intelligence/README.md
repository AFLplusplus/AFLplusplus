# Target Intelligence

These are some ideas you can do so that your target that you are fuzzing can
give helpful feedback to AFL++.

## Add to the AFL++ dictionary from your target

For this you target must be compiled for CMPLOG (`AFL_LLVM_CMPLOG=1`).

Add in your source code:

```
__attribute__((weak)) void __cmplog_rtn_hook_strn(u8 *ptr1, u8 *ptr2, u64 len);
__attribute__((weak)) void __cmplog_ins_hook1(uint8_t arg1, uint8_t arg2, uint8_t attr);
__attribute__((weak)) void __cmplog_ins_hook2(uint16_t arg1, uint16_t arg2, uint8_t attr);
__attribute__((weak)) void __cmplog_ins_hook4(uint32_t arg1, uint32_t arg2, uint8_t attr);
__attribute__((weak)) void __cmplog_ins_hook8(uint64_t arg1, uint64_t arg2, uint8_t attr);

int in_your_function(...) {

  // to add two strings to the AFL++ dictionary:
  if (__cmplog_rtn_hook_strn)
    __cmplog_rtn_hook_strn(string1, length_of_string1, string2, length_of_string2);

  // to add two 32 bit integers to the AFL++ dictionary:
  if (__cmplog_ins_hook4)
    __cmplog_ins_hook4(first_32_bit_var, second_32_bit_var, 0);

}
```

Note that this only makes sense if these values are in-depth processed in the
target in a way that AFL++ CMPLOG cannot uncover these, e.g. if these values
are transformed by a matrix computation.

Fixed values are always better to give to afl-fuzz via a `-x dictionary`.

## Add inputs to AFL++ dictionary from your target

If for whatever reason you want your target to propose new inputs to AFL++,
then this is actually very easy.
The environment variable `AFL_CUSTOM_INFO_OUT` contains the output directory
of this run - including the fuzzer instance name (e.g. `default`), so if you
run `afl-fuzz -o out -S foobar`, the value would be `out/foobar`).

To show afl-fuzz an input it should consider just do the following:

1. create the directory `$AFL_CUSTOM_INFO_OUT/../target/queue`
2. create any new inputs you want afl-fuzz to notice in that directory with the
   following naming convention: `id:NUMBER-OF-LENGTH-SIX-WITH-LEADING-ZEROES,whatever`
   where that number has to be increasing.
   e.g.:
```
   id:000000,first_file
   id:000001,second_file
   id:000002,third_file
   etc.
```

Note that this will not work in nyx_mode because afl-fuzz cannot see inside the
virtual machine.
