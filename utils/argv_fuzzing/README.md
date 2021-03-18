# argvfuzz

afl supports fuzzing file inputs or stdin. When source is available,
`argv-fuzz-inl.h` can be used to change `main()` to build argv from stdin.

`argvfuzz` tries to provide the same functionality for binaries. When loaded
using `LD_PRELOAD`, it will hook the call to `__libc_start_main` and replace
argv using the same logic of `argv-fuzz-inl.h`.

A few conditions need to be fulfilled for this mechanism to work correctly:

1. As it relies on hooking the loader, it cannot work on static binaries.
2. If the target binary does not use the default libc's `_start` implementation
   (crt1.o), the hook may not run.
3. The hook will replace argv with pointers to `.data` of `argvfuzz.so`. If the
   target binary expects argv to be living on the stack, things may go wrong.
