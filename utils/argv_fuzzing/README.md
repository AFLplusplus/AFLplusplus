# argv_fuzzing feature
AFL++ supports fuzzing file inputs or standard input. The argv_fuzzing feature
allows for the fuzzing of arguments passed to a program from the command line
interface rather than from STDIN.  

## With source code
When the source code is available, a specific macro from the `argv-fuzz-inl.h`
header file can be used to change the program's behavior to build argv from STDIN.

### Without persistent mode
Conditions needed to use the argv_fuzzing feature:
1. Include `argv-fuzz-inl.h` header file (`#include "argv-fuzz-inl.h"`)
2. Identify your main function that parses arguments
(for example, `int main(int argc, char **argv)`)
3. Use one of the following macros (near the beginning of the main function)
to initialize argv with the fuzzer's input:
   - `AFL_INIT_ARGV();` or
   - `AFL_INIT_SET0("prog_name");` to preserve `argv[0]`
   (the name of the program being executed)
   
see: [argv_fuzz_demo.c](argv_fuzz_demo.c)

### With persistent mode
Conditions needed to use the argv_fuzzing feature with persistent mode:
1. Ensure your target can handle persistent mode fuzzing
2. Follow instructions in the [llvm_mode persistent mode](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.persistent_mode.md)
3. Use one of the following macros near the beginning of the main function and after 
the buffer initialization (`unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF`):
   - `AFL_INIT_ARGV_PERSISTENT(buf)`, if you want to 
   - `AFL_INIT_SET0_PERSISTENT("name_of_binary", buf)`

see: [argv_fuzz_persistent_demo.c](argv_fuzz_persistent_demo.c)

## Binary only
`argvfuzz` tries to provide the same functionality for binaries. When loaded
using `LD_PRELOAD`, it will hook the call to `__libc_start_main` and replace
argv using the same logic of `argv-fuzz-inl.h`.

A few conditions need to be fulfilled for this mechanism to work correctly:

1. As it relies on hooking the loader, it cannot work on static binaries
2. If the target binary does not use the default libc's `_start` implementation
   (crt1.o), the hook may not run.
3. The hook will replace argv with pointers to `.data` of `argvfuzz.so`.
Things may go wrong if the target binary expects argv to live on the stack.
