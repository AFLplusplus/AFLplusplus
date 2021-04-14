# afl++ drivers

## aflpp_driver

aflpp_driver is used to compile directly libfuzzer `LLVMFuzzerTestOneInput()`
targets.

Just do `afl-clang-fast++ -o fuzz fuzzer_harness.cc libAFLDriver.a [plus required linking]`.

You can also sneakily do this little trick: 
If this is the clang compile command to build for libfuzzer:
  `clang++ -o fuzz -fsanitize=fuzzer fuzzer_harness.cc -lfoo`
then just switch `clang++` with `afl-clang-fast++` and our compiler will
magically insert libAFLDriver.a :)


## aflpp_qemu_driver

aflpp_qemu_driver is used for libfuzzer `LLVMFuzzerTestOneInput()` targets that
are to be fuzzed in qemu_mode. So we compile them with clang/clang++, without
-fsantize=fuzzer or afl-clang-fast, and link in libAFLQemuDriver.a:

`clang++ -o fuzz fuzzer_harness.cc libAFLQemuDriver.a [plus required linking]`.


Then just do (where the name of the binary is `fuzz`):
```
AFL_QEMU_PERSISTENT_ADDR=0x$(nm fuzz | grep "T LLVMFuzzerTestOneInput" | awk '{print $1}')
AFL_QEMU_PERSISTENT_HOOK=/path/to/aflpp_qemu_driver_hook.so afl-fuzz -Q ... -- ./fuzz`
```
