# custum mutator: libfuzzer LLVMFuzzerMutate()

This uses the libfuzzer LLVMFuzzerMutate() function in llvm 12.

just type `make` to build

```AFL_CUSTOM_MUTATOR_LIBRARY=custom_mutators/libfuzzer/libfuzzer-mutator.so afl-fuzz ...```

Note that this is currently a simple implementation and it is missing two features:
  * Splicing ("Crossover")
  * Dictionary support

To update the source, all that is needed is that FuzzerDriver.cpp has to receive
```
#include "libfuzzer.inc"
```
before the closing namespace bracket.

It is also libfuzzer.inc where the configuration of the libfuzzer mutations
are done.

> Original repository: https://github.com/llvm/llvm-project
> Path: compiler-rt/lib/fuzzer/*.{h|cpp}
> Source commit: df3e903655e2499968fc7af64fb5fa52b2ee79bb
