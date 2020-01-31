# CmpLog instrumentation

The CmpLog instrumentation enables the logging of the comparisons operands in a
shared memory.

These values can be used by various mutators built on top of it.
At the moment we support the RedQueen mutator (input-2-state instructions only).

## Build

To use CmpLog, you have to build two versions of the instrumented target
program.

The first version is built using the regular AFL++ instrumentation.

The second one, the CmpLog binary, with setting AFL_LLVM_CMPLOG during the compilation.

For example:

```
./configure --cc=~/path/to/afl-clang-fast
make
cp ./program ./program.afl
make clean
export AFL_LLVM_CMPLOG=1
./configure --cc=~/path/to/afl-clang-fast
make
cp ./program ./program.cmplog
```

## Use

AFL++ has the new -c option that can be used to specify a CmpLog binary (the second
build).

For example:

```
afl-fuzz -i input -o output -c ./program.cmplog -m none -- ./program.afl @@
```

Be careful to use -m none because CmpLog maps a lot of pages.
