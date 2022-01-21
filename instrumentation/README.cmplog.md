# CmpLog instrumentation

The CmpLog instrumentation enables logging of comparison operands in a shared
memory.

These values can be used by various mutators built on top of it. At the moment,
we support the Redqueen mutator (input-2-state instructions only), for details
see [the Redqueen paper](https://github.com/RUB-SysSec/redqueen).

## Build

To use CmpLog, you have to build two versions of the instrumented target
program:

* The first version is built using the regular AFL++ instrumentation.
* The second one, the CmpLog binary, is built with setting `AFL_LLVM_CMPLOG`
  during the compilation.

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
unset AFL_LLVM_CMPLOG
```

## Use

AFL++ has the new `-c` option that needs to be used to specify the CmpLog binary
(the second build).

For example:

```
afl-fuzz -i input -o output -c ./program.cmplog -m none -- ./program.afl @@
```

Be careful with the usage of `-m` because CmpLog can map a lot of pages.
