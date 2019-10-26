# laf-intel instrumentation

## Usage

By default these passes will not run when you compile programs using 
afl-clang-fast. Hence, you can use AFL as usual.
To enable the passes you must set environment variables before you
compile the target project.

The following options exist:

`export AFL_LLVM_LAF_SPLIT_SWITCHES=1`

Enables the split-switches pass.

`export AFL_LLVM_LAF_TRANSFORM_COMPARES=1`

Enables the transform-compares pass (strcmp, memcmp, strncmp,
strcasecmp, strncasecmp).

`export AFL_LLVM_LAF_SPLIT_COMPARES=1`

Enables the split-compares pass.
By default it will 
1. simplify operators >= (and <=) into chains of > (<) and == comparisons
2. change signed integer comparisons to a chain of sign-only comparison
and unsigned comparisons
3. split all unsigned integer comparisons with bit widths of
64, 32 or 16 bits to chains of 8 bits comparisons.

You can change the behaviour of the last step by setting
`export AFL_LLVM_LAF_SPLIT_COMPARES_BITW=<bit_width>`, where 
bit_width may be 64, 32 or 16.

A new experimental feature is splitting floating point comparisons into a
series of sign, exponent and mantissa comparisons followed by splitting each
of them into 8 bit comparisons when necessary.
It is activated with the `AFL_LLVM_LAF_SPLIT_FLOATS` setting, available only
when `AFL_LLVM_LAF_SPLIT_COMPARES` is set.
