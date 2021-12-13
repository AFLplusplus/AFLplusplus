# laf-intel instrumentation

## Introduction

This originally is the work of an individual nicknamed laf-intel. His blog
[Circumventing Fuzzing Roadblocks with Compiler Transformations](https://lafintel.wordpress.com/)
and GitLab repo [laf-llvm-pass](https://gitlab.com/laf-intel/laf-llvm-pass/)
describe some code transformations that help AFL++ to enter conditional blocks,
where conditions consist of comparisons of large values.

## Usage

By default, these passes will not run when you compile programs using
afl-clang-fast. Hence, you can use AFL++ as usual. To enable the passes, you
must set environment variables before you compile the target project.

The following options exist:

`export AFL_LLVM_LAF_SPLIT_SWITCHES=1`

Enables the split-switches pass.

`export AFL_LLVM_LAF_TRANSFORM_COMPARES=1`

Enables the transform-compares pass (strcmp, memcmp, strncmp, strcasecmp,
strncasecmp).

`export AFL_LLVM_LAF_SPLIT_COMPARES=1`

Enables the split-compares pass. By default, it will
1. simplify operators >= (and <=) into chains of > (<) and == comparisons
2. change signed integer comparisons to a chain of sign-only comparison and
   unsigned integer comparisons
3. split all unsigned integer comparisons with bit widths of 64, 32, or 16 bits
   to chains of 8 bits comparisons.

You can change the behavior of the last step by setting `export
AFL_LLVM_LAF_SPLIT_COMPARES_BITW=<bit_width>`, where bit_width may be 64, 32, or
16. For example, a bit_width of 16 would split larger comparisons down to 16 bit
comparisons.

A new unique feature is splitting floating point comparisons into a series
of sign, exponent and mantissa comparisons followed by splitting each of them
into 8 bit comparisons when necessary. It is activated with the
`AFL_LLVM_LAF_SPLIT_FLOATS` setting.

Note that setting this automatically activates `AFL_LLVM_LAF_SPLIT_COMPARES`.

You can also set `AFL_LLVM_LAF_ALL` and have all of the above enabled. :-)
