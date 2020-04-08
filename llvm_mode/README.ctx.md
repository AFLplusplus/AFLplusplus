# AFL Context Sensitive Branch Coverage

## What is this?

This is an LLVM-based implementation of the context sensitive branch coverage.

Basically every function gets it's own ID and that ID is combined with the
edges of the called functions.

So if both function A and function B call a function C, the coverage
collected in C will be different.

In math the coverage is collected as follows:
`map[current_location_ID ^ previous_location_ID >> 1 ^ previous_callee_ID] += 1`

## Usage

Set the `AFL_LLVM_INSTRUMENT=CTX` or `AFL_LLVM_CTX=1` environment variable.

It is highly recommended to increase the MAP_SIZE_POW2 definition in
config.h to at least 18 and maybe up to 20 for this as otherwise too
many map collisions occur.
