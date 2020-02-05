# Ideas for afl++

In the following, we describe a variety of ideas that could be implemented for further AFL++ versions.

## Flexible Grammar Mutator

Currently, AFL++'s mutation does not have deeper knowledge about the fuzzed binary, apart from feedback, even though the developer may have insights about the target. A developer may choose to provide dictionaries and implement own mutations in python or c, but an easy mutator that behaves according to a given grammar, does not exist.

## LTO Based Non-Colliding Edge Coverage

An unsolved problem in our fuzzing, right now, are hash collisions between paths. By iterating through all functions at link time, assigning unique values to each branch, therefore reducing or even eliminating collisions, should be possible.

## QEMU 4-based Instrumentation

First tests to use QEMU 4 for binary-only AFL++ showed that caching behavior changed, which vastly decreases fuzzing speeds.
This is the cause why, right now, we cannot switch to QEMU 4.2. Understanding the current instrumentation and fixing the current caching issues will be needed.

## WASM Instrumentation

Currently, AFL++ can be used for source code fuzzing and traditional binaries.
With the rise of WASM as compile target, however, a novel way of instrumentation needs to be implemented for binaries compiled to Webassembly. This can either be done by inserting instrumentation directly into the WASM AST, or by patching feedback into a WASM VMs of choice, similar to the current Unicorn instrumentation.
