# Adding custom mutators to AFL

This file describes how you can implement custom mutations to be used in AFL.

Implemented by Khaled Yakdan from Code Intelligence <yakdan@code-intelligence.de>

## 1) Description

Custom mutator libraries can be passed to afl-fuzz to perform custom mutations
on test cases beyond those available in AFL - for example, to enable structure-aware
fuzzing by using libraries that perform mutations according to a given grammar.

The custom mutator library is passed to afl-fuzz via the AFL_CUSTOM_MUTATOR_LIBRARY
environment variable. The library must export the afl_custom_mutator() function and
must be compiled as a shared object. For example:
     $CC -shared -Wall -O3 <lib-name>.c -o <lib-name>.so

Note: unless AFL_CUSTOM_MUTATOR_ONLY is set, its state mutator like any others,
so it will be used for some test cases, and other mutators for others.

Only if AFL_CUSTOM_MUTATOR_ONLY is set the afl_custom_mutator() function will
be called every time it needs to mutate test case!

For some cases, the format of the mutated data returned from
the custom mutator is not suitable to directly execute the target with this input.
For example, when using libprotobuf-mutator, the data returned is in a protobuf
format which corresponds to a given grammar. In order to execute the target,
the protobuf data must be converted to the plain-text format expected by the target.
In such scenarios, the user can define the afl_pre_save_handler() function. This function
is then transforms the data into the format expected by the API before executing the target.
afl_pre_save_handler is optional and does not have to be implemented if its functionality
is not needed.

## 2) Example

A simple example is provided in ../examples/custom_mutators/
