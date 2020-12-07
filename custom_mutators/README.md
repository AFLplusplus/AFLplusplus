# Custom Mutators

Custom mutators enhance and alter the mutation strategies of afl++.
For further information and documentation on how to write your own, read [the docs](../docs/custom_mutators.md).

## The afl++ Grammar Mutator

If you use git to clone afl++, then the following will incorporate our
excellent grammar custom mutator:
```sh
git submodule update --init
```

Read the README in the [Grammar-Mutator] repository on how to use it.

[Grammar-Mutator]: https://github.com/AFLplusplus/Grammar-Mutator

## Production-Ready Custom Mutators

This directory holds ready to use custom mutators.
Just type "make" in the individual subdirectories.

Use with e.g.

`AFL_CUSTOM_MUTATOR_LIBRARY=custom_mutators/radamsa/radamsa-mutator.so afl-fuzz ....`

and add `AFL_CUSTOM_MUTATOR_ONLY=1` if you only want to use the custom mutator.

Multiple custom mutators can be used by separating their paths with `:` in the environment variable.

## 3rd Party Custom Mutators

### Superion Mutators

Adrian Tiron ported the Superion grammar fuzzer to afl++, it is WIP and
requires cmake (among other things):
[https://github.com/adrian-rt/superion-mutator](https://github.com/adrian-rt/superion-mutator)

### libprotobuf Mutators

There are two WIP protobuf projects, that require work to be working though:

transforms protobuf raw:
https://github.com/bruce30262/libprotobuf-mutator_fuzzing_learning/tree/master/4_libprotobuf_aflpp_custom_mutator

has a transform function you need to fill for your protobuf format, however
needs to be ported to the updated afl++ custom mutator API (not much work):
https://github.com/thebabush/afl-libprotobuf-mutator
