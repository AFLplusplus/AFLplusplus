# Custom Mutators

Custom mutators enhance and alter the mutation strategies of AFL++.
For further information and documentation on how to write your own, read [the docs](../docs/custom_mutators.md).

## Examples

The `./examples` folder contains examples for custom mutators in python and C.

## Rust

In `./rust`, you will find rust bindings, including a simple example in `./rust/example` and an example for structured fuzzing, based on lain, in`./rust/example_lain`.

## Production-Ready Custom Mutators

This directory holds ready to use custom mutators.
Just type "make" in the individual subdirectories.

Use with e.g.

`AFL_CUSTOM_MUTATOR_LIBRARY=custom_mutators/radamsa/radamsa-mutator.so afl-fuzz ....`

and add `AFL_CUSTOM_MUTATOR_ONLY=1` if you only want to use the custom mutator.

Multiple custom mutators can be used by separating their paths with `:` in the environment variable.

### The AFL++ grammar agnostic grammar mutator

In `./autotokens` you find a token-level fuzzer that does not need to know
anything about the grammar of an input as long as it is in ascii and allows
whitespace.
It is very fast and effective.

If you are looking for an example of how to effectively create a custom
mutator take a look at this one.

### The AFL++ Grammar Mutator

If you use git to clone AFL++, then the following will incorporate our
excellent grammar custom mutator:

```sh
git submodule update --init
```

Read the README in the [Grammar-Mutator] repository on how to use it.

[Grammar-Mutator]: https://github.com/AFLplusplus/Grammar-Mutator

Note that this custom mutator is not very good though!

### Other Mutators

atnwalk and gramatron are grammar custom mutators. Example grammars are
provided.

honggfuzz, libfuzzer and  libafl are partial implementations based on the
mutator implementations of the respective fuzzers. 
More for playing than serious usage.

radamsa is slow and not very good.

## 3rd Party Custom Mutators

### Superion Mutators

Adrian Tiron ported the Superion grammar fuzzer to AFL++, it is WIP and
requires cmake (among other things):
[https://github.com/adrian-rt/superion-mutator](https://github.com/adrian-rt/superion-mutator)

### libprotobuf Mutators

There are three WIP protobuf projects, that require work to be working though:

ASN.1 example:
[https://github.com/airbus-seclab/AFLplusplus-blogpost/tree/main/src/mutator](https://github.com/airbus-seclab/AFLplusplus-blogpost/tree/main/src/mutator)

transforms protobuf raw:
[https://github.com/bruce30262/libprotobuf-mutator_fuzzing_learning/tree/master/4_libprotobuf_aflpp_custom_mutator](https://github.com/bruce30262/libprotobuf-mutator_fuzzing_learning/tree/master/4_libprotobuf_aflpp_custom_mutator)

has a transform function you need to fill for your protobuf format, however
needs to be ported to the updated AFL++ custom mutator API (not much work):
[https://github.com/thebabush/afl-libprotobuf-mutator](https://github.com/thebabush/afl-libprotobuf-mutator)

same as above but is for current AFL++:
[https://github.com/P1umer/AFLplusplus-protobuf-mutator](https://github.com/P1umer/AFLplusplus-protobuf-mutator)