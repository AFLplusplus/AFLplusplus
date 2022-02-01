# custum mutator: libafl basic havoc mutator

This uses the libafl StdScheduledMutator with `havoc_mutations` and `token_mutations`.

Make sure to have [cargo installed](https://rustup.rs/) and just type `make` to build.

Run with:

```AFL_CUSTOM_MUTATOR_LIBRARY=custom_mutators/libafl_base/libafl_base.so afl-fuzz ...```
```
