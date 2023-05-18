# custum mutator: symqemu

This uses the symcc to find new paths into the target.

To use this custom mutator follow the steps in the symqemu repository 
[https://github.com/eurecom-s3/symqemu/](https://github.com/eurecom-s3/symqemu/) 
on how to build symqemu-x86_x64 and put it in your `PATH`.

just type `make` to build this custom mutator.

```AFL_CUSTOM_MUTATOR_LIBRARY=custom_mutators/symqemu/symqemu-mutator.so AFL_DISABLE_TRIM=1 afl-fuzz ...```
