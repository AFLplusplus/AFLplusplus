# production ready custom mutators

This directory holds ready to use custom mutators.
Just type "make" in the individual subdirectories.

Use with e.g.

`AFL_CUSTOM_MUTATOR_LIBRARY=custom_mutators/radamsa/radamsa-mutator.so afl-fuzz ....`

and add `AFL_CUSTOM_MUTATOR_ONLY=1` if you only want to use the custom mutator.

Multiple custom mutators can be used by seperating their paths with `:` in the environment variable.
