# custum mutator: honggfuzz mangle

this is the honggfuzz mutator in mangle.c as a custom mutator
module for AFL++. It is the original mangle.c, mangle.h and honggfuzz.h
with a lot of mocking around it :-)

just type `make` to build

```AFL_CUSTOM_MUTATOR_LIBRARY=custom_mutators/honggfuzz/honggfuzz-mutator.so afl-fuzz ...```

> Original repository: https://github.com/google/honggfuzz
> Source commit: d0fbcb0373c32436b8fb922e6937da93b17291f5
