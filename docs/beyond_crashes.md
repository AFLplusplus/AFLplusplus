# Going beyond crashes

Fuzzing is a wonderful and underutilized technique for discovering non-crashing
design and implementation errors, too. Quite a few interesting bugs have been
found by modifying the target programs to call abort() when say:

  - Two bignum libraries produce different outputs when given the same
    fuzzer-generated input,

  - An image library produces different outputs when asked to decode the same
    input image several times in a row,

  - A serialization / deserialization library fails to produce stable outputs
    when iteratively serializing and deserializing fuzzer-supplied data,

  - A compression library produces an output inconsistent with the input file
    when asked to compress and then decompress a particular blob.

Implementing these or similar sanity checks usually takes very little time;
if you are the maintainer of a particular package, you can make this code
conditional with `#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION` (a flag also
shared with libfuzzer and honggfuzz) or `#ifdef __AFL_COMPILER` (this one is
just for AFL).