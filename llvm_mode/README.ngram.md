# AFL N-Gram Branch Coverage

## Source

This is an LLVM-based implementation of the n-gram branch coverage proposed in
the paper ["Be Sensitive and Collaborative: Analzying Impact of Coverage Metrics
in Greybox Fuzzing"](https://www.usenix.org/system/files/raid2019-wang-jinghan.pdf),
by Jinghan Wang, et. al.

Note that the original implementation (available
[here](https://github.com/bitsecurerlab/afl-sensitive))
is built on top of AFL's QEMU mode.
This is essentially a port that uses LLVM vectorized instructions to achieve
the same results when compiling source code.

## Usage

The size of `n` (i.e., the number of branches to remember) is an option
that is specified in the `AFL_LLVM_NGRAM_SIZE` environment variable.
Good values are 2, 4 or 8.
