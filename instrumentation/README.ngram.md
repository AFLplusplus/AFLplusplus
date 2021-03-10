# AFL N-Gram Branch Coverage

## Source

This is an LLVM-based implementation of the n-gram branch coverage proposed in
the paper ["Be Sensitive and Collaborative: Analzying Impact of Coverage Metrics
in Greybox Fuzzing"](https://www.usenix.org/system/files/raid2019-wang-jinghan.pdf),
by Jinghan Wang, et. al.

Note that the original implementation (available
[here](https://github.com/bitsecurerlab/afl-sensitive))
is built on top of AFL's QEMU mode.
This is essentially a port that uses LLVM vectorized instructions (available from
llvm versions 4.0.1 and higher) to achieve the same results when compiling source code.

In math the branch coverage is performed as follows:
`map[current_location ^ prev_location[0] >> 1 ^ prev_location[1] >> 1 ^ ... up to n-1`] += 1`

## Usage

The size of `n` (i.e., the number of branches to remember) is an option
that is specified either in the `AFL_LLVM_INSTRUMENT=NGRAM-{value}` or the
`AFL_LLVM_NGRAM_SIZE` environment variable.
Good values are 2, 4 or 8, valid are 2-16.

It is highly recommended to increase the MAP_SIZE_POW2 definition in
config.h to at least 18 and maybe up to 20 for this as otherwise too
many map collisions occur.
