# BaSFuzz seed weighting

`AFL_BASFUZZ=1` makes afl-fuzz prefer queue entries whose bytes are atypical
for the corpus, based on the idea of BaSFuzz (byte-similarity based seed
selection).

## How it works

For every active queue entry, afl-fuzz looks at its first
`AFL_BASFUZZ_MAX_POS` bytes (default 2048). For each byte position it computes
the fraction of the *other* entries covering that position that have the same
byte value there, and averages this over the positions that at least two
entries cover. The result is a similarity in [0, 1]. It does not depend on the
entry's length.

Entries are ranked by similarity. The least similar entry gets its selection
weight multiplied by `AFL_BASFUZZ_BOOST` (default 2.0), the median entry by 1,
the most similar one by `1 / AFL_BASFUZZ_BOOST`. This factor is applied on
top of the normal AFL++ weighting (exec time, bitmap size, length, depth,
schedule). Favored-but-unfuzzed entries are still fuzzed first.

New, trimmed, disabled and re-enabled entries are picked up incrementally.
Scores are recomputed at most every `AFL_BASFUZZ_INTERVAL` seconds (default
30), and only if the corpus changed.

## Cost

* Memory: `min(max seed length, AFL_BASFUZZ_MAX_POS)` KiB for the histogram
  plus the sum of `min(len, AFL_BASFUZZ_MAX_POS)` over all entries. Shown as
  `basfuzz_mem_kb` in `fuzzer_stats`.
* CPU: one linear pass over the stored prefixes per rescore. Total time is
  shown as `basfuzz_time` (seconds) and the number of rescores as
  `basfuzz_rescores`.

## Differences from the original BaSFuzz

* No external Python process and no TCP connection; everything runs inside
  afl-fuzz.
* The original combined a "byte" and a "structure" similarity. The structure
  term is a linear function of the byte term, so it did not change the
  ranking and is not computed.
* The original zero-padded all seeds to the longest one, so short seeds
  looked similar and long ones rare. Here only real bytes are compared.
* The original dropped seeds larger than 10000 bytes and fuzzed only the 50%
  least-similar seeds, in a fixed order. Here every seed stays selectable and
  the ranking only scales its selection weight. Set a large
  `AFL_BASFUZZ_BOOST` to get close to a hard selection.

## Limitations

* Not active with sequential seed selection (`-Z`, or `-M` which implies it).
* Seeds whose content changes without a length change are not re-scored.
