# KFUZZ
KFUZZ proposes a new seed-saving strategy based on AFL++. In addition to saving mutated inputs that discover new paths or edges into fuzzing queue, we also saving certain high-potential mutated inputs, even if they do not find new paths or edges. The potential of these inputs is determined by their execution paths and the characteristics of their original seeds.

To use this new seed-saving strategy, simply add the `-k` flag when running afl-fuzz. For optimal performance, we recommend using this strategy in combination with `cmplog` mode:

```
  ./afl-fuzz -i seeds_dir -o output_dir -k -c /path/to/program_cmp -- \
  /path/to/tested/program [...program's cmdline...]
```
Note that since this approach may add a significant number of new seeds to the queue, seed selection strategies like AFLFast are not compatible with our seed-saving method.