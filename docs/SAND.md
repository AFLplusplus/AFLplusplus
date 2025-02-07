# SAND: Decoupling Sanitization from Fuzzing for Low Overhead

- Authors: Ziqiao Kong, Shaohua Li, Heqing Huang, Zhendong Su
- Maintainer: [Ziqiao Kong](https://github.com/wtdcode)
- Preprint: [arXiv](https://arxiv.org/abs/2402.16497), accepted by ICSE 2025
- Main repo (for paper, reproduction, reference or cite): https://github.com/wtdcode/sand-aflpp

## Motivation

SAND introduces a new fuzzing workflow that can greatly reduce (or even eliminate) sanitizer overhead and combine different sanitizers in one fuzzing campaign.

The key point of SAND is that: sanitizing all inputs is wasting fuzzing power, because bug-triggering inputs are extremely rare (~1%). Obviously, not all inputs worth going through sanitizers. Therefore, if we can somehow "predict" if an input could trigger bugs (defined as "execution pattern"), we could greatly save fuzzing power by only sanitizing a small proportion of all inputs. That's exactly how SAND works.

## Usage

For a normal fuzzing workflow, we have:

1. Build target project with AFL_USE_ASAN=1 to get `target_asan`
2. Fuzz the target with `afl-fuzz -i seeds -o out -- ./target_asan`

For SAND fuzzing workflow, this is slightly different:

1. Build target project _without_ any sanitizers to get `target_native`, which we will define as a "native binary". It is usually done by using `afl-clang-fast/lto(++)` to compile your project _without_ `AFL_USE_ASAN/UBSAN/MSAN`.
2. Build target project with AFL_USE_ASAN=1 AFL_SAN_NO_INST=1 to get `target_asan`. Do note this step can be repeated for multiple sanitizers, like MSAN, UBSAN etc. It is also possible to have ASAN and UBSAN to build together.
3. Fuzz the target with `afl-fuzz -i seeds -o out -w ./target_asan -- ./target_native`. Note `-w` can be specified multiple times.

Then you get:

- almost the same performance as `afl-fuzz -i seeds -o out -- ./target_native`
- and the same bug-finding capability as `afl-fuzz -i seeds -o out -- ./target_asan`

## Example Workflow

Take [test-instr.c](../test-instr.c) as an example.

1. Build the native binary

```bash
afl-clang-fast test-instr.c -o ./native
```

Just like the normal building process, except using `afl-clang-fast`

2. Build the sanitizers-enabled binaries.

```bash
AFL_SAN_NO_INST=1 AFL_USE_UBSAN=1 AFL_USE_ASAN=1 afl-clang-fast test-instr.c -o ./asanubsan
AFL_SAN_NO_INST=1 AFL_USE_MSAN=1 afl-clang-fast test-instr.c -o ./msan
```

Do note `AFL_SAN_NO_INST=1` is crucial, this enables forkservers but disables pc instrumentation. Do not reuse sanitizers-enabled binaries built _without_ `AFL_SAN_NO_INST=1`. This will mess up SAND execution pattern.

3. Start fuzzing

```bash
mkdir /tmp/test
echo "a" > /tmp/test/a
AFL_NO_UI=1 AFL_SKIP_CPUFREQ=1 afl-fuzz -i /tmp/test -o /tmp/out -w ./asanubsan -w ./msan -- ./native @@
```

That's it!

## Tips

### Alternative execution patterns

By default, SAND uses the hash value of the simplified coverage map as execution pattern, i.e. if an input has a unique simplefied coverage map, it will be sent to sanitizers for inspection. This shall work for most cases. However, if you are strongly worried about missing bugs, try `AFL_SAN_ABSTRACTION=unique_trace afl-fuzz ...`, which filters inputs having a _unique coverage map_. Do note this significantly increases the number of inputs by 4-10 times, leading to much lower throughput. Alternatively, SAND also supports `AFL_SAN_ABSTRACTION=coverage_increase`, which essentially equals to running sanitizers on the corpus and thus having almost zero overhead, but at a cost of missing ~15% bugs in our evaluation.

### Run as many sanitizers as possible

Though we just used ASAN as an example, SAND works best if you provide more sanitizers, for example, UBSAN and MSAN.

You might do it via `afl-fuzz -i seeds -o out -w ./target_asan -w ./target_msan -w ./target_ubsan -- ./target_native`. Don't worry about the slow sanitizers like MSAN, SAND could still run very fast because only rather a few inputs are sanitized.

### Bugs types

The execution pattern evaluated in our papers is targeting the common bugs, as ASAN/MSAN/UBSAN catches. For other bug types, you probably need to define new execution patterns and re-evaluate.

### My throughput is greatly impacted

Generally, this is due to too many inputs going through sanitizers, for example, because of unstable targets. You could check stats from `plot_file` to confirm this. Try to switch execution patterns as stated above.