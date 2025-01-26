# SAND: Decoupling Sanitization from Fuzzing for Low Overhead

- Authors: Ziqiao Kong, Shaohua Li, Heqing Huang, Zhendong Su
- Maintainer: [Ziqiao Kong](https://github.com/wtdcode)
- Preprint: [arXiv](https://arxiv.org/abs/2402.16497), accepted by ICSE 2025
- Main repo (for paper, reproduction, reference or cite): https://github.com/wtdcode/sand-aflpp

## Motivation

SAND introduces a new fuzzing workflow that can greatly reduce (or even eliminate) sanitizer overhead and combine different sanitizers in one fuzzing compaign.

The key point of SAND is that: sanitizing all inputs is wasting fuzzing power, because bug-triggering inputs are extremely rare (~1%). Obviously, not all inputs worth going through sanitizers. There, if we can somehow "predict" if an input could trigger bugs (defined as "execution pattern"), we could greatly save fuzzing power by only sanitizing a small proportion of all inputs. That's exactly how SAND works.

## Usage

For a normal fuzzing workflow, we have:

1. Build target project with AFL_USE_ASAN=1 to get `target_asan`
2. Fuzz the target with `afl-fuzz -i seeds -o out -- ./target_asan`

For SAND fuzzing workflow, this is slightly different:

1. Build target project _without_ any sanitizers to get `target_native`, which we will define as "native binary".
2. Build target project with AFL_USE_ASAN=1 AFL_SAN_NO_INST=1 to get `target_asan`
3. Fuzz the target with `afl-fuzz -i seeds -o out -w ./target_asan -- ./target_native`

Then you get:

- almost the same performance as `afl-fuzz -i seeds -o out -- ./target_native`
- and the same bug-finding capability as `afl-fuzz -i seeds -o out -- ./target_asan`

## Tips

### Alternative execution patterns

By default, SAND use the hash value of the simplified coverage map as execution pattern, i.e. if an input has a unique execution pattern, it will be sent to sanitizers for inspection. This shall work for most cases. However, if you are strongly worried about missing bugs, try `AFL_SAN_ABSTRACTION=unique_trace afl-fuzz ...`. Alternatively, you can also have `AFL_SAN_ABSTRACTION=coverage_increase`, which essentially equals to running sanitizers on the corpus.

### Run as many sanitizers as possible

Though we just used ASAN as an example, SAND works best if you provide more sanitizers, for example, UBSAN and MSAN.

You might do it via `afl-fuzz -i seeds -o out -w ./target_asan -w ./target_msan -w ./target_ubsan -- ./target_native`. Don't worry about the slow sanitizers like MSAN, SAND could still run very fast because only rather a few inputs are sanitized.

### Bugs types

The execution pattern evaluated in our papers is targeting the common bugs, as ASAN/MSAN/UBSAN catches. For other bug types, you probably need to define new execution patterns and re-evaluate.

### My throughput is greatly impacted

Generally, this is due to too many inputs going through sanitizers, for example, because of unstable targets. You could check stats from `plot_file` to confirm this. Try to switch execution patterns as stated above.

### Cmplog Compatibility

At this moment, SAND probably is not compatible with cmplog and we will fix this soon.

