# afl-compiler-fuzzer custom mutators

This is a port of [afl-compiler-fuzzer](https://github.com/agroce/afl-compiler-fuzzer)
to AFL++ custom mutators. afl-compiler-fuzzer is a variant of AFL 2.56b for
fuzzing compilers, interpreters, and other tools that take C-like source code as
input (C, C++, Java, JavaScript, Rust, Solidity, Move, Zig, Fe, Promela, ...).
It has found many bugs in the Solidity compiler and others; see
[Making No-Fuss Compiler Fuzzing Effective](https://agroce.github.io/cc22.pdf)
(Groce, van Tonder, Kalburgi, Le Goues, CC 2022).

The idea is to use mutation-testing operators (operator replacement, statement
deletion, argument swapping, loop insertion, ...) as havoc mutations. Mutants
of valid programs tend to stay valid (or close to valid), so the fuzzer spends
its time past the parser, without needing a grammar or a big dictionary.

Two mutators are provided:

| Library               | Original option    | What it does                                                     |
|-----------------------|--------------------|------------------------------------------------------------------|
| `compiler-mutator.so` | `afl-fuzz-compiler -1 N` | Built-in string-based source mutations (64 operators)       |
| `comby-mutator.so`    | `afl-fuzz-compiler -2 N` | Asks a [comby-decomposer](https://github.com/comby-tools/comby-decomposer) server to transform the input |

Both work like the original: each stacked havoc step is, with the configured
probability, a source-level mutation; otherwise, or if no source-level
mutation applies (or the server returns nothing), the step is a normal AFL++
havoc operation (from `afl-mutations.h`, text mode, with splicing).

## Build

```sh
make
```

`make test` runs a short smoke test (needs `afl-fuzz` and `afl-cc` built in
the AFL++ root).

## Usage

To reproduce `afl-fuzz-compiler` (havoc with source mutations replaces the
AFL++ mutation stages):

```sh
AFL_CUSTOM_MUTATOR_ONLY=1 \
AFL_CUSTOM_MUTATOR_LIBRARY=/path/to/custom_mutators/compiler_fuzzer/compiler-mutator.so \
afl-fuzz -i seeds -o out -- ./solc @@
```

Without `AFL_CUSTOM_MUTATOR_ONLY`, AFL++ runs its own stages in addition to
the custom one, which is also a reasonable configuration.

Seeds should be real, valid programs, e.g. the target's own test suite.
Since mutants tend to be larger than what trimming finds necessary for
coverage, you may want to try `AFL_DISABLE_TRIM=1` as well.

### comby-decomposer

Generate templates and fragments and start the server as described in the
[comby-decomposer README](https://github.com/comby-tools/comby-decomposer#on-demand-input-generation)
(default port 4448), then:

```sh
AFL_CUSTOM_MUTATOR_ONLY=1 \
AFL_CUSTOM_MUTATOR_LIBRARY=/path/to/comby-mutator.so \
afl-fuzz -i seeds -o out -- ./target @@
```

The original allowed both kinds of mutation at once (`-1 75 -2 10`); with
AFL++, load both libraries (`AFL_CUSTOM_MUTATOR_LIBRARY="a.so;b.so"`), and
each gets its own custom mutation stage.

If the server is not reachable, the mutator warns at startup and its requests
fall back to havoc until the server is up.

## Environment variables

| Variable               | Default     | Meaning (original equivalent)                                  |
|------------------------|-------------|----------------------------------------------------------------|
| `ACF_MUTATION_PROB`    | 75          | % of stacked steps trying a source mutation (`-1`, `AFL_P_C_STRING_MUTATION`) |
| `ACF_COMBY_PROB`       | 25          | % of stacked steps that query the server (`-2`, `AFL_P_COMBY_SERVER`) |
| `ACF_COMBY_HOST`       | 127.0.0.1   | comby-decomposer server host (was fixed to localhost)          |
| `ACF_COMBY_PORT`       | 4448        | comby-decomposer server port (`-p`, `AFL_COMBY_SERVER_PORT`)    |
| `ACF_COMBY_TIMEOUT_MS` | 2000        | per-request socket timeout                                      |
| `ACF_STACK_POW2`       | AFL++ (4)   | stacked steps per input are 2^(1..N); AFL 2.56b used 7          |

## The source mutations

On each attempt a random position and one of 64 operators are picked; the
operator is applied at the first match at or after that position. Up to 16
attempts are made before falling back to havoc.

* Replacements at the first occurrence: `==`/`!=`/`<`/`>`/`=` swaps,
  arithmetic operator swaps among `+ - * / %`, `++`/`--`, `&&`/`||`,
  `0`/`1`, `if`/`while`, `(` to `(!`, deleting `!`.
* Statement-level insertions after a newline: `if (0==1)` (semantic
  deletion of the next statement), `while(1==1)`, `break;`, `continue;`.
* Delimiter-based deletion: a statement after `;` or `}`, a `{...}` block
  (or emptying it), a line, a space- or newline-delimited token such as
  `const`.
* Delimiter-based swaps: adjacent statements, comma-separated arguments,
  space-separated tokens.
* Duplication of a line, or of a construct ending in `}` (e.g. a loop).

Delimiter matches are textual (not nesting-aware) and bounded to 1024 bytes,
as in the original.

## Differences from afl-compiler-fuzzer

* Fixed: `while` to `if` fell through to the `while(1==1)` insertion, so it
  never happened (and the insertion was twice as likely as intended).
* Fixed: the two duplication operators replaced text with itself, a no-op.
  They now duplicate.
* Fixed: a delimiter operator that found no match could silently re-apply the
  previous attempt's operator; now it just counts as a failed attempt.
* Inputs are handled as length-delimited buffers (the original used
  `strnstr`, which stopped at NUL bytes and could read past the buffer).
* comby: the last byte of the input is no longer dropped from requests, the
  response body is located by its header terminator rather than by assuming 8
  header lines, and a missing server no longer exits the fuzzer.
* The fallback havoc is AFL++'s (text-mode operators, AFL++ stacking depth),
  and the scheduling is AFL++'s, so runs are not identical to AFL 2.56b ones.
