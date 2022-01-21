# Unicorn-based binary-only instrumentation for afl-fuzz

The idea and much of the original implementation comes from Nathan Voss
<njvoss299@gmail.com>.

The port to AFL++ is by Dominik Maier <mail@dmnk.co>.

The CompareCoverage and NeverZero counters features are by Andrea Fioraldi
<andreafioraldi@gmail.com>.

## 1) Introduction

The code in [unicorn_mode/](./) allows you to build the
[Unicorn Engine](https://github.com/unicorn-engine/unicorn) with AFL++ support.
This means, you can run anything that can be emulated in unicorn and obtain
instrumentation output for black-box, closed-source binary code snippets. This
mechanism can be then used by afl-fuzz to stress-test targets that couldn't be
built with afl-cc or used in QEMU mode.

There is a significant performance penalty compared to native AFL, but at least
we're able to use AFL++ on these binaries, right?

## 2) How to use

First, you will need a working harness for your target in unicorn, using Python,
C, or Rust.

For some pointers for more advanced emulation, take a look at
[BaseSAFE](https://github.com/fgsect/BaseSAFE) and
[Qiling](https://github.com/qilingframework/qiling).

### Building AFL++'s Unicorn mode

First, make AFL++ as usual. Once that completes successfully, you need to build
and add in the Unicorn mode features:

```
cd unicorn_mode
./build_unicorn_support.sh
```

NOTE: This script checks out a Unicorn Engine fork as submodule that has been
tested and is stable-ish, based on the unicorn engine `next` branch.

Building Unicorn will take a little bit (~5-10 minutes). Once it completes, it
automatically compiles a sample application and verifies that it works.

### Fuzzing with Unicorn mode

To use unicorn-mode effectively, you need to prepare the following:

* Relevant binary code to be fuzzed
* Knowledge of the memory map and good starting state
* Folder containing sample inputs to start fuzzing with
    * Same ideas as any other AFL++ inputs
    * Quality/speed of results will depend greatly on the quality of starting
      samples
    * See AFL's guidance on how to create a sample corpus
* Unicornafl-based test harness in Rust, C, or Python, which:
    * Adds memory map regions
    * Loads binary code into memory
    * Calls uc.afl_fuzz() / uc.afl_start_forkserver
    * Loads and verifies data to fuzz from a command-line specified file
        * AFL++ will provide mutated inputs by changing the file passed to the
          test harness
        * Presumably the data to be fuzzed is at a fixed buffer address
        * If input constraints (size, invalid bytes, etc.) are known, they
          should be checked in the place_input handler. If a constraint fails,
          just return false from the handler. AFL++ will treat the input as
          'uninteresting' and move on.
    * Sets up registers and memory state to start testing
    * Emulates the interesting code from beginning to end
    * If a crash is detected, the test harness must 'crash' by throwing a signal
      (SIGSEGV, SIGKILL, SIGABORT, etc.), or indicate a crash in the crash
      validation callback.

Once you have all those things ready to go, you just need to run afl-fuzz in
`unicorn-mode` by passing in the `-U` flag:

```
afl-fuzz -U -m none -i /path/to/inputs -o /path/to/results -- ./test_harness @@
```

The normal afl-fuzz command line format applies to everything here. Refer to
AFL's main documentation for more info about how to use afl-fuzz effectively.

For a much clearer vision of what all of this looks like, refer to the sample
provided in the [samples/](./samples/) directory. There is also a blog post that
uses slightly older concepts, but describes the general ideas, at:

[https://medium.com/@njvoss299/afl-unicorn-fuzzing-arbitrary-binary-code-563ca28936bf](https://medium.com/@njvoss299/afl-unicorn-fuzzing-arbitrary-binary-code-563ca28936bf)

The [helper_scripts/](./helper_scripts/) directory also contains several helper
scripts that allow you to dump context from a running process, load it, and hook
heap allocations. For details on how to use this, check out the follow-up blog
post to the one linked above:

[https://hackernoon.com/afl-unicorn-part-2-fuzzing-the-unfuzzable-bea8de3540a5](https://hackernoon.com/afl-unicorn-part-2-fuzzing-the-unfuzzable-bea8de3540a5)

An example use of AFL-Unicorn mode is discussed in the paper Unicorefuzz:
[https://www.usenix.org/conference/woot19/presentation/maier](https://www.usenix.org/conference/woot19/presentation/maier)

## 3) Options

As for the QEMU-based instrumentation, unicornafl comes with a sub-instruction
based instrumentation similar in purpose to laf-intel.

The options that enable Unicorn CompareCoverage are the same used for QEMU. This
will split up each multi-byte compare to give feedback for each correct byte:

* `AFL_COMPCOV_LEVEL=1` to instrument comparisons with only immediate values.
* `AFL_COMPCOV_LEVEL=2` to instrument all comparison instructions.

Comparison instructions are currently instrumented only for the x86, x86_64, and
ARM targets.

## 4) Gotchas, feedback, bugs

Running the build script builds unicornafl and its Python bindings and installs
them on your system. This installation will leave any existing Unicorn
installations untouched.

If you want to use unicornafl instead of unicorn in a script, replace all
`unicorn` imports with `unicornafl` inputs, everything else should "just work".
If you use 3rd party code depending on unicorn, you can use unicornafl
monkeypatching. Before importing anything that depends on unicorn, do:

```python
import unicornafl
unicornafl.monkeypatch()
```

This will replace all unicorn imports with unicornafl inputs.

## 5) Examples

Apart from reading the documentation in `afl.c` and the Python bindings of
unicornafl, the best documentation are the [samples/](./samples).

The following examples exist at the time of writing:

- c: A simple example on how to use the C bindings
- compcov_x64: A Python example that uses compcov to traverse hard-to-reach
  blocks
- persistent: A C example using persistent mode for maximum speed, and resetting
  the target state between each iteration
- simple: A simple Python example
- speedtest/c: The C harness for an example target, used to compare C, Python,
  and Rust bindings and fix speed issues
- speedtest/python: Fuzzing the same target in Python
- speedtest/rust: Fuzzing the same target using a Rust harness

Usually, the place to look at is the `harness` in each folder. The source code
in each harness is pretty well documented. Most harnesses also have the
`afl-fuzz` commandline, or even offer a `make fuzz` Makefile target. Targets in
these folders, if x86, can usually be made using `make target` in each folder or
get shipped pre-built (plus their source).

Especially take a look at the
[speedtest documentation](./samples/speedtest/README.md) to see how the
languages compare.