# Unicorn-based binary-only instrumentation for afl-fuzz

The idea and much of the original implementation comes from Nathan Voss <njvoss299@gmail.com>.

The port to afl++ is by Dominik Maier <mail@dmnk.co>.

The CompareCoverage and NeverZero counters features are by Andrea Fioraldi <andreafioraldi@gmail.com>.

## 1) Introduction

The code in ./unicorn_mode allows you to build a standalone feature that
leverages the Unicorn Engine and allows callers to obtain instrumentation 
output for black-box, closed-source binary code snippets. This mechanism 
can be then used by afl-fuzz to stress-test targets that couldn't be built 
with afl-gcc or used in QEMU mode, or with other extensions such as 
TriforceAFL.

There is a significant performance penalty compared to native AFL,
but at least we're able to use AFL++ on these binaries, right?

## 2) How to use

Requirements: you need an installed python environment.

### Building AFL++'s Unicorn Mode

First, make afl++ as usual.
Once that completes successfully you need to build and add in the Unicorn Mode 
features:

```
$ cd unicorn_mode
$ ./build_unicorn_support.sh
```

NOTE: This script checks out a Unicorn Engine fork as submodule that has been tested 
and is stable-ish, based on the unicorn engine master. 

Building Unicorn will take a little bit (~5-10 minutes). Once it completes 
it automatically compiles a sample application and verifies that it works.

### Fuzzing with Unicorn Mode

To really use unicorn-mode effectively you need to prepare the following:

	* Relevant binary code to be fuzzed
	* Knowledge of the memory map and good starting state
	* Folder containing sample inputs to start fuzzing with
		+ Same ideas as any other AFL inputs
		+ Quality/speed of results will depend greatly on quality of starting 
		  samples
		+ See AFL's guidance on how to create a sample corpus
	* Unicornafl-based test harness which:
		+ Adds memory map regions
		+ Loads binary code into memory		
		+ Calls uc.afl_fuzz() / uc.afl_start_forkserver
		+ Loads and verifies data to fuzz from a command-line specified file
			+ AFL will provide mutated inputs by changing the file passed to 
			  the test harness
			+ Presumably the data to be fuzzed is at a fixed buffer address
			+ If input constraints (size, invalid bytes, etc.) are known they 
			  should be checked after the file is loaded. If a constraint 
			  fails, just exit the test harness. AFL will treat the input as 
			  'uninteresting' and move on.
		+ Sets up registers and memory state for beginning of test
		+ Emulates the interested code from beginning to end
		+ If a crash is detected, the test harness must 'crash' by 
		  throwing a signal (SIGSEGV, SIGKILL, SIGABORT, etc.)

Once you have all those things ready to go you just need to run afl-fuzz in
'unicorn-mode' by passing in the '-U' flag:

```
$ afl-fuzz -U -m none -i /path/to/inputs -o /path/to/results -- ./test_harness @@
```

The normal afl-fuzz command line format applies to everything here. Refer to
AFL's main documentation for more info about how to use afl-fuzz effectively.

For a much clearer vision of what all of this looks like, please refer to the
sample provided in the 'unicorn_mode/samples' directory. There is also a blog
post that goes over the basics at:

[https://medium.com/@njvoss299/afl-unicorn-fuzzing-arbitrary-binary-code-563ca28936bf](https://medium.com/@njvoss299/afl-unicorn-fuzzing-arbitrary-binary-code-563ca28936bf)

The 'helper_scripts' directory also contains several helper scripts that allow you 
to dump context from a running process, load it, and hook heap allocations. For details
on how to use this check out the follow-up blog post to the one linked above.

A example use of AFL-Unicorn mode is discussed in the paper Unicorefuzz:
[https://www.usenix.org/conference/woot19/presentation/maier](https://www.usenix.org/conference/woot19/presentation/maier)

## 3) Options

As for the QEMU-based instrumentation, the afl-unicorn twist of afl++
comes with a sub-instruction based instrumentation similar in purpose to laf-intel.

The options that enable Unicorn CompareCoverage are the same used for QEMU.
AFL_COMPCOV_LEVEL=1 is to instrument comparisons with only immediate values.

AFL_COMPCOV_LEVEL=2 instruments all comparison instructions.

Comparison instructions are currently instrumented only for the x86, x86_64 and ARM targets.

## 4) Gotchas, feedback, bugs

Running the build script builds Unicornafl and its python bindings and installs 
them on your system. 
This installation will leave any existing Unicorn installations untouched.
If you want to use unicornafl instead of unicorn in a script,
replace all `unicorn` imports with `unicornafl` inputs, everything else should "just work".
If you use 3rd party code depending on unicorn, you can use unicornafl monkeypatching:
Before importing anything that depends on unicorn, do:

```python
import unicornafl
unicornafl.monkeypatch()
```

This will replace all unicorn imports with unicornafl inputs.

Refer to the [samples/arm_example/arm_tester.c](samples/arm_example/arm_tester.c) for an example
of how to do this properly! If you don't get this right, AFL will not 
load any mutated inputs and your fuzzing will be useless!
