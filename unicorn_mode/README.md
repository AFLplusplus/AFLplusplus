# Unicorn-based binary-only instrumentation for afl-fuzz

The idea and much of the original implementation comes from Nathan Voss <njvoss299@gmail.com>.

The port to afl++ if by Dominik Maier <mail@dmnk.co>.

The CompareCoverage and NeverZero counters features by Andrea Fioraldi <andreafioraldi@gmail.com>.

## 1) Introduction

The code in ./unicorn_mode allows you to build a standalone feature that
leverages the Unicorn Engine and allows callers to obtain instrumentation 
output for black-box, closed-source binary code snippets. This mechanism 
can be then used by afl-fuzz to stress-test targets that couldn't be built 
with afl-gcc or used in QEMU mode, or with other extensions such as 
TriforceAFL.

There is a performance penalty compared to native AFL,
but at least we're able to use AFL on these binaries, right?

## 2) How to use

Requirements: you need an installed python environment.
Fuzzing in C should also be possible, however is currently untested.

### Building AFL's Unicorn Mode

First, make afl++ as usual.
Once that completes successfully you need to build and add in the Unicorn Mode 
features:

```bash
  $ cd unicorn_mode
  $ ./build_unicorn_support.sh
```

NOTE: This script downloads a Unicorn Engine commit that has been tested 
and is stable-ish from the Unicorn github page. If you are offline, you'll need 
to hack up this script a little bit and supply your own copy of Unicorn's latest 
stable release. It's not very hard, just check out the beginning of the 
build_unicorn_support.sh script and adjust as necessary.

Building Unicorn will take a little bit (~5-10 minutes). Once it completes 
it automatically compiles a sample application and verify that it works.

### Fuzzing with Unicorn Mode

To really use unicorn-mode effectively you need to prepare the following:

	* Relevant binary code to be fuzzed
	* Knowledge of the memory map and good starting state
	* Folder containing sample inputs to start fuzzing with
		+ Same ideas as any other AFL inputs
		+ Quality/speed of results will depend greatly on quality of starting 
		  samples
		+ See AFL's guidance on how to create a sample corpus
	* Unicorn-based test harness which:
		+ Adds memory map regions
		+ Loads binary code into memory		
		+ Emulates at least one instruction*
			+ Yeah, this is lame. See 'Gotchas' section below for more info		
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
		  throwing a signal (SIGSEGV, SIGKILL, SIGABORT, etc.).
		  If using afl_fuzz, these signals are automatically forwarded to afl.

Once you have all those things ready to go you just need to run afl-fuzz in
'unicorn-mode' by passing in the '-U' flag:

```bash
	$ afl-fuzz -U -m none -i /path/to/inputs -o /path/to/results -- python ./test_harness @@
```

The normal afl-fuzz command line format applies to everything here. Refer to
AFL's main documentation for more info about how to use afl-fuzz effectively.

For a much clearer vision of what all of this looks like, please refer to the
sample provided in the 'unicorn_mode/samples' directory or take a look at the 
(qiling.io fuzzer)[https://github.com/domenukk/qiling/blob/unicornafl/afl/README.md] example. 
There is also an (a bit outdated) 
(blog post)[https://medium.com/@njvoss299/afl-unicorn-fuzzing-arbitrary-binary-code-563ca28936bf] 
that goes over the basics by the original author, Nathan Voss.

The 'helper_scripts' directory contains several helper scripts that allow you 
to dump context from a running process, load it, and hook heap allocations. For details
on how to use this check out the follow-up blog post to the one linked above.

Further details of AFL-Unicorn mode is discussed in the Paper Unicorefuzz:
https://www.usenix.org/conference/woot19/presentation/maier

## 3) Options

As for the QEMU-based instrumentation, the afl-unicorn twist of afl++
comes with a sub-instruction based instrumentation similar in purpose to laf-intel.

The options that enables Unicorn CompareCoverage are the same used for QEMU.
`AFL_COMPCOV_LEVEL=1` is to instrument comparisons with only immediate
values. `QEMU_COMPCOV_LEVEL=2` instruments all
comparison instructions. Comparison instructions are currently instrumented only
for the x86, x86_64 and ARM targets.

## 4) Fuzz Functions


To start the forkserver, call `uc.afl_forkserver_start(exits)`:

```python
# type: (Uc, List[int]) -> int
"""
This will start the forkserver.
Call this to kick off afl forkserver mode (when running as child of AFL)
If you just want to fuzz, use uc.afl_fuzz instead.
It forks internally, leaving the parent running in an endless loop.
The child notifies the parent about any new block encountered.
The parent then also translates this block for the next AFL iteration.
Since the parent won't know about any exits set after this point, there is no use in using
emu_start params like until or count.
Instead, the exit list of int addresses is passed directly to the parent.
Everything beyond this func is done for every. single. child. Make sure to do the important stuff before.
Will raise UcAflError if something went wrong or AFL died (in which case we want to exit)
:param exits: A list of exits at which the Uc execution will stop.
:return: UC_AFL_RET_CHILD: 
	   You're now in the child. Over and over again.
	 UC_AFL_RET_NO_AFL:
	   No AFL to communicate with. Running on as sole process. :)
	   It's porbably best to just continue to emulate from here on.
	 UC_AFL_RET_FINISHED:
	   Successful fuzz run ended. Probably not much else to do.
-> Prints to sterr and raises UcAflError on error.
(See stderr of your child in AFL with `AFL_DEBUG_CHILD_OUTPUT=1` env)
"""
```
Afterwards, your process will be forked, read input from AFL's input file.

Alternatively, `uc.afl_fuzz(input_file, place_input_callback, exits, validate_crash_callback, always_validate, persistent_iters, data)` 
can be used, which takes care of most of the troubles.

```python
def afl_fuzz(
            self,                   # type: Uc
            input_file,             # type: str
            place_input_callback,   # type: Callable[[Uc, bytes, int, Any], Optional[bool]]
            exits,                  # type: List[int]
            validate_crash_callback=None,  # type: Optional[Callable[[Uc, UcError, bytes, int, Any], Optional[bool]]]
            always_validate=False,  # type: bool
            persistent_iters=1000,  # type: int
            data=None               # type: Any
):
```
```python
# type: (...) -> bool"""
The main fuzzer.
Starts the forkserver, then beginns a persistent loop.
Reads input, calls the place_input callback, emulates, repeats.
If unicorn errors out, will call the validate_crash_callback, if set.
Will only return in the parent after the whole fuzz thing has been finished and afl died.
The child processes never return from here.

:param input_file: filename/path to the (AFL) inputfile. Usually supplied on the commandline.
:param place_input_callback: Callback function that will be called before each test runs.
	This function needs to write the input from afl to the correct position on the unicorn object.
	This function is mandatory.
	It's purpose is to place the input at the right place in unicorn.

	    @uc: (Uc) Unicorn instance
	    @input: (bytes) The current input we're workin on. Place this somewhere in unicorn's memory now.
	    @persistent_round: (int) which round we are currently crashing in, if using persistent mode.
	    @data: (Any) Data pointer passed to uc_afl_fuzz(...).

	    @return: (bool)
		If you return is True (or None) all is well. Fuzzing starts.
		If you return False, something has gone wrong. the execution loop will exit. 
		    There should be no reason to do this in a usual usecase.
:param exits: address list of exits where fuzzing should stop
:param persistent_iters:
	The amount of loop iterations in persistent mode before restarteing with a new forked child.
	If your target cannot be fuzzed using persistent mode (global state changes a lot), 
	set persistent_iters = 1 for the normal fork-server experience.
	Else, the default is usually around 1000.
	If your target is super stable (and unicorn is, too - not sure about that one),
	you may pass persistent_iter = 0 for that an infinite fuzz loop.
:param validate_crash_callback: Optional callback (if not needed, pass NULL), that determines 
	if a non-OK uc_err is an actual error. If false is returned, the test-case will not crash.
	Callback function called after a non-UC_ERR_OK returncode was returned by Unicorn. 
	This function is not mandatory.
	    @uc: Unicorn instance
	    @unicorn_result: The error state returned by the current testcase
	    @input: The current input we're workin with.
	    @persistent_round: which round we are currently crashing in, if using persistent mode.
	    @data: Data pointer passed to uc_afl_fuzz(...).

	    @Return:
	    If you return false, the crash is considered invalid and not reported to AFL.
		-> Next loop iteration begins.
	    If return is true, the crash is reported // the program crashes.
		-> The child will die and the forkserver will spawn a new child.
:param always_validate: If false, validate_crash_callback will only be called for crashes.
:param data: Your very own data pointer. This will passed into every callback.

:return:
	True, if we fuzzed.
	False, if AFL was not available but we ran once.
	raises UcAflException if nothing worked.
"""
```
## 5) Updating

If coming form an older version of afl-unicorn to unicornafl, the scripts need to be adapted:

- replace `import unicorn` with `import unicornafl`
- if using libraries, you can use `unicornafl.monkeypatch()` at the start of your scripts to force the use of unicornafl in the whole project.
- the forkserver no longer starts at the first instruction. Rather, call `uc.afl_start_forkserver` or `uc.afl_fuzz`.

## 6) Gotchas, feedback, bugs

Running the build script builds Unicorn and its python bindings and installs 
them on your system. This installation will supersede any existing Unicorn
installation with the patched afl-unicorn version.

Refer to the unicorn_mode/samples/arm_example/arm_tester.c for an example
of how to do this properly! If you don't get this right, AFL will not 
load any mutated inputs and your fuzzing will be useless!
