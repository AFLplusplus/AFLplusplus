# Obtaining Source Code Coverage while Fuzzing

*Note: This feature was initially built to be used with Nyx and currently does
not work outside of that setup. Work is on the way to generalize this feature.*

The AFL++ runtime has builtin support for gathering source code coverage
measurements while fuzzing, using Clang's native trace-pc-guard implementation.
This implementation is very similar to how sancov works, but was designed in
such a way that it would work with Nyx snapshot fuzzing.

## Getting started

* AFL++ has to be built with `CODE_COVERAGE=1` to enable the runtime parts.
* The target application has to be built with debug symbols
  and `AFL_LLVM_INSTRUMENT=llvmcodecov` set.
* Optimizations should be disabled using `AFL_DONT_OPTIMIZE=1`.


The preload uses two additional buffers, similar to the trace buffer:

1. The pcmap buffer is a 1:1 mapping of an index in the trace buffer
to a PC (pointer) in the loaded module. Combined with module loading
information, this can be used to calculate relative offsets and then
resolve a code location for each entry in the trace buffer.

2. The permanent trace buffer is a copy of the trace buffer that must
be updated *before* each iteration's RELEASE operation. The regular
trace buffer is resetted each time a new iteration begins so we can
measure the coverage of that iteration only. Since we want to accumulate
coverage, we do a byte-wise addition of the current trace buffer over
the permanent trace buffer (up to 0xFF per entry, no wrap around). This
way, the permanent trace buffer holds an overall coverage map with counters
between 0 and 255.

The buffers are added to the packer here:

https://github.com/choller/packer/commit/613bb23e54cdb4bb3ed817c90fdcd268feb0457c

Helper methods are added here:

https://github.com/choller/packer/commit/9d8f384e9e4570f3d241a07df4fabb5091e68c8e

You should call `start_coverage` right before the snapshot to dump module
information (modinfo.txt) and the pcmap buffer (pcmap.dump).

The method `update_coverage_dump` should be called every X iterations to
update the coverage dump (covmap.dump). Doing this on every iteration is
possible but slow, so instead having a permanent counter in the preload
and doing this only periodically is advisable.

The method `update_perm_trace_buffer` should be called before each RELEASE
to capture the current coverage back into the permanent trace buffer.

## Postprocessing Results

The postprocessing toolchain supports two variants of code coverage:

* Basic block code coverage (similar to sancov) except the counters are capped

and

* GCOV-compatible source code coverage.

To obtain the first type of coverage, simply run:

```
python nyx-code-coverage.py path/to/out/workdir/dump/ /build/prefix some_rev coverage.json
```

This assumes that the files `modinfo.txt`, `pcmap.dump` and `covmap.dump` are
in the Nyx dump directory, produced by your preload.

If instead, you want GCOV-compatible coverage (every coverable line is marked),
you need to first run the following command, assuming you have a GCOV build
of your target available (built with --coverage so you have `.gcno` files).

```
python postprocess-gcno.py lineclusters.json /path/to/build /build/prefix
```

Then place the `lineclusters.json` file into the `dump` directory next to the
other files and the `nyx-code-coverage.py` script will automatically pick it
up and use it.
