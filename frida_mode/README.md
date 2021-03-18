# FRIDA MODE
The purpose of FRIDA mode is to provide an alternative binary only fuzzer for AFL
just like that provided by QEMU mode. The intention is to provide a very similar
user experience, right down to the options provided through environment variables.

Additionally, the intention is to be able to make a direct performance comparison
between the two approaches. Hopefully, we should also be able to leverage the same
approaches for adding features which QEMU uses, possibly even sharing code.

## Limitations
The current focus is on x64 support for Intel. Although parts may be architecturally
dependent, the approach itself should remain architecture agnostic.

## Usage
FRIDA mode requires some small modifications to the afl-fuzz and similar tools in
AFLplusplus. The intention is that it behaves identically to QEMU, but uses the 'O'
switch rather than 'Q'.

## Design
AFL Frida works by means of a shared library injected into a binary program using
LD_PRELOAD, similar to the way which other fuzzing features are injected into targets.

## Testing
Alongside the FRIDA mode, we also include a test program for fuzzing. This test
program is built using the libpng benchmark from fuzz-bench and integrating the
StandaloneFuzzTargetMain from the llvm project. This is built and linked without
any special modifications to suit FRIDA or QEMU. However, at present we don't have
a representative corpus.

## Getting Started
To build everything run `make`.

To run the benchmark sample with qemu run `make test_qemu`.
To run the benchmark sample with frida run `make test_frida`.

# Configuration options
* `AFL_FRIDA_DEBUG_MAPS` - See `AFL_QEMU_DEBUG_MAPS`
* `AFL_FRIDA_EXCLUDE_RANGES` - See `AFL_QEMU_EXCLUDE_RANGES`
* `AFL_FRIDA_INST_NO_OPTIMIZE` - Don't use optimized inline assembly coverage instrumentation (the default where available). Required to use `AFL_FRIDA_INST_TRACE`.
* `AFL_FRIDA_INST_NO_PREFETCH` - Disable prefetching. By default the child will report instrumented blocks back to the parent so that it can also instrument them and they be inherited by the next child on fork.
* `AFL_FRIDA_INST_RANGES` - See `AFL_QEMU_INST_RANGES`
* `AFL_FRIDA_INST_STRICT` - Under certain conditions, Stalker may encroach into excluded regions and generate both instrumented blocks and coverage data (e.g. indirect calls on x86). The excluded block is generally honoured as soon as another function is called within the excluded region. The overhead of generating, running and instrumenting these few additional blocks is likely to be fairly small, but it may hinder you when checking that the correct number of paths are found for testing purposes or similar. There is a performance penatly for this option during block compilation where we check the block isn't in a list of excluded ranges.
* `AFL_FRIDA_INST_TRACE` - Generate some logging when running instrumented code. Requires `AFL_FRIDA_INST_NO_OPTIMIZE`.

# TODO
* Add AARCH64 inline assembly optimization from libFuzz
* Fix issues running on OSX
* Identify cause of erroneous additional paths
