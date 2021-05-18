# FRIDA MODE

The purpose of FRIDA mode is to provide an alternative binary only fuzzer for
AFL just like that provided by QEMU mode. The intention is to provide a very
similar user experience, right down to the options provided through environment
variables.

Whilst AFLplusplus already has some support for running on FRIDA [here](https://github.com/AFLplusplus/AFLplusplus/tree/stable/utils/afl_frida)
this requires the code to be fuzzed to be provided as a shared library, it
cannot be used to fuzz executables. Additionally, it requires the user to write
a small harness around their target code of interest.
FRIDA mode instead takes a different approach to avoid these limitations.
In Frida mode binary programs are instrumented, similarly to QEMU mode.

## Current Progress

As FRIDA mode is new, it is missing a lot of features. The design is such that it
should be possible to add these features in a similar manner to QEMU mode and
perhaps leverage some of its design and implementation.

  | Feature/Instrumentation  | frida-mode | Notes                                        |
  | -------------------------|:----------:|:--------------------------------------------:|
  | NeverZero                |     x      |                                              |
  | Persistent Mode          |     x      | (x86/x64 only)(Only on function boundaries)  |  
  | LAF-Intel / CompCov      |     -      | (CMPLOG is better 90% of the time)           |
  | CMPLOG                   |     x      | (x86/x64 only)                               |
  | Selective Instrumentation|     x      |                                              |
  | Non-Colliding Coverage   |     -      | (Not possible in binary-only instrumentation |
  | Ngram prev_loc Coverage  |     -      |                                              |
  | Context Coverage         |     -      |                                              |
  | Auto Dictionary          |     -      |                                              |
  | Snapshot LKM Support     |     -      |                                              |
  | In-Memory Test Cases     |     x      | (x86/x64 only)                               |

## Compatibility
Currently FRIDA mode supports Linux and macOS targets on both x86/x64
architecture and aarch64. Later releases may add support for aarch32 and Windows
targets as well as embedded linux environments.

FRIDA has been used on various embedded targets using both uClibc and musl C
runtime libraries, so porting should be possible. However, the current build
system does not support cross compilation.

## Getting Started

To build everything run `make`. To build for x86 run `make 32`. Note that in 
x86 bit mode, it is not necessary for afl-fuzz to be built for 32-bit. However,
the shared library for frida_mode must be since it is injected into the target
process.

Various tests can be found in subfolders within the `test/` directory. To use
these, first run `make` to build any dependencies. Then run `make qemu` or
`make frida` to run on either QEMU of FRIDA mode respectively. To run frida 
tests in 32-bit mode, run `make ARCH=x86 frida`. When switching between 
architectures it may be necessary to run `make clean` first for a given build 
target to remove previously generated binaries for a different architecture.

## Usage

FRIDA mode added some small modifications to `afl-fuzz` and similar tools
in AFLplusplus. The intention was that it behaves identically to QEMU, but it uses
the 'O' switch rather than 'Q'. Whilst the options 'f', 'F', 's' or 'S' may have
made more sense for a mode powered by FRIDA Stalker, they were all taken, so
instead we use 'O' in hommage to the [author](https://github.com/oleavr) of
FRIDA.

Similarly, the intention is to mimic the use of environment variables used by
QEMU where possible (by replacing `s/QEMU/FRIDA/g`). Accordingly, the
following options are currently supported:

* `AFL_FRIDA_DEBUG_MAPS` - See `AFL_QEMU_DEBUG_MAPS`
* `AFL_FRIDA_EXCLUDE_RANGES` - See `AFL_QEMU_EXCLUDE_RANGES`
* `AFL_FRIDA_INST_RANGES` - See `AFL_QEMU_INST_RANGES`
* `AFL_FRIDA_PERSISTENT_ADDR` - See `AFL_QEMU_PERSISTENT_ADDR`
* `AFL_FRIDA_PERSISTENT_CNT` - See `AFL_QEMU_PERSISTENT_CNT`
* `AFL_FRIDA_PERSISTENT_HOOK` - See `AFL_QEMU_PERSISTENT_HOOK`

To enable the powerful CMPLOG mechanism, set `-c 0` for `afl-fuzz`.

## Performance

Additionally, the intention is to be able to make a direct performance
comparison between the two approaches. Accordingly, FRIDA mode includes various
test targets based on the [libpng](https://libpng.sourceforge.io/) benchmark
used by [fuzzbench](https://google.github.io/fuzzbench/) and integrated with the
[StandaloneFuzzTargetMain](https://raw.githubusercontent.com/llvm/llvm-project/main/compiler-rt/lib/fuzzer/standalone/StandaloneFuzzTargetMain.c)
from the llvm project. These tests include basic fork-server support, persistent
mode and persistent mode with in-memory test-cases. These are built and linked
without any special modifications to suit FRIDA or QEMU. The test data provided
with libpng is used as the corpus.

The intention is to add support for FRIDA mode to the FuzzBench project and
perform a like-for-like comparison with QEMU mode to get an accurate
appreciation of its performance.

## Design

FRIDA mode is supported by using `LD_PRELOAD` (`DYLD_INSERT_LIBRARIES` on macOS)
to inject a shared library (`afl-frida-trace.so`) into the target. This shared
library is built using the [frida-gum](https://github.com/frida/frida-gum)
devkit from the [FRIDA](https://github.com/frida/frida) project. One of the
components of frida-gum is [Stalker](https://medium.com/@oleavr/anatomy-of-a-code-tracer-b081aadb0df8),
this allows the dynamic instrumentation of running code for AARCH32, AARCH64,
x86 and x64 architectures. Implementation details can be found
[here](https://frida.re/docs/stalker/).

Dynamic instrumentation is used to augment the target application with similar
coverage information to that inserted by `afl-gcc` or `afl-clang`. The shared
library is also linked to the `compiler-rt` component of AFLplusplus to feedback
this coverage information to AFL++ and also provide a fork server. It also makes
use of the FRIDA [prefetch](https://github.com/frida/frida-gum/blob/56dd9ba3ee9a5511b4b0c629394bf122775f1ab7/gum/gumstalker.h#L115)
support to feedback instrumented blocks from the child to the parent using a
shared memory region to avoid the need to regenerate instrumented blocks on each
fork.

Whilst FRIDA allows for a normal C function to be used to augment instrumented
code, FRIDA mode instead makes use of optimized assembly instead on AARCH64 and
x86/64 targets. By injecting these small snippets of assembly, we avoid having
to push and pop the full register context. Note that since this instrumentation
is used on every basic block to generate coverage, it has a large impact on
performance.

CMPLOG support also adds code to the assembly, however, at present this code
makes use of a basic C function and is yet to be optimized. Since not all
instances run CMPLOG mode and instrumentation of the binary is less frequent
(only on CMP, SUB and CALL instructions) performance is not quite so critical.

## Advanced configuration options

* `AFL_FRIDA_INST_NO_OPTIMIZE` - Don't use optimized inline assembly coverage
instrumentation (the default where available). Required to use
`AFL_FRIDA_INST_TRACE`.
* `AFL_FRIDA_INST_NO_PREFETCH` - Disable prefetching. By default the child will
report instrumented blocks back to the parent so that it can also instrument
them and they be inherited by the next child on fork.
* `AFL_FRIDA_INST_TRACE` - Generate some logging when running instrumented code.
Requires `AFL_FRIDA_INST_NO_OPTIMIZE`.

## FASAN - Frida Address Sanitizer Mode
Frida mode also supports FASAN. The design of this is actually quite simple and
very similar to that used when instrumenting applications compiled from source.

### Address Sanitizer Basics

When Address Sanitizer is used to instrument programs built from source, the 
compiler first adds a dependency (`DT_NEEDED` entry) for the Address Sanitizer
dynamic shared object (DSO). This shared object contains the main logic for Address
Sanitizer, including setting and managing up the shadow memory. It also provides
replacement implementations for a number of functions in standard libraries. 

These replacements include things like `malloc` and `free` which allows for those
allocations to be marked in the shadow memory, but also a number of other fuctions.
Consider `memcpy` for example, this is instrumented to validate the paramters 
(test the source and destination buffers against the shadow memory. This is much 
easier than instrumenting those standard libraries since, first it would require 
you to re-compile them and secondly it would mean that the instrumentation would
be applied at a more expensive granular level. Lastly, load-widening (typically 
found in highy optimized code) can also make this instrumentation more difficult.

Since the DSO is loaded before all of the standard libraries (in fact it insists
on being first), the dynamic loader will use it to resolve imports from other
modules which depend on it.

### FASAN Implementation

FASAN takes a similar approach. It requires the user to add the Address Sanitizer
DSO to the `AFL_PRELOAD` environment variable such that it is loaded into the target.
Again, it must be first in the list. This means that it is not necessary to 
instrument the standard libraries to detect when an application has provided an 
incorrect argument to `memcpy` for example. This avoids issues with load-widening 
and should also mean a huge improvement in performance.

FASAN then adds instrumentation for any instrucutions which use memory operands and
then calls into the `__asan_loadN` and `__asan_storeN` functions provided by the DSO
to validate memory accesses against the shadow memory.

## TODO

The next features to be added are Aarch64 and Aarch32 support as well as looking at 
potential performance improvements. The intention is to achieve feature parity with
QEMU mode in due course. Contributions are welcome, but please get in touch to
ensure that efforts are deconflicted.
