# FRIDA MODE
The purpose of FRIDA mode is to provide an alternative binary only fuzzer for AFL
just like that provided by QEMU mode. The intention is to provide a very similar
user experience, right down to the options provided through environment variables.

Whilst AFLplusplus already has some support for running on FRIDA [here](https://github.com/AFLplusplus/AFLplusplus/tree/stable/utils/afl_frida)
this requires the code to be fuzzed to be provided as a shared library, it
cannot be used to fuzz executables. Additionally, it requires the user to write
a small harness around their target code of interest, FRIDA mode instead takes a
different approach to avoid these limitations.

# Current Progress
As FRIDA mode is new, it is missing a lot of features. Most importantly,
persistent mode. The design is such that it should be possible to add these
features in a similar manner to QEMU mode and perhaps leverage some of its
design and implementation.

  | Feature/Instrumentation  | frida-mode |
  | -------------------------|:----------:|
  | NeverZero                |            |
  | Persistent Mode          |            |
  | LAF-Intel / CompCov      |            |
  | CmpLog                   |            |
  | Selective Instrumentation|     x      |
  | Non-Colliding Coverage   |            |
  | Ngram prev_loc Coverage  |            |
  | Context Coverage         |            |
  | Auto Dictionary          |            |
  | Snapshot LKM Support     |            |

# Compatibility
Currently FRIDA mode supports Linux and macOS targets on both x86/x64
architecture and aarch64. Later releases may add support for aarch32 and Windows
targets as well as embedded linux environments.

FRIDA has been used on various embedded targets using both uClibc and musl C
runtime libraries, so porting should be possible. However, the current build
system does not support cross compilation.

## Getting Started
To build everything run `make`.

To run the benchmark sample with qemu run `make png_qemu`.
To run the benchmark sample with frida run `make png_frida`.

## Usage
FRIDA mode requires some small modifications to `afl-fuzz` and similar tools
in AFLplusplus. The intention is that it behaves identically to QEMU, but uses
the 'O' switch rather than 'Q'. Whilst the options 'f', 'F', 's' or 'S' may have
made more sense for a mode powered by FRIDA Stalker, they were all taken, so
instead we use 'O' in hommage to the [author](https://github.com/oleavr) of
FRIDA.

Similarly, the intention is to mimic the use of environment variables used by
QEMU where possible (although replacing `s/QEMU/FRIDA/g`). Accodingly, the
following options are currently supported.

* `AFL_FRIDA_DEBUG_MAPS` - See `AFL_QEMU_DEBUG_MAPS`
* `AFL_FRIDA_EXCLUDE_RANGES` - See `AFL_QEMU_EXCLUDE_RANGES`
* `AFL_FRIDA_INST_RANGES` - See `AFL_QEMU_INST_RANGES`

# Performance

Additionally, the intention is to be able to make a direct performance
comparison between the two approaches. Accordingly, FRIDA mode includes a test
target based on the [libpng](https://libpng.sourceforge.io/) benchmark used by
[fuzzbench](https://google.github.io/fuzzbench/) and integrated with the
[StandaloneFuzzTargetMain](https://raw.githubusercontent.com/llvm/llvm-project/main/compiler-rt/lib/fuzzer/standalone/StandaloneFuzzTargetMain.c)
from the llvm project. This is built and linked without any special
modifications to suit FRIDA or QEMU. We use the test data provided with libpng
as our corpus.

Whilst not much performance tuning has been completed to date, performance is
around 30-50% of that of QEMU mode, however, this gap may reduce with the 
introduction of persistent mode. Performance can be tested by running 
`make compare`, albeit a longer time measurement may be required for more 
accurate results. 

Whilst [afl_frida](https://github.com/AFLplusplus/AFLplusplus/tree/stable/utils/afl_frida)
claims a 5-10x performance increase over QEMU, it has not been possible to
reproduce these claims. However, the number of executions per second can vary
dramatically as a result of the randomization of the fuzzer input. Some inputs
may traverse relatively few paths before being rejected as invalid whilst others
may be valid inputs or be subject to much more processing before rejection.
Accordingly, it is recommended that testing be carried out over prolongued
periods to gather timings which are more than indicative.

# Design
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
code, to minimize the costs of storing and restoring all of the registers, FRIDA
mode instead makes use of optimized assembly instead on AARCH64 and x86/64
targets.

# Advanced configuration options
* `AFL_FRIDA_INST_NO_OPTIMIZE` - Don't use optimized inline assembly coverage
instrumentation (the default where available). Required to use
`AFL_FRIDA_INST_TRACE`.
* `AFL_FRIDA_INST_NO_PREFETCH` - Disable prefetching. By default the child will
report instrumented blocks back to the parent so that it can also instrument
them and they be inherited by the next child on fork.
* `AFL_FRIDA_INST_STRICT` - Under certain conditions, Stalker may encroach into
excluded regions and generate both instrumented blocks and coverage data (e.g.
indirect calls on x86). The excluded block is generally honoured as soon as
another function is called within the excluded region and so such encroachment
is usually of little consequence. This detail may however, hinder you when
checking that the correct number of paths are found for testing purposes or
similar. There is a performance penatly for this option during block compilation
where we check the block isn't in a list of excluded ranges.
* `AFL_FRIDA_INST_TRACE` - Generate some logging when running instrumented code.
Requires `AFL_FRIDA_INST_NO_OPTIMIZE`.

# TODO
As can be seen from the progress section above, there are a number of features
which are missing in its currently form. Chief amongst which is persistent mode.
The intention is to achieve feature parity with QEMU mode in due course.
Contributions are welcome, but please get in touch to ensure that efforts are
deconflicted.
