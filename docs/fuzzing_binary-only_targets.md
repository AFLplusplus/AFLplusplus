# Fuzzing binary-only targets

When source code is *NOT* available, AFL++ offers various support for fast,
on-the-fly instrumentation of black-box binaries. 

If you do not have to use Unicorn the following setup is recommended to use
qemu_mode:
  * run 1 afl-fuzz -Q instance with CMPLOG (`-c 0` + `AFL_COMPCOV_LEVEL=2`)
  * run 1 afl-fuzz -Q instance with QASAN  (`AFL_USE_QASAN=1`)
  * run 1 afl-fuzz -Q instance with LAF (`AFL_PRELOAD=libcmpcov.so` + `AFL_COMPCOV_LEVEL=2`)
Alternatively you can use frida_mode, just switch `-Q` with `-O` and remove the
LAF instance.

Then run as many instances as you have cores left with either -Q mode or - better -
use a binary rewriter like afl-dyninst, retrowrite, zafl, etc.

For Qemu and Frida mode, check out the persistent mode, it gives a huge speed
improvement if it is possible to use.

### QEMU

For linux programs and its libraries this is accomplished with a version of
QEMU running in the lesser-known "user space emulation" mode.
QEMU is a project separate from AFL, but you can conveniently build the
feature by doing:

```shell
cd qemu_mode
./build_qemu_support.sh
```

For additional instructions and caveats, see [qemu_mode/README.md](../qemu_mode/README.md).
If possible you should use the persistent mode, see [qemu_mode/README.persistent.md](../qemu_mode/README.persistent.md).
The mode is approximately 2-5x slower than compile-time instrumentation, and is
less conducive to parallelization.

If [afl-dyninst](https://github.com/vanhauser-thc/afl-dyninst) works for
your binary, then you can use afl-fuzz normally and it will have twice
the speed compared to qemu_mode (but slower than qemu persistent mode).
Note that several other binary rewriters exist, all with their advantages and
caveats.

### Frida

Frida mode is sometimes faster and sometimes slower than Qemu mode.
It is also newer, lacks COMPCOV, but supports MacOS.

```shell
cd frida_mode
make
```

For additional instructions and caveats, see [frida_mode/README.md](../frida_mode/README.md).
If possible you should use the persistent mode, see [qemu_frida/README.persistent.md](../qemu_frida/README.persistent.md).
The mode is approximately 2-5x slower than compile-time instrumentation, and is
less conducive to parallelization.

### Unicorn

For non-Linux binaries you can use AFL++'s unicorn mode which can emulate
anything you want - for the price of speed and user written scripts.
See [unicorn_mode/README.md](../unicorn_mode/README.md).

It can be easily built by:
```shell
cd unicorn_mode
./build_unicorn_support.sh
```

### Shared libraries

If the goal is to fuzz a dynamic library then there are two options available.
For both you need to write a small harness that loads and calls the library.
Faster is the frida solution: [utils/afl_frida/README.md](../utils/afl_frida/README.md)

Another, less precise and slower option is using ptrace with debugger interrupt
instrumentation: [utils/afl_untracer/README.md](../utils/afl_untracer/README.md).

### More

A more comprehensive description of these and other options can be found in
[binaryonly_fuzzing.md](binaryonly_fuzzing.md).