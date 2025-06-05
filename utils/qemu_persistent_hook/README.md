# QEMU persistent hook example

Compile the test binary and the library:

```
make
```

Fuzz with:

```
export AFL_QEMU_PERSISTENT_ADDR=0x$(nm test | grep "T target_func" | awk '{print $1}')
export AFL_QEMU_PERSISTENT_HOOK=./read_into_rdi.so

mkdir in
echo 0000 > in/in

../../afl-fuzz -Q -i in -o out -- ./test
```

## Example for mipsel architecture

Compile QEMU with `mipsel` support by running the following:

```bash
# From root directory
cd qemu_mode && CPU_TARGET=mipsel ./build_qemu_support.sh
```

To compile binaries for `mipsel`, you need a GCC cross-compiler for
the target architecture.
How to build a GCC cross-compiler is out of scope for this document, but you
may find this
[OSDev Wiki Tutorial](https://wiki.osdev.org/GCC_Cross-Compiler) helpful.
If you are using Nix, you may find
[this tutorial](https://ayats.org/blog/nix-cross) useful.

The next step assumes that you have a GCC cross-compiler for `mipsel` available
under `mipsel-gnu-linux-cc`. Verify that `qemu_mode` works properly by running
`test/test-qemu-mode.sh`:

```bash
# From root directory
cd test
CPU_TARGET_CC=mipsel-linux-gnu-cc CPU_TARGET=mipsel ./test-qemu-mode.sh
```

The output should look something like this:

```
[*] Using environment variable CPU_TARGET=mipsel for SYS
[*] starting AFL++ test framework ...
[*] Testing: qemu_mode
[*] Using mipsel-linux-gnu-cc as compiler for target
[*] running afl-fuzz for qemu_mode, this will take approx 10 seconds
[+] afl-fuzz is working correctly with qemu_mode
[*] running afl-fuzz for qemu_mode AFL_ENTRYPOINT, this will take approx 6 seconds
[+] afl-fuzz is working correctly with qemu_mode AFL_ENTRYPOINT
[-] not an intel or arm platform, cannot test qemu_mode compcov
[-] not an intel or arm platform, cannot test qemu_mode cmplog
[*] running afl-fuzz for persistent qemu_mode, this will take approx 10 seconds
[+] afl-fuzz is working correctly with persistent qemu_mode
[+] persistent qemu_mode was noticeable faster than standard qemu_mode
[*] running afl-fuzz for persistent qemu_mode with AFL_QEMU_PERSISTENT_EXITS, this will take approx 10 seconds
[+] afl-fuzz is working correctly with persistent qemu_mode and AFL_QEMU_PERSISTENT_EXITS
[+] persistent qemu_mode with AFL_QEMU_PERSISTENT_EXITS was noticeable faster than standard qemu_mode
[-] we cannot test qemu_mode unsigaction library (32 bit) because it is not present
[+] qemu_mode unsigaction library (64 bit) ignores signals
[*] 1 test cases completed.
[-] not all test cases were executed
[+] all tests were successful :-)
```

Then, compile the test binary and library for `mipsel` using the following
`make` command:

```bash
CPU_TARGET_CC=mipsel-linux-gnu-cc make all_mipsel
```

Make sure that the test binary and library have the correct format. When you
run `file` on the two output files, you should see something like the
following:

```
$ file mipsel_read_into_a0.so mipsel_test
mipsel_read_into_a0.so: ELF 32-bit LSB shared object, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, not stripped
mipsel_test:            ELF 32-bit LSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /nix/store/837z8p51k37n0s1l3hlawx6inc60cq9d-uclibc-ng-mipsel-linux-gnu-1.0.50/lib/ld64-uClibc.so.1, not stripped
```

Then, like in the previous section, prepare the fuzzing environment:

```bash
export AFL_QEMU_PERSISTENT_ADDR=0x$(nm mipsel_test | grep "T target_func" | awk '{print $1}')
export AFL_QEMU_PERSISTENT_HOOK=./mipsel_read_into_a0.so

mkdir in
echo 0000 > in/in

# Set the following environment variables to avoid having to adjust
# kernel settings:
export AFL_SKIP_CPUFREQ=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
```

Run the fuzzer using the following command:

```bash
../../afl-fuzz -V10 -Q -i in -o out -- ./mipsel_test
```

If you run the fuzzer with `export AFL_DEBUG=1`, you should see the following
repeating output:

```
...
Placing input into 0x410950
buffer:0x410950, size:1
Placing input into 0x410950
buffer:0x410950, size:1
Placing input into 0x410950
buffer:0x410950, size:185
Placing input into 0x410950
buffer:0x410950, size:5
Placing input into 0x410950
buffer:0x410950, size:113
Placing input into 0x410950
buffer:0x410950, size:28
Placing input into 0x410950
buffer:0x410950, size:78
Placing input into 0x410950
buffer:0x410950, size:2
...
```
