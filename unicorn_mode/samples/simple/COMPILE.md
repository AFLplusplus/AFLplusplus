# Compiling simple_target.c

You shouldn't need to compile simple_target.c since a MIPS binary version is
pre-built and shipped with afl-unicorn. This file documents how the binary
was built in case you want to rebuild it or recompile it for any reason.

The pre-built binary (simple_target.bin) was built by cross-compiling 
simple_target.c for MIPS using the mips-linux-gnu-gcc package on an Ubuntu
16.04 LTS system. This cross compiler (and associated binutils) was installed
from apt-get packages:

```
sudo apt-get install gcc-mips-linux-gnu
```

simple_target.c was compiled without optimization, position-independent,
and without standard libraries using the following command line:

```
mips-linux-gnu-gcc -o simple_target.elf simple_target.c -fPIC -O0 -nostdlib
```

The .text section from the resulting ELF binary was then extracted to create
the raw binary blob that is loaded and emulated by simple_test_harness.py:

```
mips-linux-gnu-objcopy -O binary --only-section=.text simple_target.elf simple_target.bin 
```

In summary, to recreate simple_taget.bin execute the following:

```
mips-linux-gnu-gcc -o simple_target.elf simple_target.c -fPIC -O0 -nostdlib
  && mips-linux-gnu-objcopy -O binary --only-section=.text simple_target.elf simple_target.bin 
    && rm simple_target.elf
```

Note that the output of this is padded with nulls for 16-byte alignment. This is 
important when emulating it, as NOPs will be added after the return of main()
as necessary.
