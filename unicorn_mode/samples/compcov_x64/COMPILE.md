# Compiling compcov_target.c

compcov_target.c was compiled without optimization, position-independent,
and without standard libraries using the following command line:

```
gcc -o compcov_target.elf compcov_target.c -fPIC -O0 -nostdlib
```

The .text section from the resulting ELF binary was then extracted to create
the raw binary blob that is loaded and emulated by compcov_test_harness.py:

```
objcopy -O binary --only-section=.text compcov_target.elf compcov_target.bin 
```

Note that the output of this is padded with nulls for 16-byte alignment. This is 
important when emulating it, as NOPs will be added after the return of main()
as necessary.
