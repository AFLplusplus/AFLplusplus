# Speedtest

This is a simple sample harness for a non-crashing file,
to show the raw speed of C, Rust, and Python harnesses.

## Compiling...

Make sure, you built unicornafl first (`../../build_unicorn_support.sh`).
Then, follow these individual steps:

### Rust

```bash
cd rust
cargo build --release
../../../afl-fuzz -i ../sample_inputs -o out -- ./target/release/harness @@
```

### C

```bash
cd c
make
../../../afl-fuzz -i ../sample_inputs -o out -- ./harness @@
```

### python

```bash
cd python
../../../afl-fuzz -i ../sample_inputs -o out -U -- python3 ./harness.py @@
```

## Results

TODO: add results here.


## Compiling speedtest_target.c

You shouldn't need to compile simple_target.c since a X86_64 binary version is
pre-built and shipped in this sample folder. This file documents how the binary
was built in case you want to rebuild it or recompile it for any reason.

The pre-built binary (simple_target_x86_64.bin) was built using -g -O0 in gcc.

We then load the binary and execute the main function directly.

## Addresses for the harness:
To find the address (in hex) of main, run:
```bash
objdump -M intel -D target | grep '<main>:' | cut -d" " -f1
```
To find all call sites to magicfn, run:
```bash
objdump -M intel -D target | grep '<magicfn>$' | cut -d":" -f1
```
For malloc callsites:
```bash
objdump -M intel -D target | grep '<malloc@plt>$' | cut -d":" -f1
```
And free callsites:
```bash
objdump -M intel -D target | grep '<free@plt>$' | cut -d":" -f1
```
