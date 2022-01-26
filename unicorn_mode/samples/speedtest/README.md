# Speedtest

This is a simple sample harness for a non-crashing file,
to show the raw speed of C, Rust, and Python harnesses.

## Compiling...

Make sure you built unicornafl first (`../../build_unicorn_support.sh`).
Build the target using the provided Makefile.
This will also run the [./get_offsets.py](./get_offsets.py) script,
which finds some relevant addresses in the target binary using `objdump`,
and dumps them to different files.
Then, follow these individual steps:

### Rust

```bash
cd rust
cargo build --release
../../../../afl-fuzz -i ../sample_inputs -o out -U -- ./target/release/harness @@
```

### C

```bash
cd c
make
../../../../afl-fuzz -i ../sample_inputs -o out -U -- ./harness @@
```

### python

```bash
cd python
../../../../afl-fuzz -i ../sample_inputs -o out -U -- python3 ./harness.py @@
```

## Results

TODO: add results here.
