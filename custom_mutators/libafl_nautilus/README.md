# LibAFL Nautilus Mutator

This custom mutator integrates the [Nautilus](https://github.com/nautilus-fuzz/nautilus) grammar fuzzer into AFL++ using [LibAFL](https://github.com/AFLplusplus/LibAFL).

It supports:
- Grammar-based mutation using Nautilus.
- Persisting grammar trees in the AFL++ queue (via `postcard` serialization).
- Unparsing trees to target bytes during execution.

## Build

Prerequisites:
- Rust (install via [rustup](https://rustup.rs/))

```sh
cargo build --release
```

Or use the Makefile:
```sh
make
```

## Usage

To run AFL++ with this mutator, you need to:
1.  Set `AFL_CUSTOM_MUTATOR_LIBRARY` to the path of the compiled shared library.
2.  Set `AFL_POST_PROCESS_KEEP_ORIGINAL=1` to ensure AFL++ stores the serialized tree in the queue, not the unparsed bytes.
3.  Set `NAUTILUS_GRAMMAR_FILE` to the path of your grammar JSON file.

```sh
export NAUTILUS_GRAMMAR_FILE=/path/to/grammar.json
export AFL_CUSTOM_MUTATOR_LIBRARY=target/release/liblibafl_nautilus.so
export AFL_POST_PROCESS_KEEP_ORIGINAL=1

# Run AFL++ (add -n if you don't want deterministic fuzzing, usually good for grammar)
afl-fuzz -i in -o out -n -- ./target @@
```

## Tools

### dump_inputs

A utility to convert the serialized Nautilus trees (Postcard format) in the queue back to raw bytes.

**Build:**
```sh
cargo build --release --bin dump_inputs
# Or with JSON support (if you enabled the json feature in the mutator)
cargo build --release --bin dump_inputs --features json
```

**Usage:**
```sh
./target/release/dump_inputs <grammar_file> <input_dir> <output_dir>
```

Example:
```sh
./target/release/dump_inputs grammar.json out/default/queue out_dumped
```
