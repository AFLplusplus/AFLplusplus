all: fuzz

clean:
	cargo clean

./target/release/unicornafl_harness: ./src/main.rs
	cargo build --release

./target/debug/unicornafl_harness: ./src/main.rs
	cargo build

../target:
	$(MAKE) -c ..

fuzz: ../target ./target/release/unicornafl_harness
	rm -rf ./output
	SKIP_BINCHECK=1 ../../../../afl-fuzz -s 1 -i ../sample_inputs -o ./output -- ./target/release/unicornafl_harness @@
