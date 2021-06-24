.PHONY: all fuzz

all: ../target ./target/release/unicornafl_harness

afl-fuzz: ../../../../afl-fuzz
../../../../afl-fuzz:
	$(MAKE) -C ../../../../ afl-fuzz

clean:
	cargo clean

./target/release/unicornafl_harness: ./src/main.rs
	cargo build --release

./target/debug/unicornafl_harness: ./src/main.rs
	cargo build

../target:
	$(MAKE) -C ..

fuzz: all afl-fuzz
	rm -rf ./output
	SKIP_BIN_CHECK=1 ../../../../afl-fuzz -s 1 -i ../sample_inputs -o ./output -- ./target/release/unicornafl_harness @@
