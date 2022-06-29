all: target/release/liblibafl_base.so
	cp target/release/liblibafl_base.so libafl_base.so

target/release/liblibafl_base.so: src/lib.rs
	cargo build --release

clean:
	cargo clean
	rm -f libafl_base.so
