# Rust Custom Mutators

Bindings to create custom mutators in Rust.

These bindings are documented with rustdoc. To view the documentation run
```cargo doc -p custom_mutator --open```.

A minimal example can be found in `example`. Build it using `cargo build --example example_mutator`. 

An example using [lain](https://github.com/microsoft/lain) for structured fuzzing can be found in `example_lain`.
Since lain requires a nightly rust toolchain, you need to set one up before you can play with it.
