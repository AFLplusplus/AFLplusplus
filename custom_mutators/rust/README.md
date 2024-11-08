# Rust Custom Mutators

Bindings to create custom mutators in Rust.

These bindings are documented with rustdoc. To view the documentation run
```cargo doc -p custom_mutator --open```.

A minimal example can be found in `example`. Build it using `cargo build --example example_mutator`.

An example using [lain](https://github.com/microsoft/lain) for structured fuzzing can be found in `example_lain`.
Since lain requires a nightly rust toolchain, you need to set one up before you can play with it.

An example for the use of the post_process function, using [lain](https://github.com/microsoft/lain) with [serde](https://github.com/serde-rs/serde) and [bincode](https://github.com/bincode-org/bincode) can be found in `example_lain_post_process`.
In order for it to work you need to:

- disable input trimming with `AFL_DISABLE_TRIM=1`
- provide an initial instance serialized with `bincode` or use the `AFL_NO_STARTUP_CALIBRATION=1` environment variable.

Note that `bincode` can also be used to serialize/deserialize the lain-generated structure and mutate it rather than generating a new one at each iteration, but it requires some structure serialized with `bincode` as input seed.
