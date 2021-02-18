extern crate bindgen;

use std::env;
use std::path::PathBuf;

// this code is largely taken straight from the handbook: https://github.com/fitzgen/bindgen-tutorial-bzip2-sys
fn main() {
    // Tell cargo to invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed=wrapper.h");

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header("wrapper.h")
        .whitelist_type("afl_state_t")
        .blacklist_type(r"u\d+")
        .opaque_type(r"_.*")
        .opaque_type("FILE")
        .opaque_type("in_addr(_t)?")
        .opaque_type("in_port(_t)?")
        .opaque_type("sa_family(_t)?")
        .opaque_type("sockaddr_in(_t)?")
        .opaque_type("time_t")
        .rustfmt_bindings(true)
        .size_t_is_usize(true)
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
