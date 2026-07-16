//! Library-mode UniFFI bindings generator for the native verification SDK.
//!
//! Generates Swift / Kotlin / Python bindings directly from the compiled
//! `metamorphic_log` cdylib (built with `--features uniffi`), e.g.:
//!
//! ```sh
//! uniffi-bindgen generate --library target/debug/libmetamorphic_log.dylib \
//!   --language swift --out-dir bindings/swift
//! ```
fn main() {
    uniffi::uniffi_bindgen_main()
}
