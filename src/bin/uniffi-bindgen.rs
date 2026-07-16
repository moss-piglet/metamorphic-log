//! Library-mode UniFFI bindings generator for the native verification SDK.
//!
//! Built only with `--features uniffi`. Generates Swift / Kotlin / Python
//! bindings directly from the compiled `metamorphic_log` cdylib, e.g.:
//!
//! ```sh
//! cargo run --features uniffi --bin uniffi-bindgen -- \
//!   generate --library target/debug/libmetamorphic_log.dylib \
//!   --language swift --out-dir bindings/swift
//! ```
fn main() {
    uniffi::uniffi_bindgen_main()
}
