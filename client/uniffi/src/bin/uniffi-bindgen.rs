//! Generates the Swift and Kotlin sources (see client/uniffi/README.md).
//! Built only with `--features bindgen`; never part of an app.

fn main() {
    uniffi::uniffi_bindgen_main()
}
