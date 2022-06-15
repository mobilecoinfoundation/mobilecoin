// #![allow(warnings)]
use tempfile::{Builder, TempDir};

/// Get environment variable `OUT_DIR` provided by cargo.
fn out() -> String {
    std::env::var("OUT_DIR").expect("Missing environment variable OUT_DIR")
}

/// Create a temporary directory in the directory specified by the
/// cargo-provided `OUT_DIR` environment variable.
///
/// # Panics
///
/// - If `OUT_DIR` doesn't exist
/// - If [`TempDir::new_in`] fails to create the directory.
pub fn tempdir() -> TempDir {
    let out = out();
    TempDir::new_in(&out)
        .unwrap_or_else(|err| panic!("Could not create temporary directory in {}: {}", out, err))
}

/// Create a temporary directory in the directory specified by the
/// cargo-provided `OUT_DIR` environment variable, using `prefix`.
///
/// # Panics
///
/// - If `OUT_DIR` doesn't exist
/// - If [`Builder::tempdir_in`] fails to create the directory.
pub fn tempdir_with_prefix(prefix: &str) -> TempDir {
    let out = out();
    Builder::new()
        .prefix(prefix)
        .tempdir_in(&out)
        .unwrap_or_else(|err| panic!("Could not create temporary directory in {}: {}", out, err))
}
