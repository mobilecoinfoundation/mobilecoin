#![allow(warnings)]
use tempfile::{NamedTempFile, TempDir};

/// Create a temporary directory in the directory specified by the
/// cargo-provided `OUT_DIR` environment variable.
///
/// # Panics
///
/// - If `OUT_DIR` doesn't exist
/// - If [`TempDir::new_in`] fails to create the directory.
pub fn tempdir() -> TempDir {
    let out = std::env::var("OUT_DIR").expect("Missing environment variable OUT_DIR");
    TempDir::new_in(&out).expect(&format!("Could not create temporary directory {}", &out))
}
