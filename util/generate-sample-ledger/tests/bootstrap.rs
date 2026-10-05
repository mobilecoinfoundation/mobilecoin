use std::{env::set_current_dir, path::PathBuf, process::Command};
use tempfile::TempDir;

// Test that the bootstrap binary works with basic config
//
// Note: This test is needed mainly because if there is not an integration test
// in the `util-generate-sample-ledger` crate, then `cargo test` will not build
// the bootstrap binary, and this will cause the `bootstrap` test in
// `mc-fog-distribution` to fail. That test is there to confirm that bootstrap
// and fog distribution are working together in the way that they are used in CD
// and improve on iteration times.
//
// If cargo creates a way for one crate to have a dev dependency on a binary
// from another crate, that would be a way to avoid needing this test. (AFAIK
// this can't be done right now.)
#[test]
fn test_exercise_bootstrap() {
    let generate_sample_ledger = PathBuf::from(env!("CARGO_BIN_EXE_generate-sample-ledger"));
    let sample_keys = generate_sample_ledger.with_file_name("sample-keys");
    println!("generate-sample-ledger = {generate_sample_ledger:?}");
    println!("sample-keys = {sample_keys:?}");

    let dir = TempDir::new().unwrap();
    set_current_dir(dir.path()).unwrap();
    println!("dir = {dir:?}");

    assert!(Command::new(sample_keys)
        .args(["--num", "5"])
        .status()
        .expect("sample-keys")
        .success());

    assert!(Command::new(generate_sample_ledger)
        .args(["--txs", "10"])
        .status()
        .expect("generate-sample-ledger")
        .success());
}
