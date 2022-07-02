use std::{
    env::{args, set_current_dir},
    path::PathBuf,
    process::Command,
};
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
    let me = PathBuf::from(args().next().unwrap());
    let bin = me.parent().unwrap().parent().unwrap();
    println!("bin = {:?}", bin);

    let dir = TempDir::new().unwrap();
    set_current_dir(dir.path()).unwrap();
    println!("dir = {:?}", dir);

    assert!(Command::new(bin.join("sample-keys"))
        .args(["--num", "5"])
        .status()
        .expect("sample-keys")
        .success());

    assert!(Command::new(bin.join("generate-sample-ledger"))
        .args(["--txs", "10"])
        .status()
        .expect("generate-sample-ledger")
        .success());
}
