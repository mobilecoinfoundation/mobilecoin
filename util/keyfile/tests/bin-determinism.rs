// Copyright (c) 2018-2021 The MobileCoin Foundation

use std::{env, process::Command};
use tempdir::TempDir;

// Get the build dir, which is one down from current_exe, which is in
// target/debug/deps,
fn build_dir() -> std::path::PathBuf {
    let mut result = env::current_exe().unwrap();
    result.pop();
    result.pop();
    result
}

// Test that the sample keys binary is deterministic
#[test]
#[ignore]
fn sample_keys_determinism() {
    let sample_keys_bin = build_dir().join("sample-keys");
    assert!(
        sample_keys_bin.exists(),
        "sample_keys binary was not found: {}",
        sample_keys_bin.display()
    );

    let tempdir = TempDir::new("keys").unwrap();
    env::set_current_dir(&tempdir).unwrap();
    assert!(Command::new(sample_keys_bin.clone())
        .args(&[
            "--num",
            "10",
            "--fog-report-url",
            "discovery.example.mobilecoin.com"
        ])
        .status()
        .expect("sample_keys failed")
        .success());

    let tempdir2 = TempDir::new("keys").unwrap();
    env::set_current_dir(&tempdir2).unwrap();
    assert!(Command::new(sample_keys_bin)
        .args(&[
            "--num",
            "10",
            "--fog-report-url",
            "discovery.example.mobilecoin.com"
        ])
        .status()
        .expect("sample_keys failed")
        .success());

    assert!(Command::new("diff")
        .args(&[
            "-rq",
            tempdir.path().to_str().unwrap(),
            tempdir2.path().to_str().unwrap()
        ])
        .status()
        .expect("Diff reported unexpected differences, this indicates nondeterminism")
        .success());
}

// Test that if we generate 20 keys and look at only the first 10, its the same
// as if we just generate 10
#[test]
#[ignore]
fn sample_keys_determinism2() {
    let sample_keys_bin = build_dir().join("sample-keys");
    assert!(
        sample_keys_bin.exists(),
        "sample_keys binary was not found: {}",
        sample_keys_bin.display()
    );

    let tempdir = TempDir::new("keys").unwrap();
    env::set_current_dir(&tempdir).unwrap();
    assert!(Command::new(sample_keys_bin.clone())
        .args(&[
            "--num",
            "10",
            "--fog-report-url",
            "discovery.example.mobilecoin.com"
        ])
        .status()
        .expect("sample_keys failed")
        .success());

    let tempdir2 = TempDir::new("keys").unwrap();
    env::set_current_dir(&tempdir2).unwrap();
    assert!(Command::new(sample_keys_bin)
        .args(&[
            "--num",
            "20",
            "--fog-report-url",
            "discovery.example.mobilecoin.com"
        ])
        .status()
        .expect("sample_keys failed")
        .success());

    // exclude 1, any character, ., in order to exclude numbers 10 - 19
    assert!(Command::new("diff")
        .args(&[
            "-rq",
            "--exclude=*1[0123456789].*",
            tempdir.path().to_str().unwrap(),
            tempdir2.path().to_str().unwrap()
        ])
        .status()
        .expect("Diff reported unexpected differences, this indicates nondeterminism")
        .success());
}
