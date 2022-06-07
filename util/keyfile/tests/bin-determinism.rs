// Copyright (c) 2018-2022 The MobileCoin Foundation

use mc_util_test_utils::tempdir;
use std::{env, io::Write, process::Command};
use tempfile::NamedTempFile;

// Get the build dir, which is one down from current_exe, which is in
// target/debug/deps,
fn build_dir() -> std::path::PathBuf {
    let mut result = env::current_exe().unwrap();
    result.pop();
    result.pop();
    result
}

// Test that the sample keys binary is deterministic.
#[test]
#[ignore]
fn sample_keys_determinism() {
    let sample_keys_bin = build_dir().join("sample-keys");
    assert!(
        sample_keys_bin.exists(),
        "sample_keys binary was not found: {}",
        sample_keys_bin.display()
    );

    let mut authority_pemfile =
        NamedTempFile::new().expect("Could not create file for temp root authority");
    authority_pemfile
        .write_all(mc_crypto_x509_test_vectors::ok_rsa_head().as_bytes())
        .expect("Could not write temp root authority");
    let fog_authority_root = authority_pemfile
        .path()
        .to_str()
        .expect("Authority pemfile is not valid UTF-8");

    let dir = tempdir();
    let dir_path = dir.path().to_str().expect("tempdir was not UTF-8");

    assert!(Command::new(sample_keys_bin.clone())
        .args(&[
            "--output-dir",
            dir_path,
            "--num",
            "10",
            "--fog-report-url",
            "fog://fog.unittest.mobilecoin.com",
            "--fog-report-id",
            "",
            "--fog-authority-root",
            fog_authority_root,
        ])
        .status()
        .expect("sample_keys failed")
        .success());

    let dir2 = tempdir();
    let dir2_path = dir2.path().to_str().expect("tempdir2 was not UTF-8");
    assert!(Command::new(sample_keys_bin)
        .args(&[
            "--output-dir",
            dir2_path,
            "--num",
            "10",
            "--fog-report-url",
            "fog://fog.unittest.mobilecoin.com",
            "--fog-report-id",
            "",
            "--fog-authority-root",
            fog_authority_root,
        ])
        .status()
        .expect("sample_keys failed")
        .success());

    assert!(Command::new("diff")
        .args(&["-rq", dir_path, dir2_path])
        .status()
        .expect("Diff reported unexpected differences, this indicates nondeterminism")
        .success());
}

/// Generate 20 keys and look at only the first 10, should be the same as just
/// generating 10.
#[test]
#[ignore]
fn sample_keys_determinism2() {
    let sample_keys_bin = build_dir().join("sample-keys");
    assert!(
        sample_keys_bin.exists(),
        "sample_keys binary was not found: {}",
        sample_keys_bin.display()
    );
    let mut authority_pemfile =
        NamedTempFile::new().expect("Could not create file for temp root authority");
    authority_pemfile
        .write_all(mc_crypto_x509_test_vectors::ok_rsa_head().as_bytes())
        .expect("Could not write temp root authority");
    let fog_authority_root = authority_pemfile
        .path()
        .to_str()
        .expect("Authority pemfile is not valid UTF-8");

    let dir = tempdir();
    let dir_path = dir.path().to_str().expect("tempdir was not UTF-8");

    assert!(Command::new(sample_keys_bin.clone())
        .args(&[
            "--output-dir",
            dir_path,
            "--num",
            "10",
            "--fog-report-url",
            "fog://fog.unittest.mobilecoin.com",
            "--fog-report-id",
            "",
            "--fog-authority-root",
            fog_authority_root,
        ])
        .status()
        .expect("sample_keys failed")
        .success());

    let dir2 = tempdir();
    let dir2_path = dir2.path().to_str().expect("tempdir2 was not UTF-8");
    assert!(Command::new(sample_keys_bin)
        .args(&[
            "--output-dir",
            dir2_path,
            "--num",
            "20",
            "--fog-report-url",
            "fog://fog.unittest.mobilecoin.com",
            "--fog-report-id",
            "",
            "--fog-authority-root",
            fog_authority_root,
        ])
        .status()
        .expect("sample_keys failed")
        .success());
    // exclude 1, any character, ., in order to exclude numbers 10 - 19
    assert!(Command::new("diff")
        .args(&["-rq", "--exclude=*1[0123456789].*", dir_path, dir2_path])
        .status()
        .expect("Diff reported unexpected differences, this indicates nondeterminism")
        .success());
}
