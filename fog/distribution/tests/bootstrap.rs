// Copyright (c) 2018-2022 The MobileCoin Foundation

use std::{
    env::{args, set_current_dir},
    path::PathBuf,
    process::Command,
};
use tempfile::TempDir;

// Test that fog distro can find the spendable tx outs from the bootstrap
//
// This is meant to be kept in sync with CD and help catch bootstrap / fog
// distro problems earlier and with faster iteration times.
#[test]
fn test_find_spendable_tx_outs() {
    let me = PathBuf::from(args().next().unwrap());
    let bin = me.parent().unwrap().parent().unwrap();
    println!("bin = {:?}", bin);

    let dir = TempDir::new().unwrap();
    set_current_dir(dir.path()).unwrap();
    println!("dir = {:?}", dir);

    assert!(Command::new(bin.join("sample-keys"))
        .args([
            "--num",
            "10",
            "--seed",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ])
        .status()
        .unwrap()
        .success());

    assert!(Command::new(bin.join("generate-sample-ledger"))
        .args(["--txs", "10"])
        .status()
        .unwrap()
        .success());

    assert!(Command::new(bin.join("sample-keys"))
        .args(["--num", "5", "--output-dir", "./fog_keys"])
        .status()
        .unwrap()
        .success());

    assert!(Command::new(bin.join("fog-distribution"))
        .args([
            "--sample-data-dir",
            "./",
            "--peer",
            "mc://test.com",
            "--num-tx-to-send",
            "5",
            "--num-seed-transactions-per-destination-account",
            "2",
            "--dry-run"
        ])
        .status()
        .unwrap()
        .success());
}
