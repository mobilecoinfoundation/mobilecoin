// Copyright (c) 2018-2020 MobileCoin Inc.

//! Generate canned certificate data (via bash script)

use mc_util_build_script::Environment;
use std::process::Command;

fn main() {
    let env = Environment::default();

    let openssl = env.dir().join("openssl.cnf");
    cargo_emit::rerun_if_changed!("{}", openssl.display());

    let generate = env.dir().join("generate.sh");
    cargo_emit::rerun_if_changed!("{}", generate.display());

    assert!(Command::new(generate)
        .status()
        .expect("Failed to run generate.sh")
        .success())
}
