// Copyright (c) 2018-2021 MobileCoin Inc.

//! Generate canned certificate data (via bash script)

use mc_util_build_script::Environment;
use std::process::Command;

fn main() {
    let env = Environment::default();
    let generate = env.dir().join("generate.sh");
    let openssl_cnf = env.dir().join("openssl.cnf");

    cargo_emit::rerun_if_changed!(openssl_cnf.display());
    cargo_emit::rerun_if_changed!(generate.display());
    cargo_emit::rerun_if_env_changed!("OUT_DIR");
    cargo_emit::rerun_if_env_changed!("OPENSSL_BIN");

    if !Command::new(generate)
        .status()
        .expect("Failed to run generate.sh")
        .success()
    {
        panic!("Generate script did not succeed");
    }
}
