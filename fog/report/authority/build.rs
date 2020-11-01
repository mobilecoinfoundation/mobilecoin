// Copyright (c) 2018-2020 MobileCoin Inc.

//! Generate certs for the test harness.

use mc_util_build_script::Environment;
use std::process::Command;

fn main() {
    if cfg!(test) {
        let env = Environment::default();

        let _output = Command::new("tests/generate-certs.sh")
            .arg(env.out_dir())
            .output()
            .expect("Could not generate certs");
    }
}
