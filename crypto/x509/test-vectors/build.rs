// Copyright (c) 2018-2020 MobileCoin Inc.

//! Generate canned certificate data (via bash script)

use mc_util_build_script::Environment;
use std::{fs, io::ErrorKind, process::Command};

fn main() {
    let env = Environment::default();

    let openssl_tmpl = env.dir().join("openssl.cnf.tmpl");
    cargo_emit::rerun_if_changed!("{}", openssl_tmpl.display());

    let tmpl_contents =
        fs::read_to_string(openssl_tmpl).expect("Could not read openssl.cnf template");
    let cnf_contents = tmpl_contents.replace(
        "${ENV::OUT_DIR}",
        env.out_dir()
            .as_os_str()
            .to_str()
            .expect("OUT_DIR contains invalid UTF-8"),
    );

    let mut openssl_cnf = env.out_dir().join("openssl");
    match fs::remove_dir_all(&openssl_cnf) {
        Ok(()) => (),
        Err(e) => {
            if e.kind() != ErrorKind::NotFound {
                panic!("Error removing existing openssl dir: {}", e);
            }
        }
    }
    fs::create_dir_all(&openssl_cnf).expect("Could not create openssl output dir");

    openssl_cnf.push("openssl.cnf");
    fs::write(openssl_cnf, cnf_contents).expect("Could not write openssl.cnf file");

    let generate = env.dir().join("generate.sh");
    cargo_emit::rerun_if_changed!("{}", generate.display());

    assert!(Command::new(generate)
        .status()
        .expect("Failed to run generate.sh")
        .success())
}
