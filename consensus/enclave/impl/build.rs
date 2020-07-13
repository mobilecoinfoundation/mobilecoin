// Copyright (c) 2018-2020 MobileCoin Inc.

//! Bake the compile-time target features into the enclave.

use mc_util_build_script::Environment;
use std::fs;

fn main() {
    let env = Environment::default();

    let mut target_features = env
        .target_features()
        .iter()
        .map(ToOwned::to_owned)
        .collect::<Vec<String>>();
    target_features.sort();

    let mut contents = String::from("const TARGET_FEATURES: &[&str] = &[\n");
    for feature in target_features {
        contents.push_str("    \"");
        contents.push_str(&feature);
        contents.push_str("\",\n");
    }
    contents.push_str("];\n\n");

    fs::write(&env.out_dir().join("target_features.rs"), &contents)
        .expect("Could not write target feature array");
}
