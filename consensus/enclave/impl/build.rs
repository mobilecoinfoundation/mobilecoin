// Copyright (c) 2018-2020 MobileCoin Inc.

//! Bake the compile-time target features into the enclave.

use cargo_emit::rerun_if_env_changed;
use mc_util_build_script::Environment;
use std::{convert::TryFrom, env::var, fs, path::PathBuf};

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

    rerun_if_env_changed!("FEE_SPEND_PUBLIC_KEY");
    rerun_if_env_changed!("FEE_VIEW_PUBLIC_KEY");

    let mut fee_spend_public_key = [0u8; 32];
    let mut fee_view_public_key = [0u8; 32];

    let default_fee_spend_pub = "26b507c63124a2f5e940b4fb89e4b2bb0a2078ed0c8e551ad59268b9646ec241";
    let default_fee_view_pub = "5222a1e9ae32d21c23114a5ce6bb39e0cb56aea350d4619d43b1207061b10346";

    // Check for env var and override
    fee_spend_public_key[..32].copy_from_slice(
        &hex::decode(&var("FEE_SPEND_PUBLIC_KEY").unwrap_or(default_fee_spend_pub.to_string()))
            .unwrap(),
    );
    fee_view_public_key[..32].copy_from_slice(
        &hex::decode(&var("FEE_VIEW_PUBLIC_KEY").unwrap_or(default_fee_view_pub.to_string()))
            .unwrap(),
    );

    let mut constants = format!(
        "pub const FEE_SPEND_PUBLIC_KEY: [u8; 32] = {:?};",
        fee_spend_public_key
    );
    constants.push_str(&format!(
        "pub const FEE_VIEW_PUBLIC_KEY: [u8; 32] = {:?};",
        fee_view_public_key
    ));
    /*
    constants.push_str(&format!(
        "pub const FEE_VIEW_PRIVATE_KEY: [u8; 32] = {:?};",
        fee_view_private_key
    ));

     */

    let mut search_path =
        PathBuf::try_from(var("CARGO_MANIFEST_DIR").expect("Could not read CARGO_MANIFEST_DIR"))
            .expect("Could not construct PathBuf from CARGO_MANIEFST_DIR")
            .canonicalize()
            .expect("Could not canonicalize CARGO_MANIFEST_DIR");
    search_path.push("src");
    fs::write(&search_path.join("constants.rs"), &constants)
        .expect("Could not write target feature array");
}
